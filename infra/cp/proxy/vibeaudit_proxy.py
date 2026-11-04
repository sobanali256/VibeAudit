"""
VibeAudit egress proxy addon for mitmproxy (runs on VM 1, the only egress for sandboxes).

Policy:
  * Only the sandbox host (VIBEAUDIT_SANDBOX_IP) may use the proxy.
  * No active audit (missing/invalid state file) -> everything is blocked.
  * HTTP(S) only: raw TCP passthrough is disabled (`rawtcp=false`) and any TCP/UDP flow that
    still appears is killed, so nothing bypasses the HTTP hooks below.
  * Host must be on the allowlist for the current stage (STAGE_HOSTS) or, in run-time
    stages, be a host one of the audit's test keys is scoped to. Exactly one Host header,
    matching the CONNECT/target authority (no domain fronting).
  * Ports 80/443 only, no IP-literal hosts, and upstreams must resolve to public IPs
    (VM 1 holds every secret). An iptables owner guard on VM 1 is the hard stop for this.
  * Install/build: GET/HEAD only, no request bodies, no websockets.
  * Request bodies: must have a known length <= MAX_SCAN_BYTES (no unbounded chunked uploads).
  * Test keys: `sk-PLACEHOLDER-<VAR>-<auditId>` is swapped for the real key ONLY when it is
    the entire credential in one of that key's auth headers (e.g. `Authorization: Bearer
    <placeholder>`), on the way to a host the key is scoped to. The placeholder anywhere
    else (URL, body, other headers, websocket frames, wrong host) is blocked as exfiltration:
    otherwise an allowed API could store or echo the real key (a public gist, an LLM asked to
    reverse it...).
  * Responses to a swapped request are fully buffered and the real key (plain, URL-encoded,
    JSON-escaped, partial `sk-ab***yz` echoes) is masked back to the placeholder. If such a
    response can't be fully inspected (too large, undecodable) it is replaced with a 502.
  * Canaries (fake secrets planted in the sandbox env) in any outbound request, in plain,
    URL-encoded, base64 or hex form, block the request as exfiltration.

State file (written atomically by the worker; re-read whenever the file is replaced):
  {"auditId": "a1b2", "stage": "install",
   "keys": {"OPENAI_API_KEY": {"value": "sk-...", "hosts": ["api.openai.com"],
                               "headers": ["authorization"]}},
   "canaries": ["AKIAVIBEAUDITCANARY01", "..."]}
  `headers` is optional (default: authorization, x-api-key, api-key).

Every decision is appended to EVENTS_PATH as one JSON object per line (the containment log).
Secrets are never written there; repeated identical events are rate limited.
"""

import base64
import binascii
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass, field

from mitmproxy import ctx, http, tcp, udp
from mitmproxy.proxy import server_hooks

STATE_PATH = os.environ.get("VIBEAUDIT_PROXY_STATE", "/var/lib/vibeaudit/proxy/state.json")
EVENTS_PATH = os.environ.get("VIBEAUDIT_PROXY_EVENTS", "/var/lib/vibeaudit/proxy/events.jsonl")
SANDBOX_CLIENT_IP = os.environ.get("VIBEAUDIT_SANDBOX_IP", "10.1.96.3")

# Exact hostnames per stage. Subdomains are NOT implied.
_INSTALL = {
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "codeload.github.com",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "nodejs.org",
    "binaries.prisma.sh",
}
_BUILD = {"fonts.googleapis.com", "fonts.gstatic.com", "binaries.prisma.sh"}
STAGE_HOSTS: dict[str, set[str]] = {
    "install": _INSTALL,
    "build": _BUILD,
    # run/dynamic/verify: only hosts the audit's test keys are scoped to (added per state).
    "run": set(),
    "dynamic": set(),
    "verify": set(),
}
KEY_STAGES = {"run", "dynamic", "verify"}
READ_ONLY_STAGES = {"install", "build"}
ALLOWED_PORTS = {80, 443}
DEFAULT_KEY_HEADERS = ("authorization", "x-api-key", "api-key")
MAX_SCAN_BYTES = 1 << 20          # request bodies above this are refused
MAX_SWAPPED_RESPONSE = 8 << 20    # responses to key-bearing requests above this become 502
EVENTS_MAX_BYTES = 256 << 20      # stop logging "allowed" events past this size
EVENT_BURST = 20                  # identical events logged before sampling kicks in
EVENT_SAMPLE = 100                # ...then every Nth occurrence, with a count

HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
VAR_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
HEADER_RE = re.compile(r"^[a-z0-9-]{1,64}$")
# Secrets and canaries: printable ASCII, no spaces, 8-512 chars (same rule as shared/ids.ts).
SECRET_VALUE_RE = re.compile(r"^[\x21-\x7e]{8,512}$")


@dataclass
class Key:
    var: str
    value: str
    hosts: frozenset[str]
    headers: frozenset[str]
    placeholder: str
    echo_re: re.Pattern | None = None

    def __post_init__(self) -> None:
        if len(self.value) >= 12:
            # Partial echoes like OpenAI's "sk-vibea****6789": 3+ leading chars, mask run, tail.
            self.echo_re = re.compile(
                re.escape(self.value[:3]) + r"[A-Za-z0-9_-]{0,9}[*.…x]{3,}[A-Za-z0-9_-]{0,6}"
            )

    def forms(self) -> list[str]:
        """Encodings of the real value that might appear in a response body."""
        out = {self.value, urllib.parse.quote(self.value, safe=""), json.dumps(self.value)[1:-1]}
        return [f for f in out if f]


@dataclass
class State:
    audit_id: str
    stage: str
    keys: list[Key] = field(default_factory=list)
    canaries: list[str] = field(default_factory=list)
    canary_forms: list[tuple[str, str]] = field(default_factory=list)  # (form, canary)

    def allowed_hosts(self) -> set[str]:
        hosts = set(STAGE_HOSTS.get(self.stage, set()))
        if self.stage in KEY_STAGES:
            for k in self.keys:
                hosts |= k.hosts
        return hosts


def _norm_host(h: str) -> str:
    return h.strip().rstrip(".").lower()


def _b64_variants(s: str) -> set[str]:
    """Base64 substrings that appear whenever `s` is base64-encoded at any alignment."""
    out = set()
    raw = s.encode()
    for pad in range(3):
        enc = base64.b64encode(b"\0" * pad + raw).decode()
        # Drop chars influenced by the padding prefix / unknown trailing bytes.
        start = (pad * 4 + 2) // 3 + (1 if pad else 0)
        core = enc[start : len(enc) - 4]
        if len(core) >= 8:
            out.add(core)
            out.add(core.replace("+", "-").replace("/", "_"))  # base64url
    return out


def _canary_forms(c: str) -> list[tuple[str, str]]:
    forms = {c, c.lower(), urllib.parse.quote(c, safe=""), binascii.hexlify(c.encode()).decode()}
    forms |= _b64_variants(c)
    return [(f, c) for f in forms if len(f) >= 8]


def _parse_state(raw: dict) -> State:
    audit_id = raw["auditId"]
    stage = raw["stage"]
    if not isinstance(audit_id, str) or not AUDIT_ID_RE.fullmatch(audit_id):
        raise ValueError("bad auditId")
    if not isinstance(stage, str):
        raise ValueError("bad stage")
    keys = []
    for var, spec in (raw.get("keys") or {}).items():
        if not VAR_RE.fullmatch(var):
            raise ValueError(f"bad key var {var!r}")
        value = spec["value"]
        hosts = frozenset(_norm_host(h) for h in spec["hosts"])
        headers = frozenset(h.lower() for h in spec.get("headers") or DEFAULT_KEY_HEADERS)
        if not isinstance(value, str) or not SECRET_VALUE_RE.fullmatch(value):
            raise ValueError(f"bad key value for {var}")
        if not hosts or not all(HOST_RE.fullmatch(h) for h in hosts):
            raise ValueError(f"bad hosts for {var}")
        if not headers or not all(HEADER_RE.fullmatch(h) for h in headers):
            raise ValueError(f"bad headers for {var}")
        keys.append(Key(var, value, hosts, headers, f"sk-PLACEHOLDER-{var}-{audit_id}"))
    if keys and stage not in KEY_STAGES:
        raise ValueError(f"test keys are not allowed in stage {stage}")
    canaries = raw.get("canaries") or []
    if not isinstance(canaries, list) or not all(isinstance(c, str) and SECRET_VALUE_RE.fullmatch(c) for c in canaries):
        raise ValueError("bad canaries")  # reject, don't silently drop: a dropped canary = unmonitored
    forms = [f for c in canaries for f in _canary_forms(c)]
    return State(audit_id, stage, keys, canaries, forms)


class VibeAuditProxy:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: State | None = None
        self._sig: tuple | None = None
        self._events_lock = threading.Lock()
        self._event_counts: dict[tuple, int] = {}

    # ---------------------------------------------------------------- state
    def _current(self) -> State | None:
        with self._lock:
            try:
                fd = os.open(STATE_PATH, os.O_RDONLY)
            except FileNotFoundError:
                self._state, self._sig = None, None
                return None
            try:
                st = os.fstat(fd)
                # Every atomic rename yields a new inode, so this changes on every write even
                # when two writes land in the same mtime tick.
                sig = (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)
                if sig == self._sig:
                    return self._state
                try:
                    with os.fdopen(os.dup(fd), encoding="utf-8") as f:
                        self._state = _parse_state(json.load(f))
                except Exception as e:  # fail closed
                    ctx.log.warn(f"vibeaudit: invalid state file ({type(e).__name__}); blocking all")
                    self._state = None
                self._sig = sig
                return self._state
            finally:
                os.close(fd)

    # --------------------------------------------------------------- events
    def _event(self, state: State | None, kind: str, flow: http.HTTPFlow | None = None, **extra) -> None:
        rec = {
            "ts": time.time(),
            "auditId": state.audit_id if state else None,
            "stage": state.stage if state else None,
            "kind": kind,
        }
        if flow is not None:
            req = flow.request
            path = flow.metadata.get("vibeaudit_orig_path", req.path)
            rec.update(method=req.method, host=req.pretty_host, port=req.port, path=path[:300])
        rec.update(extra)
        line = json.dumps(rec, separators=(",", ":"))
        if state:
            line = self._redact(state, line)

        dedupe = (rec["auditId"], kind, rec.get("host"), rec.get("reason"), rec.get("method"))
        with self._events_lock:
            n = self._event_counts.get(dedupe, 0) + 1
            self._event_counts[dedupe] = n
            if len(self._event_counts) > 50_000:
                self._event_counts.clear()
            if n > EVENT_BURST and n % EVENT_SAMPLE:
                return
            if n > EVENT_BURST:
                rec["repeat"] = n
                line = json.dumps(rec, separators=(",", ":"))
                if state:
                    line = self._redact(state, line)
            try:
                if kind == "allowed" and os.path.getsize(EVENTS_PATH) > EVENTS_MAX_BYTES:
                    return
            except FileNotFoundError:
                pass
            with open(EVENTS_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    @staticmethod
    def _redact(state: State, text: str) -> str:
        for k in state.keys:
            for form in k.forms():
                text = text.replace(form, f"<{k.var}>")
        return text

    def _block(self, flow: http.HTTPFlow, state: State | None, reason: str, kind: str = "blocked", **extra) -> None:
        self._event(state, kind, flow, reason=reason, **extra)
        flow.response = http.Response.make(
            403,
            f"Blocked by VibeAudit egress policy: {reason}\n".encode(),
            {"Content-Type": "text/plain", "X-VibeAudit-Blocked": kind},
        )

    # ---------------------------------------------------------------- policy
    def _check_target(self, flow: http.HTTPFlow, state: State | None) -> bool:
        """True if the request target is allowed; otherwise blocks the flow."""
        if state is None:
            self._block(flow, None, "no active audit")
            return False
        host = _norm_host(flow.request.host)
        try:
            ipaddress.ip_address(host.strip("[]"))
            self._block(flow, state, "IP-literal hosts are not allowed")
            return False
        except ValueError:
            pass
        if flow.request.port not in ALLOWED_PORTS:
            self._block(flow, state, f"port {flow.request.port} not allowed")
            return False
        if host not in state.allowed_hosts():
            self._block(flow, state, f"host not allowed in stage {state.stage}")
            return False
        return True

    def _find_canary(self, state: State, *texts: str) -> str | None:
        for t in texts:
            if not t:
                continue
            tl = t.lower()
            for form, canary in state.canary_forms:
                if form in t or form.lower() in tl:
                    return canary
        return None

    # ----------------------------------------------------------------- hooks
    def client_connected(self, client) -> None:
        ip = client.peername[0] if client.peername else None
        if ip is not None and ip.removeprefix("::ffff:") != SANDBOX_CLIENT_IP:
            client.error = "client not allowed"
            self._event(self._current(), "client_rejected", peer=ip)

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        # rawtcp is disabled; anything that still ends up as raw TCP is not inspectable.
        self._event(self._current(), "blocked", reason="raw TCP not allowed")
        flow.kill()

    def udp_start(self, flow: udp.UDPFlow) -> None:
        self._event(self._current(), "blocked", reason="UDP not allowed")
        flow.kill()

    def http_connect(self, flow: http.HTTPFlow) -> None:
        # Decide before TLS: denying CONNECT means no handshake to a forbidden host at all.
        self._check_target(flow, self._current())

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        if flow.request.method == "CONNECT":
            return
        state = self._current()
        if not self._check_target(flow, state):
            return
        assert state is not None
        req = flow.request
        flow.metadata["vibeaudit_orig_path"] = req.path

        # Domain fronting: exactly one Host header (HTTP/1) and it must match the target.
        hosts = req.headers.get_all("host")
        if len(hosts) > 1 or (hosts and _norm_host(hosts[0].rsplit(":", 1)[0] if not hosts[0].startswith("[") else hosts[0]) != _norm_host(req.host)):
            self._block(flow, state, "Host header does not match target")
            return
        if state.stage in READ_ONLY_STAGES:
            if req.method not in ("GET", "HEAD"):
                self._block(flow, state, f"{req.method} not allowed in stage {state.stage}")
                return
            if req.headers.get("upgrade"):
                self._block(flow, state, f"protocol upgrade not allowed in stage {state.stage}")
                return
        if req.headers.get("content-encoding"):
            self._block(flow, state, "encoded request bodies are not allowed")
            return
        cl = req.headers.get("content-length")
        te = req.headers.get("transfer-encoding")
        if cl is not None:
            if not cl.strip().isdigit() or int(cl) > MAX_SCAN_BYTES:
                self._block(flow, state, "request body too large to inspect")
                return
        elif te or (req.http_version == "HTTP/2.0" and req.method not in ("GET", "HEAD", "OPTIONS", "DELETE")):
            # Unbounded body: would be buffered without limit before we could inspect it.
            self._block(flow, state, "request body without content-length")
            return

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None or flow.request.method == "CONNECT":
            return
        state = self._current()
        if state is None:
            self._block(flow, None, "no active audit")
            return
        req = flow.request
        host = _norm_host(req.host)

        body = req.get_content(strict=False) or b""
        if len(body) > MAX_SCAN_BYTES:
            self._block(flow, state, "request body too large to inspect")
            return
        body_text = body.decode("utf-8", "replace")
        url_text = req.url
        try:
            url_dec = urllib.parse.unquote_plus(url_text)
            body_dec = urllib.parse.unquote_plus(body_text)
        except Exception:
            url_dec, body_dec = url_text, body_text
        header_text = "\n".join(f"{k}: {v}" for k, v in req.headers.items(multi=True))

        canary = self._find_canary(state, url_text, url_dec, header_text, body_text, body_dec)
        if canary:
            self._block(flow, state, "canary secret in outbound request", kind="exfil", canary=canary[:6] + "…")
            return

        # Placeholders: only valid as the whole credential in one of the key's auth headers.
        swapped: list[str] = []
        for k in state.keys:
            ph = k.placeholder
            ph_l = ph.lower()
            elsewhere = any(ph_l in t.lower() for t in (url_text, url_dec, body_text, body_dec))
            for name, value in req.headers.items(multi=True):
                if ph_l not in value.lower():
                    continue
                if name.lower() not in k.headers:
                    elsewhere = True
                elif value.strip() not in (ph, f"Bearer {ph}", f"bearer {ph}", f"Token {ph}"):
                    elsewhere = True
            if elsewhere:
                self._block(flow, state, f"{k.var} placeholder outside an auth header", kind="exfil", var=k.var)
                return
            if any(ph in v for n, v in req.headers.items(multi=True) if n.lower() in k.headers):
                if host not in k.hosts:
                    self._block(flow, state, f"{k.var} placeholder sent to a host it isn't scoped to", kind="exfil", var=k.var)
                    return
                for name in {n for n in req.headers.keys() if n.lower() in k.headers}:
                    req.headers.set_all(name, [v.replace(ph, k.value) for v in req.headers.get_all(name)])
                swapped.append(k.var)

        if swapped:
            flow.metadata["vibeaudit_swapped"] = swapped
            # Keep the exact keys used, so masking still works if state changes mid-flight.
            flow.metadata["vibeaudit_keys"] = [k for k in state.keys if k.var in swapped]
        self._event(state, "allowed", flow, swapped=swapped or None)

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        if flow.metadata.get("vibeaudit_keys"):
            # Must see the whole response to mask it.
            flow.response.stream = False
            cl = flow.response.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > MAX_SWAPPED_RESPONSE:
                self._replace_unmaskable(flow, "response too large to mask")
        elif not flow.metadata.get("vibeaudit_keys"):
            # No key went out on this request, so none can come back on it: stream big bodies.
            cl = flow.response.headers.get("content-length")
            if not cl or not cl.isdigit() or int(cl) > MAX_SCAN_BYTES:
                flow.response.stream = True

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.response.stream:
            return
        keys: list[Key] = list(flow.metadata.get("vibeaudit_keys") or [])
        state = self._current()
        if state:
            keys += [k for k in state.keys if k not in keys]
        if not keys:
            return
        swapped = bool(flow.metadata.get("vibeaudit_keys"))
        resp = flow.response

        for name in list(resp.headers.keys()):
            vals = resp.headers.get_all(name)
            masked = [self._mask(keys, v) for v in vals]
            if masked != vals:
                resp.headers.set_all(name, masked)

        try:
            content = resp.get_content(strict=True)
        except ValueError:
            content = None
        if content is None:
            if swapped and resp.raw_content:
                self._replace_unmaskable(flow, "response encoding can't be inspected")
            return
        if swapped and len(content) > MAX_SWAPPED_RESPONSE:
            self._replace_unmaskable(flow, "response too large to mask")
            return
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            # Binary: mask byte-wise; refuse if a key-bearing response still contains a form.
            raw = content
            for k in keys:
                for form in k.forms():
                    raw = raw.replace(form.encode(), k.placeholder.encode())
            if raw != content:
                resp.set_content(raw)
            return
        masked = self._mask(keys, text)
        if masked != text:
            resp.set_content(masked.encode("utf-8"))

    def _replace_unmaskable(self, flow: http.HTTPFlow, reason: str) -> None:
        self._event(self._current(), "blocked", flow, reason=reason)
        flow.response = http.Response.make(
            502, f"VibeAudit egress proxy: {reason}\n".encode(),
            {"Content-Type": "text/plain", "X-VibeAudit-Blocked": "unmaskable"},
        )

    @staticmethod
    def _mask(keys: list[Key], text: str) -> str:
        for k in keys:
            for form in k.forms():
                text = text.replace(form, k.placeholder)
            if k.echo_re is not None:
                text = k.echo_re.sub(k.placeholder, text)
        return text

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        assert flow.websocket is not None
        msg = flow.websocket.messages[-1]
        state = self._current()
        if state is None:
            flow.kill()
            return
        text = msg.text if msg.is_text else msg.content.decode("utf-8", "replace")
        if msg.from_client:
            if self._find_canary(state, text) or any(k.placeholder.lower() in text.lower() for k in state.keys):
                self._event(state, "exfil", flow, reason="secret in websocket frame")
                msg.drop()
                flow.kill()
        else:
            keys = list(flow.metadata.get("vibeaudit_keys") or []) + state.keys
            if msg.is_text:
                masked = self._mask(keys, msg.text)
                if masked != msg.text:
                    msg.text = masked

    def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        # Defense in depth (iptables owner rules on VM 1 are the hard stop): refuse any
        # upstream that resolves to a non-public address, e.g. a DNS-rebinding allowlisted name.
        host, port = data.server.address
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except OSError as e:
            data.server.error = f"resolve failed: {e}"
            return
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if not ip.is_global:
                data.server.error = "upstream resolves to a non-public address"
                self._event(self._current(), "blocked", None, host=host, port=port, reason=data.server.error)
                return


addons = [VibeAuditProxy()]
