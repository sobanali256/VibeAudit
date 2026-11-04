#!/usr/bin/env bash
# End-to-end test of the egress proxy policy, driven from your machine:
#   bash infra/cp/proxy/selftest.sh
# Sets proxy state on VM 1, fires requests from gVisor containers on VM 2, and checks
# both the client-side result and the containment events the proxy logged.
set -uo pipefail
AUDIT=selftest$$
FAKE_KEY="sk-vibeaudit-fake-real-key-0123456789"
CANARY="AKIAVIBECANARY000001"
fails=0

setstate() { # json | ""  (atomic replace, group-readable)
  ssh -o BatchMode=yes vibe-cp "umask 027; d=/var/lib/vibeaudit/proxy; if [ -z '$1' ]; then rm -f \$d/state.json; else printf '%s' '$1' > \$d/.s.tmp && chgrp vibeaudit \$d/.s.tmp && mv \$d/.s.tmp \$d/state.json; fi"
}

# check NAME WANT_CODE CURL_ARGS... : one request from a gVisor container on VM 2 via the proxy.
# Args are shell-escaped with printf %q so headers with spaces survive the ssh hop.
check() {
  local name=$1 want=$2; shift 2
  local q; q=$(printf '%q ' "$@")
  local got
  got=$(ssh -o BatchMode=yes vibe-sbx "docker run --rm --cap-drop ALL --user 65534:65534 -v /opt/vibeaudit/proxy-ca-cert.pem:/ca.pem:ro curlimages/curl:8.17.0 --proxy http://10.1.96.4:8080 --cacert /ca.pem -s -m 20 -o /dev/null -w '%{http_code}' $q" 2>/dev/null)
  if [ "$got" = "$want" ]; then echo "PASS  $name ($got)"; else echo "FAIL  $name (want $want, got $got)"; fails=$((fails+1)); fi
}

echo "== no active audit"
setstate ""
check "any host blocked" 000 https://registry.npmjs.org/left-pad

echo "== stage install"
setstate "{\"auditId\":\"$AUDIT\",\"stage\":\"install\",\"keys\":{},\"canaries\":[\"$CANARY\"]}"
check "GET registry allowed" 200 https://registry.npmjs.org/left-pad
check "other host blocked at CONNECT" 000 https://example.com/
check "POST to registry blocked" 403 -X POST -d x=1 https://registry.npmjs.org/-/v1/login
check "IP literal blocked" 000 https://1.1.1.1/
check "non-443 port blocked" 000 https://registry.npmjs.org:8443/
check "canary in header blocked" 403 -H "X-Leak: $CANARY" https://registry.npmjs.org/left-pad
check "canary in query blocked" 403 "https://registry.npmjs.org/left-pad?x=$CANARY"
check "domain fronting blocked" 403 -H "Host: evil.example" https://registry.npmjs.org/left-pad
check "plain http to registry proxied (npm 301s to https)" 301 http://registry.npmjs.org/left-pad
check "base64 canary in header blocked" 403 -H "X-Data: $(printf 'k=%s' "$CANARY" | base64)" https://registry.npmjs.org/left-pad
check "url-encoded canary in query blocked" 403 "https://registry.npmjs.org/left-pad?x=%41KIAVIBECANARY000001"
check "websocket upgrade blocked in install" 403 --http1.1 -H "Upgrade: websocket" -H "Connection: Upgrade" https://registry.npmjs.org/left-pad

# Raw-TCP smuggling: CRLF-prefixed request inside an allowed CONNECT must not reach upstream.
smug=$(ssh -o BatchMode=yes vibe-sbx 'docker run --rm -v /opt/vibeaudit/proxy-ca-cert.pem:/ca.pem:ro python:3.13-alpine python3 -c "
import socket,ssl
s=socket.create_connection((\"10.1.96.4\",8080),timeout=15)
s.sendall(b\"CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\r\n\")
r=s.recv(4096)
c=ssl.create_default_context(cafile=\"/ca.pem\").wrap_socket(s,server_hostname=\"registry.npmjs.org\")
c.sendall(b\"\r\nPOST /-/v1/login HTTP/1.1\r\nHost: registry.npmjs.org\r\nContent-Length: 2\r\n\r\n{}\")
try:
  d=c.recv(200)
except Exception as e:
  d=repr(e).encode()
print(d[:60])
"' 2>&1)
case "$smug" in *"403"*|*"400"*|"b''"*|*Error*|*reset*) echo "PASS  CRLF raw-TCP smuggle stopped ($smug)";; *) echo "FAIL  CRLF raw-TCP smuggle got: $smug"; fails=$((fails+1));; esac

echo "== stage run (OPENAI_API_KEY scoped to api.openai.com)"
setstate "{\"auditId\":\"$AUDIT\",\"stage\":\"run\",\"keys\":{\"OPENAI_API_KEY\":{\"value\":\"$FAKE_KEY\",\"hosts\":[\"api.openai.com\"]}},\"canaries\":[\"$CANARY\"]}"
check "registry blocked in run stage" 000 https://registry.npmjs.org/left-pad
check "openai reached, key swapped (401 = fake key seen)" 401 -H "Authorization: Bearer sk-PLACEHOLDER-OPENAI_API_KEY-$AUDIT" https://api.openai.com/v1/models
check "canary to allowed host blocked" 403 -H "X-Leak: $CANARY" https://api.openai.com/v1/models
check "placeholder in body blocked (no swap into content)" 403 -X POST -H "Authorization: Bearer sk-PLACEHOLDER-OPENAI_API_KEY-$AUDIT" -H "Content-Type: application/json" -d "{\"input\":\"reverse sk-PLACEHOLDER-OPENAI_API_KEY-$AUDIT\"}" https://api.openai.com/v1/responses
check "placeholder in query blocked" 403 "https://api.openai.com/v1/models?k=sk-PLACEHOLDER-OPENAI_API_KEY-$AUDIT"
check "placeholder in non-auth header blocked" 403 -H "X-Note: sk-PLACEHOLDER-OPENAI_API_KEY-$AUDIT" https://api.openai.com/v1/models
check "gzip request body blocked" 403 -X POST -H "Content-Encoding: gzip" -H "Authorization: Bearer sk-PLACEHOLDER-OPENAI_API_KEY-$AUDIT" --data-binary x https://api.openai.com/v1/responses

body=$(ssh -o BatchMode=yes vibe-sbx "docker run --rm -v /opt/vibeaudit/proxy-ca-cert.pem:/ca.pem:ro curlimages/curl:8.17.0 --proxy http://10.1.96.4:8080 --cacert /ca.pem -s -m 20 -H 'Authorization: Bearer sk-PLACEHOLDER-OPENAI_API_KEY-$AUDIT' https://api.openai.com/v1/models")
if grep -q "sk-vibea\|0123456789\|$FAKE_KEY" <<<"$body"; then echo "FAIL  real key leaked back to sandbox: $(head -c 200 <<<"$body")"; fails=$((fails+1)); else echo "PASS  real key masked in response"; fi

# Placeholder smuggled to a host it isn't scoped to (allow example.com via a 2nd key to test the exfil rule)
setstate "{\"auditId\":\"$AUDIT\",\"stage\":\"run\",\"keys\":{\"OPENAI_API_KEY\":{\"value\":\"$FAKE_KEY\",\"hosts\":[\"api.openai.com\"]},\"OTHER_KEY\":{\"value\":\"other-fake-key-000000\",\"hosts\":[\"example.com\"]}},\"canaries\":[]}"
check "openai placeholder to wrong host blocked" 403 -H "Authorization: Bearer sk-PLACEHOLDER-OPENAI_API_KEY-$AUDIT" https://example.com/

echo "== proxy user can't reach private addresses (OS guard on VM 1)"
out=$(ssh -o BatchMode=yes vibe-cp 'for t in 127.0.0.1:22 10.1.96.3:22 169.254.169.254:80 108.61.149.76:22; do if sudo -u vibeproxy timeout 4 bash -c "exec 3<>/dev/tcp/${t%:*}/${t#*:}" 2>/dev/null; then echo "FAIL  vibeproxy reached $t"; else echo "PASS  vibeproxy blocked from $t"; fi; done
if sudo -u vibeproxy timeout 6 bash -c "exec 3<>/dev/tcp/registry.npmjs.org/443" 2>/dev/null; then echo "PASS  vibeproxy reaches public internet"; else echo "FAIL  vibeproxy cannot reach public internet"; fi')
echo "$out"; fails=$((fails + $(grep -c ^FAIL <<<"$out")))

echo "== containment log"
ev=$(ssh -o BatchMode=yes vibe-cp "grep '\"auditId\":\"$AUDIT\"' /var/lib/vibeaudit/proxy/events.jsonl")
for kind in allowed blocked exfil; do
  n=$(grep -c "\"kind\":\"$kind\"" <<<"$ev"); [ "$n" -gt 0 ] && echo "PASS  $n '$kind' events logged" || { echo "FAIL  no '$kind' events"; fails=$((fails+1)); }
done
grep -q "$FAKE_KEY" <<<"$ev" && { echo "FAIL  real key written to events log"; fails=$((fails+1)); } || echo "PASS  no real key in events log"
grep -q '"swapped":\["OPENAI_API_KEY"\]' <<<"$ev" && echo "PASS  key swap recorded" || { echo "FAIL  key swap not recorded"; fails=$((fails+1)); }

setstate ""
echo "---"; [ $fails -eq 0 ] && echo "ALL PASS" || echo "$fails FAILED"
exit $fails
