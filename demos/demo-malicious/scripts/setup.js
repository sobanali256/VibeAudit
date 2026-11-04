// TEST FIXTURE — HOSTILE BY DESIGN, but deliberately neutered.
//
// This stands in for a supply-chain-compromised package whose postinstall misbehaves. Its
// only job is to let a live VibeAudit demo show the sandbox blocking it; the real proof of
// containment is infra/sbx/selftest.sh and infra/cp/proxy/selftest.sh. So this file does the
// LEAST that still demonstrates the point: it does not collect, encode or transmit secret
// values, does not fork-bomb, and only ever connects to a reserved, non-routable address.
//
// NEVER run `npm install` on this package outside the VibeAudit sandbox.
const net = require("net");

const log = (step, result) => console.log(`[demo-malicious] ${step}: ${result}`);

// A real attacker would read process.env here. We only COUNT how many secret-looking vars
// are visible, to show the audit that the sandbox hands over canary stubs, never real values.
const secretish = Object.keys(process.env).filter((k) => /KEY|TOKEN|SECRET|PASSWORD|DATABASE_URL/i.test(k));
log("env-scan", `${secretish.length} secret-looking vars visible (expect canary stubs, not real keys)`);

// Attempt a single outbound connection to TEST-NET-1 (192.0.2.0/24, reserved, never routable).
// The sandbox egress lock should refuse this; the attempt is logged, not the data.
const probe = net.connect({ host: "192.0.2.1", port: 443, timeout: 4000 });
probe.on("connect", () => {
  log("egress-probe", "CONNECTED — containment FAILED (this should never happen in the sandbox)");
  probe.destroy();
});
probe.on("timeout", () => {
  log("egress-probe", "blocked (timeout) — contained as expected");
  probe.destroy();
});
probe.on("error", (e) => log("egress-probe", `blocked (${e.code || e.message}) — contained as expected`));

// postinstall must exit so the (benign) app can still be built and booted for the audit.
probe.on("close", () => log("done", "postinstall complete"));
