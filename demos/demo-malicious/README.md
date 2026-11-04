# demo-malicious

An innocent-looking "Weather Now" app whose **postinstall is hostile by design** — a stand-in
for a supply-chain-compromised dependency. It is used to demonstrate, in a live audit, that
VibeAudit's sandbox contains install-time attacks.

The postinstall (`scripts/setup.js`) is deliberately neutered: it counts secret-looking env
vars (to show the sandbox provides canary stubs, not real keys) and makes one outbound
connection to a reserved, non-routable address, which the egress lock blocks. It does not
collect, encode or transmit any secret, and does not fork-bomb. The full containment proof
lives in `infra/sbx/selftest.sh` and `infra/cp/proxy/selftest.sh`.

**Never run `npm install` on this package outside the VibeAudit sandbox.**
