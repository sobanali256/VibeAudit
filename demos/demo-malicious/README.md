# demo-malicious

An innocent-looking "Weather Now" app whose **postinstall is hostile by design**: a stand-in
for a supply-chain-compromised dependency. It is used to show, in a live audit, that
VibeAudit's sandbox contains install-time attacks, and which control stops each one.

The postinstall (`scripts/setup.js`) runs a short attack lab. Each attempt is bounded and aimed
so it can't do harm anywhere:

| # | What it tries | What should stop it in VibeAudit |
|---|---|---|
| 1 | Read secrets from the environment | Only canary stubs are there, never real keys |
| 2 | Smuggle a secret out through a host install is allowed to reach (an npm registry search query) | Egress proxy: the planted canary is spotted in the URL and the request is blocked |
| 3 | Phone home directly, skipping the proxy (`192.0.2.1:443`, a reserved address) | VM 2 firewall egress lock |
| 4 | Read cloud credentials from the metadata service (`169.254.169.254`) | VM 2 firewall egress lock |
| 5 | Reach the sandbox host's Docker API (`:2375`) and SSH (`:22`) | VM 2 firewall host lock |
| 6 | Look for a mounted Docker socket | Not mounted |

The only value it ever sends is `VIBEAUDIT_CANARY`, a fake that the VibeAudit sandbox plants.
Outside the sandbox that variable doesn't exist and the step is skipped. It does not fork-bomb,
allocate memory or write files. The full containment proof lives in `infra/sbx/selftest.sh`
and `infra/cp/proxy/selftest.sh` in the VibeAudit repo.

**Never run `npm install` on this package outside the VibeAudit sandbox.**
