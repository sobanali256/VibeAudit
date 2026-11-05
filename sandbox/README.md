# sandbox

Audits run on stock, pinned images on the sandbox host (VM 2), always under gVisor. Nothing is built from the audited repo, and no secrets are ever baked in:

- `node:22-bookworm-slim` unpacks, installs, builds and starts the audited app, and runs the in-sandbox scanners. The proxy env and the proxy CA's public cert are added at `docker run` time by `containerArgs()` (`packages/shared/src/sandbox.ts`).
- `curlimages/curl:8.17.0` runs the HTTP probes and the port check.
- `mcr.microsoft.com/playwright:v1.56.1-noble` provides the headless Chromium for the logged-out browser pass. A small Node script inside the container drives Chromium over CDP, with no route to the outside network.
- `busybox:1.37` handles workspace setup and teardown and reads the firewall log.

`infra/sbx/setup.sh` pre-pulls all four, so pulls don't eat an audit's time budget. Keep this list in sync with the worker.
