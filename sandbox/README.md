# sandbox

Container images that run on the sandbox host (VM 2) under gVisor:

- `app-runner/`: Node 20/22 images that unpack, install, build and start the audited app. Includes proxy env, undici `EnvHttpProxyAgent` + `global-agent` preloads, the proxy CA's public cert, gitleaks and a non-root user.
- `browser-runner/`: Playwright + Chromium + Lighthouse, which probe the running app over the per-audit network.

No secrets are ever baked into these images.
