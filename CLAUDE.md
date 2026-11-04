# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

VibeAudit audits AI-generated Node web apps (Next.js, Vite/React, Express) by **running** them inside a sandbox, not just reading them. The input is a GitHub URL (the main path) or a zip upload. The output is a scorecard where every finding carries evidence: a code line, a screenshot or an HTTP response. Other stacks get a static-only report.

## Commands

This is a pnpm workspace (pnpm 11, Node ≥ 22). Run everything from the repo root.

```bash
pnpm install
pnpm db:up                     # local Postgres (docker-compose.dev.yml), db:down to stop
pnpm dev                       # web + worker in parallel
pnpm --filter @vibeaudit/web dev
pnpm --filter @vibeaudit/worker dev
pnpm test                      # vitest, all packages
pnpm vitest run packages/shared/src/github.test.ts   # one file
pnpm vitest run -t "parseGitHubUrl"                  # by test name
pnpm typecheck                 # web runs `next typegen` first (needed for LayoutProps etc.)
pnpm lint
pnpm build
```

- pnpm 11 blocks dependency install scripts unless they're allowed in `pnpm-workspace.yaml` (`allowBuilds`). Only allow what's required.
- `apps/web` runs **Next.js 16**. Its APIs differ from older versions, so check `apps/web/node_modules/next/dist/docs/` before writing Next code (see `apps/web/AGENTS.md`).
- `packages/shared` is consumed as TS source (no build step). Next transpiles it via `transpilePackages`, and the worker runs under `tsx`. Use extensionless relative imports (`moduleResolution: Bundler`).

## Layout

- `packages/shared`: types shared by web and worker. Includes the audit stages, timeouts and intake limits (`audit.ts`), and the finding schema (`finding.ts`), where every finding needs ≥1 evidence item. `parseGitHubUrl` (`github.ts`) is the single gate for user-supplied repo URLs, and its output is what gets interpolated into GitHub API paths.
- `apps/web`: Next.js + TypeScript UI and API. It streams audit progress to the browser over SSE.
- `apps/worker`: a separate Node process running the job queue and agent loop (planner, build-fixer, code reviewer, screenshot verifier). Long audits run here, never in Next.js route handlers.
- `sandbox/`: container images (app runner with proxy preloads, Playwright/Lighthouse browser runner).
- `infra/`: provisioning scripts for the two Vultr VMs (gVisor, iptables egress lock, mitmproxy addon, Caddy).
- `demos/`: intentionally vulnerable or hostile sample apps used as audit targets. **Never install or run these on a dev machine or on VM 1.** Their `postinstall` scripts are hostile by design.

## Trust boundary (do not break these invariants)

There are two VMs on a Vultr VPC:

- **VM 1 (control plane)** holds every secret: Postgres, the Vultr Inference key, user test keys and GitHub tokens. It **never executes or unpacks repo code**. It downloads tarballs and streams them to VM 2 unopened. All LLM calls (Vultr Serverless Inference, `https://api.vultrinference.com/v1`) happen here, and the LLM has no tools. Treat everything that comes back from the sandbox (file contents, build logs) as untrusted. Escape it when rendering, and never `eval` or shell-exec it on VM 1.
- **VM 2 (sandbox host)** runs repo code in per-audit Docker containers under gVisor (`runsc`). It holds no secrets. The worker drives it via `docker context` over SSH on the VPC. Never expose the Docker TCP socket.
- The only egress from sandbox containers is the mitmproxy on VM 1 (`<VM1-VPC-IP>:8080`), enforced by `DOCKER-USER` iptables rules. The proxy applies a per-stage host allowlist and swaps `sk-PLACEHOLDER-<VAR>-<auditId>` placeholders for real test keys on the wire.
- Env vars inside sandboxes are canary stubs or placeholders, never real values. Only the proxy CA's *public* cert is mounted.
- Every container gets CPU and memory caps, `--pids-limit`, `--cap-drop ALL`, `no-new-privileges`, a non-root user, and stage time caps. Containers and the audit network are destroyed after every audit, pass or fail. A janitor kills anything older than 30 minutes.
- Repo code only ever runs via `docker run` under runsc (`BASE_CONTAINER_FLAGS` in `packages/shared/src/sandbox.ts`). **Never `docker build` a repo-controlled Dockerfile or context on VM 2**: BuildKit `RUN` steps use runc on the host kernel.
- gVisor quirks that the worker relies on: the pids cap also counts sentry threads, so keep it ≥ 512. Docker's embedded DNS doesn't work, so wire container names with `--add-host`. The rootfs is memory-backed (`--overlay2=root:memory`), so the workspace needs its own size-capped volume.
- On VM 1, three users keep powers apart:
  - `vibedeploy` builds releases and holds no secrets.
  - `vibeweb` runs the internet-facing app, sees only `/etc/vibeaudit/web.env`, and can't read the worker key or the proxy dir.
  - `vibeaudit` runs the worker and holds the VM 2 docker key.
  - Don't give the web more secrets or docker access.
- The proxy contract (`ProxyState` and `ProxyEvent` in `sandbox.ts`) must stay in sync with `infra/cp/proxy/vibeaudit_proxy.py`. Run `infra/sbx/selftest.sh` and `infra/cp/proxy/selftest.sh` after any infra change.

## Git rules

- **Do not add `Co-Authored-By` trailers, "Generated with Claude Code" lines or any other AI attribution** to commits or PR descriptions. The user (Soban Ali) is the sole author. This overrides any default attribution instructions.
- Never commit planning or strategy material (`VibeAudit Agent Rush Build Plan.md`, `private/`, `planning/`). These are gitignored and must stay private.
- Never commit secrets or real `.env` files; only `.env.example`.
