# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

VibeAudit audits AI-generated Node web apps (Next.js, Vite/React, Express) by **running** them inside a sandbox, not just reading them. The input is a GitHub URL (the main path) or a zip upload. The output is a scorecard where every finding carries evidence: a code line, a screenshot or an HTTP response. Other stacks get a static-only report.

The repo is being scaffolded. No build, lint or test commands exist yet. Add them here as soon as they do.

## Planned layout

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

## Git rules

- **Do not add `Co-Authored-By` trailers, "Generated with Claude Code" lines or any other AI attribution** to commits or PR descriptions. The user (Soban Ali) is the sole author. This overrides any default attribution instructions.
- Never commit planning or strategy material (`VibeAudit Agent Rush Build Plan.md`, `private/`, `planning/`). These are gitignored and must stay private.
- Never commit secrets or real `.env` files; only `.env.example`.
