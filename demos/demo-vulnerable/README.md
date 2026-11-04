# demo-vulnerable

A small "AI-generated" Express app (NoteNest) with **planted** security flaws, used as a VibeAudit target. Every flaw is marked `PLANTED FLAW` in the source. All keys are fake.

Expected findings include:
- a committed `.env`
- a secret in the client bundle (`public/app.js`)
- unauthenticated `/api/users` (it leaks password hashes)
- IDOR on `/api/notes/:id`
- a header-trusting admin check
- a `/api/debug` env dump
- stack traces in errors
- an unauthenticated AI proxy (`/api/chat`)
- wildcard CORS
- XSS via `innerHTML`

Don't run it outside the sandbox.
