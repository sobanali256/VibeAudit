# demo-vulnerable

A small "AI-generated" Express app (NoteNest) with **planted** security flaws, used as a VibeAudit target. Every flaw is marked `PLANTED FLAW` in the source. All keys are fake.

Runtime-confirmed findings (the audit proves each one by running the app and hitting it):
- a committed `.env` (detected at intake)
- unauthenticated `/api/users` (leaks password hashes)
- `/api/debug` env dump
- IDOR on `/api/notes/:id` (any record readable by id)
- a header-trusting admin check (`POST /api/admin/delete-user` with `x-user-role: admin`)
- stack traces leaked by `/api/crash`
- an unauthenticated AI proxy (`/api/chat`)
- wildcard CORS

Also present, flagged once static/client-bundle scanning lands:
- a secret shipped in the client bundle (`public/app.js`)
- XSS via `innerHTML`

Don't run it outside the sandbox.
