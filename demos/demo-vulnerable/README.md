# demo-vulnerable

A small "AI-generated" Express app (NoteNest) with **planted** security flaws, used as a VibeAudit target. Every flaw is marked `PLANTED FLAW` in the source. All keys are fake.

Found by the secret scan (the key sits in the file, so it's confirmed without running anything):
- a committed `.env` holding an OpenAI-format key

Runtime-confirmed findings (the audit proves each one by running the app and hitting it):
- unauthenticated `/api/users` (leaks password hashes)
- `/api/debug` env dump
- IDOR on `/api/notes/:id` (any record readable by id)
- a header-trusting admin check (`POST /api/admin/delete-user` with `x-user-role: admin`)
- stack traces leaked by `/api/crash`
- an unauthenticated AI proxy (`/api/chat`)
- wildcard CORS

Static suspicions (flagged by the LLM code review; they can't be proven just by running the app):
- a hard-coded admin password compared in plain text (`/api/login` vs `ADMIN_PASSWORD`)
- a secret shipped in the client bundle (`public/app.js`; its fake key isn't in a real key format,
  so the secret scan leaves it to the review)
- XSS via `innerHTML`

Don't run it outside the sandbox.
