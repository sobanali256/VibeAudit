// VibeAudit demo target. Every flaw below is intentional and labelled PLANTED FLAW.
const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());

// PLANTED FLAW: wildcard CORS with credentials-style intent.
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  next();
});

// Load .env by hand (typical AI-generated pattern).
for (const line of fs.readFileSync(path.join(__dirname, ".env"), "utf8").split("\n")) {
  const m = /^([A-Z_]+)=(.*)$/.exec(line.trim());
  if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
}

// "Database": in-memory users with emails and password hashes.
const users = [
  { id: 1, email: "alice@example.com", role: "admin", passwordHash: "5f4dcc3b5aa765d61d8327deb882cf99" },
  { id: 2, email: "bob@example.com", role: "user", passwordHash: "e10adc3949ba59abbe56e057f20f883e" },
  { id: 3, email: "carol@example.com", role: "user", passwordHash: "25d55ad283aa400af464c76d713c07ad" },
];
const notes = [
  { id: 1, ownerId: 1, text: "Quarterly revenue numbers: confidential" },
  { id: 2, ownerId: 2, text: "Bob's private note" },
];

// PLANTED FLAW: full user table (incl. password hashes) with no authentication.
app.get("/api/users", (req, res) => res.json(users));

// PLANTED FLAW: IDOR - any note readable by id, no ownership check.
app.get("/api/notes/:id", (req, res) => {
  const note = notes.find((n) => n.id === Number(req.params.id));
  note ? res.json(note) : res.status(404).json({ error: "not found" });
});

// PLANTED FLAW: "admin" check trusts a client-supplied header.
app.post("/api/admin/delete-user", (req, res) => {
  if (req.headers["x-user-role"] !== "admin") return res.status(403).json({ error: "admins only" });
  const i = users.findIndex((u) => u.id === Number(req.body.id));
  if (i >= 0) users.splice(i, 1);
  res.json({ ok: true });
});

// PLANTED FLAW: hard-coded admin password compared in plain text.
app.post("/api/login", (req, res) => {
  if (req.body.password === process.env.ADMIN_PASSWORD) return res.json({ token: "admin-" + Date.now() });
  res.status(401).json({ error: "bad password" });
});

// PLANTED FLAW: debug endpoint that dumps the environment (secrets included).
app.get("/api/debug", (req, res) => res.json({ env: process.env, cwd: process.cwd() }));

// PLANTED FLAW: verbose errors leak stack traces.
app.get("/api/crash", () => {
  throw new Error("Unexpected failure in payment module at /srv/app/payments.js:42");
});

// PLANTED FLAW: the AI proxy endpoint has no auth or rate limit, so anyone can burn the key.
app.post("/api/chat", async (req, res) => {
  try {
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: String(req.body.message ?? "") }] }),
    });
    res.status(r.status).json(await r.json());
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

app.use(express.static(path.join(__dirname, "public")));

app.use((err, req, res, next) => {
  res.status(500).send(`<pre>${err.stack}</pre>`);
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, "0.0.0.0", () => console.log(`demo-vulnerable listening on ${port}`));
