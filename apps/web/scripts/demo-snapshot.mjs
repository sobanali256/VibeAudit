// Snapshot finished audits from a live VibeAudit instance into apps/web/demo-data/, for the
// read-only demo (VIBEAUDIT_DEMO=1). Uses only the public API any visitor can call:
//   GET /api/audits/<id>                    -> view.json
//   GET /api/audits/<id>/events?after=0     -> events.json (SSE replay until "end")
//   GET /api/audits/<id>/artifacts/<name>   -> public/demo/<id>/<name> (JPEG only)
// Usage: node apps/web/scripts/demo-snapshot.mjs https://host id1 id2 ...
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [base, ...ids] = process.argv.slice(2);
if (!base || !ids.length) throw new Error("usage: demo-snapshot.mjs <base-url> <audit-id>...");
const WEB = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(WEB, "demo-data");
const ID_RE = /^[a-z0-9]{20}$/;
const NAME_RE = /^[a-z0-9-]{1,40}\.jpg$/;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function get(url, tries = 4) {
  for (let i = 0; ; i++) {
    const res = await fetch(url);
    if (res.status === 429 && i < tries) {
      await sleep(1000 * Number(res.headers.get("retry-after") || 2));
      continue;
    }
    if (!res.ok) throw new Error(`${res.status} ${url}`);
    return res;
  }
}

/** Read the SSE replay of a finished audit: every "ev" until the server sends "end". */
async function events(id) {
  const res = await get(`${base}/api/audits/${id}/events?after=0`);
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  const out = [];
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const block = buf.slice(0, i);
      buf = buf.slice(i + 2);
      const field = (k) => block.split("\n").filter((l) => l.startsWith(k + ":")).map((l) => l.slice(k.length + 1).replace(/^ /, ""));
      const ev = field("event")[0];
      if (ev === "ev") out.push(JSON.parse(field("data").join("\n")));
      if (ev === "end") {
        reader.cancel();
        return out;
      }
    }
  }
  return out;
}

for (const id of ids) {
  if (!ID_RE.test(id)) throw new Error(`bad id ${id}`);
  const dir = join(OUT, id);
  const pub = join(WEB, "public", "demo", id);
  mkdirSync(dir, { recursive: true });
  mkdirSync(pub, { recursive: true });
  const view = await (await get(`${base}/api/audits/${id}`)).json();
  if (!view.report) throw new Error(`${id} has no report`);
  view.isOwner = false;
  const evs = await events(id);
  writeFileSync(join(dir, "view.json"), JSON.stringify(view, null, 1));
  writeFileSync(join(dir, "events.json"), JSON.stringify(evs, null, 1));
  // Every artifact name the report or the events mention.
  const names = new Set();
  JSON.stringify([view, evs], (_k, v) => {
    if (typeof v === "string" && NAME_RE.test(v)) names.add(v);
    return v;
  });
  for (const n of names) {
    const res = await fetch(`${base}/api/audits/${id}/artifacts/${n}`);
    if (!res.ok || res.headers.get("content-type") !== "image/jpeg") continue;
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf[0] !== 0xff || buf[1] !== 0xd8) continue;
    writeFileSync(join(pub, n), buf);
    await sleep(150);
  }
  console.log(id, view.source?.repo, "events", evs.length, "artifacts", names.size);
}
