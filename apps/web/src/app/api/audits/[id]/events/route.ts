import type { AuditEventRow } from "@vibeaudit/db";
import { AUDIT_ID_RE } from "@vibeaudit/shared";
import { loadAuditView, sharedAuditView, sharedEvents, toEventView } from "@/lib/audits";
import { subscribe } from "@/lib/db";
import { DEMO, demoEvents, demoView } from "@/lib/demo";
import { limits } from "@/lib/rate-limit";
import { clientIp, isOwner, jsonError } from "@/lib/request";
import { isTerminal } from "@/lib/view";

// Server-Sent Events: progress for one audit.
//   event: state  data: AuditView         (on connect and whenever the row changes)
//   event: ev     data: AuditEventView    (id: = event id, so EventSource resumes via Last-Event-ID)
//   event: end                            (audit finished and every event was sent)
// Updates are pushed by a shared Postgres LISTEN (one connection per process); a slow timer
// is the backstop if a NOTIFY is missed. Streams watching the same audit share their reads.

const MAX_STREAMS = 200;
const MAX_STREAMS_PER_IP = 6;
const PAGE = 200;
const DEBOUNCE_MS = 100;
const BACKSTOP_MS = 15_000;
/** After the audit turns terminal, wait this long for trailing events before hanging up. */
const END_GRACE_MS = 3_000; // > the worker's 2 s approval poll, so its `cancelled` event usually lands
const MAX_LIFETIME_MS = 30 * 60_000; // the browser reconnects (and resumes) after this
/** Queue limit (chunks) before we stop paging and wait for a slow reader to catch up. */
const HIGH_WATER = 64;

const g = globalThis as typeof globalThis & { __vibeauditStreams?: { total: number; perIp: Map<string, number> } };
const streams = (g.__vibeauditStreams ??= { total: 0, perIp: new Map() });

export async function GET(req: Request, ctx: RouteContext<"/api/audits/[id]/events">) {
  const { id } = await ctx.params;
  if (!AUDIT_ID_RE.test(id)) return jsonError(404, "audit not found");
  if (DEMO) return demoStream(id);

  const ip = clientIp(req);
  const wait = limits.read.take(ip);
  if (wait) return jsonError(429, "slow down", { "retry-after": String(wait) });
  if (streams.total >= MAX_STREAMS || (streams.perIp.get(ip) ?? 0) >= MAX_STREAMS_PER_IP) {
    return jsonError(429, "too many open progress streams", { "retry-after": "10" });
  }

  const first = await loadAuditView(id, (row) => isOwner(req, id, row.owner_hash));
  if (!first) return jsonError(404, "audit not found");
  if (req.signal.aborted) return new Response(null, { status: 499 });
  // Ownership can't change after creation: check the cookie once, not on every update.
  const owner = first.isOwner;

  const resume = req.headers.get("last-event-id") ?? new URL(req.url).searchParams.get("after") ?? "0";
  let lastId = /^\d{1,19}$/.test(resume) ? resume : "0";

  // Counted from here on; every exit path below goes through cleanup().
  streams.total++;
  streams.perIp.set(ip, (streams.perIp.get(ip) ?? 0) + 1);
  const enc = new TextEncoder();
  let closed = false;
  let unsubscribe: (() => void) | null = null;
  const timers = new Set<ReturnType<typeof setTimeout>>();
  let backstop: ReturnType<typeof setInterval> | null = null;
  let debounce: ReturnType<typeof setTimeout> | null = null;
  let lastState = "";
  let busy = false;
  let dirty = false;
  let freshNext = true; // first read and backstop reads bypass the shared cache
  let terminalSince = 0;
  let ctrl!: ReadableStreamDefaultController<Uint8Array>;

  const cleanup = () => {
    if (closed) return;
    closed = true;
    unsubscribe?.();
    if (backstop) clearInterval(backstop);
    if (debounce) clearTimeout(debounce);
    for (const t of timers) clearTimeout(t);
    streams.total--;
    const n = (streams.perIp.get(ip) ?? 1) - 1;
    if (n <= 0) streams.perIp.delete(ip);
    else streams.perIp.set(ip, n);
  };
  const close = () => {
    if (closed) return;
    cleanup();
    try {
      ctrl.close();
    } catch {
      // already closed by the client
    }
  };
  const later = (fn: () => void, ms: number) => {
    const t = setTimeout(() => {
      timers.delete(t);
      fn();
    }, ms);
    timers.add(t);
  };
  const write = (chunk: string) => {
    if (closed) return;
    try {
      ctrl.enqueue(enc.encode(chunk));
    } catch {
      cleanup();
    }
  };
  const writeEvents = (events: AuditEventRow[]) => {
    for (const e of events) {
      write(`id: ${e.id}\nevent: ev\ndata: ${JSON.stringify(toEventView(e))}\n\n`);
      lastId = e.id;
    }
  };
  const backedUp = () => (ctrl.desiredSize ?? 1) <= 0;

  // Coalesced: at most one pump in flight; notifications during it trigger one more pass.
  const pump = async () => {
    if (closed) return;
    if (busy) {
      dirty = true;
      return;
    }
    busy = true;
    const fresh = freshNext;
    freshNext = false;
    try {
      do {
        dirty = false;
        if (backedUp()) {
          later(schedule, 250); // slow reader: let it drain instead of buffering a replay
          return;
        }
        const events = await sharedEvents(id, lastId, PAGE, fresh);
        writeEvents(events);
        if (events.length === PAGE) dirty = true; // more to page through

        const view = await sharedAuditView(id, fresh);
        if (!view) {
          close();
          return;
        }
        const s = JSON.stringify({ ...view, isOwner: owner });
        if (s !== lastState) {
          lastState = s;
          write(`event: state\ndata: ${s}\n\n`);
        }
        if (isTerminal(view.status) && !dirty) {
          // A trailing event (e.g. `cancelled`) can be written just after the status flips.
          // Wait a moment, read once more straight from the db, then hang up.
          if (!terminalSince) {
            terminalSince = Date.now();
            later(schedule, END_GRACE_MS);
            return;
          }
          if (Date.now() - terminalSince < END_GRACE_MS) return; // the grace timer is pending
          const tail = await sharedEvents(id, lastId, PAGE, true);
          writeEvents(tail);
          if (tail.length < PAGE) {
            write("event: end\ndata: {}\n\n");
            close();
            return;
          }
          dirty = true;
        }
      } while (dirty && !closed);
    } catch {
      close(); // the browser reconnects and resumes from Last-Event-ID
    } finally {
      busy = false;
    }
  };
  function schedule() {
    if (closed || debounce) return;
    debounce = setTimeout(() => {
      debounce = null;
      void pump();
    }, DEBOUNCE_MS);
  }

  const stream = new ReadableStream<Uint8Array>(
    {
      async start(c) {
        ctrl = c;
        write("retry: 3000\n\n");
        req.signal.addEventListener("abort", close, { once: true });
        if (req.signal.aborted) return close();
        try {
          unsubscribe = await subscribe(id, schedule);
        } catch {
          return close();
        }
        if (closed) {
          unsubscribe();
          return;
        }
        backstop = setInterval(() => {
          write(": ping\n\n");
          freshNext = true;
          schedule();
        }, BACKSTOP_MS);
        later(close, MAX_LIFETIME_MS);
        void pump();
      },
      cancel() {
        cleanup();
      },
    },
    { highWaterMark: HIGH_WATER },
  );

  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store, no-transform",
      "x-accel-buffering": "no",
    },
  });
}

/** Read-only demo: the snapshot's state, every event, then end. Nothing is live, so no LISTEN. */
function demoStream(id: string): Response {
  const view = demoView(id);
  if (!view) return jsonError(404, "audit not found");
  const lines = [`event: state\ndata: ${JSON.stringify(view)}\n\n`];
  for (const e of demoEvents(id)) lines.push(`id: ${e.id}\nevent: ev\ndata: ${JSON.stringify(e)}\n\n`);
  lines.push("event: end\ndata: {}\n\n");
  return new Response(lines.join(""), {
    headers: { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}
