import { z } from "zod";
import type { Sandbox } from "./sandbox";

// Browser pass: headless Chromium in a `browser`-role container visits the running app, logged
// out, and reports per page: HTTP status, final URL, title, visible text and a JPEG screenshot.
//
// No npm packages: the Playwright image ships Chromium (headless_shell) and Node 22, whose
// built-in WebSocket is enough to drive Chromium over the DevTools protocol. The script runs
// inside the sandbox; everything it prints is untrusted (the page controls title, text, pixels
// and even the JS globals our expression reads) and is parsed and capped here on VM 1.

export const BROWSER_IMAGE = "mcr.microsoft.com/playwright:v1.56.1-noble";

/** Logged-out paths worth a look. "/" is the app itself; the rest should not be public. */
export const CANDIDATE_PATHS = ["/", "/admin", "/dashboard", "/admin/users", "/settings", "/account", "/users"] as const;

const MAX_PAGES = 8;
const PAGE_LOAD_MS = 10_000;
const SETTLE_MS = 1_500;
const MAX_TEXT = 3_000;
const MAX_TITLE = 300;
const MAX_URL = 2_000;
/** Base64 cap per screenshot (~450 KB decoded); a 1280x800 JPEG at q60 is usually < 150 KB. */
const MAX_IMG_B64 = 600_000;
/**
 * Replay frames (Chromium's screencast while each page loads): small JPEGs, a few per page,
 * at least FRAME_GAP_MS apart. Caps keep the whole run's output bounded whatever the page does.
 */
export const MAX_FRAMES_PER_PAGE = 6;
export const MAX_FRAMES_TOTAL = 36;
const FRAME_GAP_MS = 250;
/** Base64 cap per frame (~110 KB decoded); a 640x400 JPEG at q40 is usually < 40 KB. */
const MAX_FRAME_B64 = 150_000;
/** All frames together, so screenshots (the evidence) always fit in the output cap first. */
const MAX_FRAME_BYTES_TOTAL = 2_000_000;
/** Whole-run stdout cap: MAX_PAGES screenshots, the replay frames and text, with headroom. */
export const BROWSE_MAX_OUTPUT = 8 * 1024 * 1024; // the sandbox run ceiling; lines are per page, so a cut-off run still parses

/**
 * Runs as `node -e` in the browser container. Inputs come via env (VA_BASE, VA_PATHS,
 * VA_BYPASS) so nothing is spliced into the source. One output line per page:
 * `__VA_PAGE__{json}`.
 *
 * Chromium is pointed at a dead local proxy with only the app's IP bypassed, so a page that
 * pulls fonts/CDNs/analytics fails inside the container instead of putting packets on the
 * wire (which the firewall would drop and log as noise in the containment log).
 */
export const BROWSE_SCRIPT = `
const {spawn}=require("child_process"),fs=require("fs");
const BASE=process.env.VA_BASE,PATHS=JSON.parse(process.env.VA_PATHS||"[]"),BYPASS=process.env.VA_BYPASS;
const LOAD=${PAGE_LOAD_MS},SETTLE=${SETTLE_MS},MAXT=${MAX_TEXT},FPP=${MAX_FRAMES_PER_PAGE},FGAP=${FRAME_GAP_MS},FB64=${MAX_FRAME_B64};
let framesLeft=${MAX_FRAMES_TOTAL},frameBytes=0;const FBUDGET=${MAX_FRAME_BYTES_TOTAL},IMGMAX=${MAX_IMG_B64};
const out=o=>process.stdout.write("__VA_PAGE__"+JSON.stringify(o)+"\\n");
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const root="/ms-playwright";
const dir=fs.readdirSync(root).filter(d=>d.startsWith("chromium_headless_shell-")).sort().pop();
if(!dir){out({fatal:"no chromium"});process.exit(0)}
const ch=spawn(root+"/"+dir+"/chrome-linux/headless_shell",["--no-sandbox","--disable-dev-shm-usage","--disable-gpu","--no-first-run","--no-default-browser-check","--disable-background-networking","--disable-component-update","--disable-sync","--disable-extensions","--disable-features=Translate,OptimizationHints,MediaRouter","--mute-audio","--hide-scrollbars","--proxy-server=http://127.0.0.1:9","--proxy-bypass-list="+BYPASS,"--force-webrtc-ip-handling-policy=disable_non_proxied_udp","--webrtc-ip-handling-policy=disable_non_proxied_udp","--remote-debugging-port=0","--user-data-dir=/tmp/va-prof","--window-size=1280,800","about:blank"],{stdio:["ignore","ignore","pipe"]});
let err="";const wsUrl=new Promise((res,rej)=>{ch.stderr.on("data",d=>{err=(err+d).slice(-4000);const m=/DevTools listening on (ws:\\/\\/\\S+)/.exec(err);if(m)res(m[1])});ch.on("exit",c=>rej(new Error("chromium exited "+c+": "+err.slice(-300))));setTimeout(()=>rej(new Error("chromium did not start")),30000)});
let ws,seq=0;const pend=new Map(),subs=new Set();
const send=(method,params,sessionId,ms)=>new Promise((res,rej)=>{const id=++seq;pend.set(id,{res,rej});ws.send(JSON.stringify({id,method,params:params||{},sessionId}));setTimeout(()=>{if(pend.delete(id))rej(new Error(method+" timed out"))},ms||15000)});
async function visit(p){
  const {targetId}=await send("Target.createTarget",{url:"about:blank"});
  const {sessionId:s}=await send("Target.attachToTarget",{targetId,flatten:true});
  // A load event counts only once the real page has committed (about:blank's can arrive late).
  let status=0,loaded=false,committed=false;const frame=targetId;
  // Replay frames: keep a few, spaced out; ack every one or Chromium stops sending.
  const fr=[];let lastF=0,castOn=false;
  // Stop recording as soon as this page (or the run) has all the frames it will keep: a page that
  // animates forever would otherwise make Chromium encode and send a JPEG on every paint.
  const stopCast=()=>{if(castOn){castOn=false;send("Page.stopScreencast",{},s,3000).catch(()=>{})}};
  const h=m=>{if(m.sessionId!==s)return;const q=m.params||{};
    if(m.method==="Page.screencastFrame"){send("Page.screencastFrameAck",{sessionId:q.sessionId},s).catch(()=>{});
      // Only once the real page has committed: earlier paints are about:blank.
      const now=Date.now();if(committed&&fr.length<FPP&&framesLeft>0&&now-lastF>=FGAP&&typeof q.data==="string"&&q.data.length<=FB64&&frameBytes+q.data.length<=FBUDGET){fr.push(q.data);framesLeft--;frameBytes+=q.data.length;lastF=now}
      if(fr.length>=FPP||framesLeft<=0||frameBytes>=FBUDGET-FB64)stopCast();return}
    if(m.method==="Network.responseReceived"&&q.type==="Document"&&q.frameId===frame)status=q.response.status;
    else if(m.method==="Page.frameNavigated"&&q.frame&&q.frame.id===frame&&!String(q.frame.url).startsWith("about:"))committed=true;
    else if(m.method==="Page.loadEventFired"&&committed)loaded=true;
    else if(m.method==="Page.javascriptDialogOpening")send("Page.handleJavaScriptDialog",{accept:false},s).catch(()=>{});};
  subs.add(h);
  try{
    await send("Page.enable",{},s);await send("Network.enable",{},s);
    await send("Emulation.setDeviceMetricsOverride",{width:1280,height:800,deviceScaleFactor:1,mobile:false},s);
    if(framesLeft>0&&frameBytes<FBUDGET-FB64)await send("Page.startScreencast",{format:"jpeg",quality:40,maxWidth:640,maxHeight:400,everyNthFrame:1},s,5000).then(()=>{castOn=true}).catch(()=>{});
    const nav=await send("Page.navigate",{url:BASE+p},s);
    if(nav.errorText){out({p,err:String(nav.errorText).slice(0,200),fr});return}
    const t0=Date.now();while(!loaded&&Date.now()-t0<LOAD)await sleep(100);
    await sleep(SETTLE);
    let info={};
    // Read the page from an isolated world: its own globals and prototypes, so the page can't
    // override String/JSON/slice to bloat or reshape what we read. Values are re-checked below.
    try{const w=await send("Page.createIsolatedWorld",{frameId:frame,worldName:"va"},s,5000);
      const r=await send("Runtime.evaluate",{contextId:w.executionContextId,expression:"({u:String(location.href).slice(0,2000),t:String(document.title).slice(0,300),x:String((document.body&&document.body.innerText)||'').slice(0,"+MAXT+"),pw:document.querySelectorAll('input[type=password]').length})",returnByValue:true},s,5000);
      info=(r.result&&r.result.value)||{}}catch(e){}
    const str=(v,n)=>typeof v==="string"?v.slice(0,n):undefined;
    stopCast();
    let img=null;try{img=(await send("Page.captureScreenshot",{format:"jpeg",quality:60},s,10000)).data}catch(e){}
    if(typeof img==="string"&&img.length>IMGMAX)img=null; // the parser would drop it anyway; don't spend output on it
    out({p,status,loaded,u:str(info.u,2000),t:str(info.t,300),x:str(info.x,MAXT),pw:Number.isInteger(info.pw)&&info.pw>=0?info.pw:0,img:typeof img==="string"?img:null,fr});
  }catch(e){out({p,err:String(e&&e.message||e).slice(0,200),fr})}
  finally{subs.delete(h);send("Target.closeTarget",{targetId}).catch(()=>{})}
}
(async()=>{
  try{
    ws=new WebSocket(await wsUrl);
    await new Promise((res,rej)=>{ws.onopen=res;ws.onerror=()=>rej(new Error("devtools connect failed"))});
    ws.onmessage=ev=>{let m;try{m=JSON.parse(ev.data)}catch{return}
      if(m.id){const q=pend.get(m.id);if(q){pend.delete(m.id);m.error?q.rej(new Error(m.error.message)):q.res(m.result)}}
      else for(const h of subs)h(m)};
    for(const p of PATHS)await visit(p);
  }catch(e){out({fatal:String(e&&e.message||e).slice(0,300)})}
  try{ch.kill("SIGKILL")}catch{}
  process.exit(0);
})();
`;

export interface PageCapture {
  path: string;
  /** Main document HTTP status (0 = no response). */
  status: number;
  /** Path (+query) the page ended on, relative to the app; null if it left the app's origin;
   *  undefined if we couldn't read it. */
  finalPath: string | null | undefined;
  title: string;
  /** Visible text excerpt (for the vision prompt and SPA-fallback detection; not stored). */
  text: string;
  /** The page has a password field (a login form, not the protected content). */
  hasPassword: boolean;
  loaded: boolean;
  /** Decoded JPEG, already checked for the JPEG signature. */
  screenshot: Buffer | null;
  /** Replay frames while the page loaded (decoded, JPEG-checked), oldest first. */
  frames: Buffer[];
  error?: string;
}

// Lenient per field: one malformed value must not drop the page (and its screenshot).
const Line = z.object({
  p: z.string(),
  status: z.number().int().min(0).max(999).optional().catch(undefined),
  loaded: z.boolean().optional().catch(undefined),
  u: z.string().optional().catch(undefined),
  t: z.string().optional().catch(undefined),
  x: z.string().optional().catch(undefined),
  pw: z.number().int().nonnegative().optional().catch(undefined),
  img: z.string().nullable().optional().catch(undefined),
  fr: z.array(z.unknown()).max(MAX_FRAMES_PER_PAGE).optional().catch(undefined),
  err: z.string().optional().catch(undefined),
});

const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** Decode a screenshot, accepting only a plausible JPEG (signature + end marker). */
export function decodeJpeg(b64: unknown, maxB64 = MAX_IMG_B64): Buffer | null {
  if (typeof b64 !== "string" || b64.length < 16 || b64.length > maxB64 || b64.length % 4 !== 0 || !B64.test(b64)) return null;
  const buf = Buffer.from(b64, "base64");
  if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) return null;
  if (buf[buf.length - 2] !== 0xff || buf[buf.length - 1] !== 0xd9) return null;
  return buf;
}

/**
 * Where the page ended up, as an app-relative path; null if it left `base`'s origin (or
 * landed on a browser error page); undefined if there's no usable URL at all.
 */
export function relativePath(finalUrl: string | undefined, base: string): string | null | undefined {
  if (!finalUrl) return undefined;
  try {
    const u = new URL(finalUrl);
    if (u.origin !== new URL(base).origin) return null;
    return (u.pathname + u.search).slice(0, MAX_URL);
  } catch {
    return undefined;
  }
}

/** The page stayed on the path we asked for (a trailing-slash redirect counts as staying). */
export function stayed(p: PageCapture): boolean {
  if (p.finalPath === undefined) return true;
  if (p.finalPath === null) return false;
  const path = p.finalPath.split("?")[0]!;
  return path === p.path || path === `${p.path}/`;
}

/** Parse the script's stdout. Only requested paths count, each once, in request order. */
export function parseBrowse(stdout: string, requested: readonly string[], base: string): { pages: PageCapture[]; fatal?: string } {
  const byPath = new Map<string, PageCapture>();
  let fatal: string | undefined;
  for (const raw of stdout.split("\n")) {
    if (!raw.startsWith("__VA_PAGE__")) continue;
    let obj: unknown;
    try {
      obj = JSON.parse(raw.slice("__VA_PAGE__".length));
    } catch {
      continue;
    }
    if (obj && typeof obj === "object" && typeof (obj as { fatal?: unknown }).fatal === "string") {
      fatal ??= String((obj as { fatal: string }).fatal).slice(0, 300);
      continue;
    }
    const r = Line.safeParse(obj);
    if (!r.success || !requested.includes(r.data.p) || byPath.has(r.data.p)) continue;
    const d = r.data;
    byPath.set(d.p, {
      path: d.p,
      status: d.status ?? 0,
      finalPath: relativePath(d.u?.slice(0, MAX_URL), base),
      title: (d.t ?? "").slice(0, MAX_TITLE),
      text: (d.x ?? "").slice(0, MAX_TEXT),
      hasPassword: (d.pw ?? 0) > 0,
      loaded: d.loaded ?? false,
      screenshot: decodeJpeg(d.img),
      frames: (d.fr ?? []).map((f) => decodeJpeg(f, MAX_FRAME_B64)).filter((b): b is Buffer => b !== null),
      error: d.err?.slice(0, 200),
    });
  }
  return { pages: requested.filter((p) => byPath.has(p)).map((p) => byPath.get(p)!), fatal };
}

/** Visit `paths` on the app at ip:port from a browser container. Never throws. */
export async function browse(
  sandbox: Sandbox,
  id: string,
  ip: string,
  port: number,
  paths: readonly string[] = CANDIDATE_PATHS,
  timeoutMs = 120_000,
): Promise<{ pages: PageCapture[]; why?: string }> {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || !Number.isInteger(port) || port < 1 || port > 65535) return { pages: [], why: "bad target" };
  const list = paths.slice(0, MAX_PAGES);
  const base = `http://${ip}:${port}`;
  try {
    const r = await sandbox.run({
      role: "browser",
      image: BROWSER_IMAGE,
      cmd: ["node", "-e", BROWSE_SCRIPT],
      env: { VA_BASE: base, VA_PATHS: JSON.stringify(list), VA_BYPASS: ip },
      timeoutMs,
      maxOutput: BROWSE_MAX_OUTPUT,
      name: `va-${id}-browser`,
    });
    const parsed = parseBrowse(r.stdout, list, base);
    const why =
      parsed.fatal ??
      (parsed.pages.length
        ? r.truncated
          ? "output cap reached, later pages missing"
          : undefined
        : `exit ${r.code}${r.timedOut ? ", timed out" : ""}${r.stderr.trim() ? `: ${r.stderr.trim().slice(-200)}` : ""}`);
    return { pages: parsed.pages, why };
  } catch (e) {
    return { pages: [], why: String((e as Error)?.message ?? e).slice(0, 200) };
  }
}

/** Normalised visible text, for spotting an SPA that serves its home page for every path. */
export function sameContent(a: PageCapture, b: PageCapture): boolean {
  const norm = (s: string) => s.replace(/\s+/g, " ").trim().slice(0, 1500);
  return norm(a.text) === norm(b.text) && a.title === b.title;
}

/**
 * Which captures are worth keeping as evidence: the home page, plus any other path that
 * served a 2xx page of its own: not a 404, not a redirect to somewhere else (CDP reports the
 * final response of a redirect chain, so a 302 to /login arrives as a 200), not a login form
 * and not the SPA's home page again.
 */
export function worthKeeping(pages: readonly PageCapture[]): PageCapture[] {
  const home = pages.find((p) => p.path === "/");
  return pages.filter((p) => {
    if (!p.screenshot) return false;
    if (p.path === "/") return true;
    if (p.status < 200 || p.status >= 300 || !stayed(p) || p.hasPassword) return false;
    return !(home && sameContent(home, p));
  });
}
