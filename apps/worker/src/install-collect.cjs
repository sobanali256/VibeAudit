// Install-hook collector. Runs INSIDE the sandbox app container as `node -e` (cwd = the repo),
// never on VM 1. install-scripts.ts prepends `const CFG={...};` (limits, hook lists, tool maps).
// It only reads files: no network, no exec. Its stdout is untrusted data to VM 1.
//
// VA_MODE=root: the repo's own install surfaces (lifecycle hooks, .npmrc node-options /
// script-shell, .pnpmfile.cjs, .yarnrc yarnPath/plugins, binding.gyp). VA_MODE=deps: every
// package in node_modules with install hooks, local (repo) packages first.
//
// For each package: hook commands are split into shell steps; each step's entry point is
// resolved (node + preload flags, shells, -c strings, $(...) / backticks, npm/pnpm/yarn script
// indirection, tools that load repo config files); the files reached are read and their
// requires/imports/child-process calls followed a few levels, never leaving the package dir.
// Anything that names code we couldn't read lands in `unresolved`; anything cut short sets
// `truncated`. The caller fails closed on either.
/* global CFG */
const fs = require("fs"), path = require("path");
const L = CFG.limits, BENIGN = new Set(CFG.benign), TOOL_CONFIGS = CFG.toolConfigs;
const MODE = process.env.VA_MODE;
const DEADLINE = Date.now() + L.deadlineMs;
let bytes = 0, reads = 0, partial = false;
const out = [];
const jb = (v) => Buffer.byteLength(JSON.stringify(v));
const rj = (p) => { if (++reads > L.maxReads) { partial = true; return null } try { return JSON.parse(fs.readFileSync(p, "utf8")) } catch { return null } };
const readText = (p, max) => { try { const fd = fs.openSync(p, "r"); const b = Buffer.alloc(max); const n = fs.readSync(fd, b, 0, max, 0); fs.closeSync(fd); return b.subarray(0, n).toString("utf8") } catch { return null } };
const inside = (dir, abs) => abs === dir || abs.startsWith(dir + path.sep);

const RUNTIMES = new Set(["node", "nodejs", "tsx", "ts-node", "bun", "deno"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash"]);
const PRELOAD = /^(?:-r|--require|--import|--loader|--experimental-loader)$/;
const PRELOAD_EQ = /^(?:--require|--import|--loader|--experimental-loader|-r)=(.+)$/;
const PM = new Set(["npm", "pnpm", "yarn", "bun"]);
const PM_BUILTIN = new Set(["install", "i", "add", "ci", "rebuild", "rb", "exec", "dlx", "x", "link", "ln", "prune", "dedupe", "audit", "config", "set", "get", "cache", "help", "version", "whoami", "ls", "list", "outdated", "why", "init", "create", "publish", "pack", "store", "env", "bin", "root", "prefix", "remove", "rm", "uninstall", "un", "update", "up", "upgrade", "import", "fetch", "setup", "doctor", "only-allow"]);
const PM_SCOPED = /^(?:--prefix|-C|--dir|--cwd|-r|--recursive|--filter|-F|-w|--workspace|--workspaces|-ws|--workspace-root)(?:=.*)?$/;
const SCRIPT_ALIASES = { start: "start", test: "test", t: "test", tst: "test", stop: "stop", restart: "restart" };

// Requires/imports a file pulls in (relative), and child-process calls (commands or paths).
const REQ_RE = /(?:require\(\s*|from\s+|import\(\s*|import\s+)["'`](\.{1,2}\/[^"'`$\n]{1,200})["'`]|path\.(?:join|resolve)\(\s*__dirname\s*,\s*["'`]([^"'`$\n]{1,200})["'`]|["'`]((?:\.{1,2}\/)?[\w@.\/-]{1,200}\.(?:c|m)?js|[\w@.\/-]{1,200}\.sh)["'`]/g;
const DYNAMIC_RE = /\b(?:require|import)\(\s*(?:(?!["'`]|\))[^)\n]{1,200}\)|["'`][^"'`\n]{0,200}["'`]\s*\+)/;
const SAFE_JOIN_RE = /(?:require|import)\(\s*path\.(?:join|resolve)\(\s*__dirname\s*,\s*["'`][^"'`$]+["'`]\s*\)\s*\)/g;
const isDynamic = (txt) => DYNAMIC_RE.test(String(txt).replace(SAFE_JOIN_RE, ""));
const CHILD_RE = /\b(fork|exec|execSync|execFile|execFileSync|spawn|spawnSync)\(\s*["'`]([^"'`$\n]{1,300})["'`]/g;

// Shell steps of a command. Quoted strings are pulled out first (kept whole as tokens), and
// $(...) / backtick bodies are returned as extra commands to classify too.
function steps(cmd) {
  const quotes = [], subs = [];
  let s = String(cmd).replace(/\$\(([^()]{0,2000})\)|`([^`]{0,2000})`/g, (m, a, b) => { subs.push(a !== undefined ? a : b); return " SUBST "; });
  s = s.replace(/"((?:[^"\\]|\\.){0,4000})"|'([^']{0,4000})'/g, (m, a, b) => { quotes.push(a !== undefined ? a : b); return "\u0000" + (quotes.length - 1) + "\u0000"; });
  const restore = (t) => t.replace(/\u0000(\d+)\u0000/g, (m, i) => quotes[+i]);
  const list = s.split(/&&|\|\||[;|\n]/).map((x) => x.trim().split(/\s+/).filter(Boolean).map(restore)).filter((w) => w.length);
  return { list, subs };
}

// Strip env assignments and runners to reach the real command; NODE_OPTIONS preloads kept.
function entry(w) {
  const preload = [];
  for (let i = 0; i < 10 && w.length; i++) {
    const a = /^([A-Za-z_]\w*)=(.*)$/.exec(w[0]);
    if (a) { if (a[1] === "NODE_OPTIONS") preload.push(...preloadsOf(a[2].split(/\s+/))); w = w.slice(1); continue; }
    if (w[0] === "npx" || w[0] === "bunx") { w = w.slice(1); while (w.length && /^(?:-y|--yes|--no|--no-install|-q|--quiet|--prefer-offline)$/.test(w[0])) w = w.slice(1); if (w.length && /^(?:-p|--package)(?:=|$)/.test(w[0])) return { w: ["npx-package"], preload }; continue; }
    if (w[0] === "cross-env" || (w[0] === "env" && w.length > 1)) { w = w.slice(1); continue; }
    if (w[0] === "dotenv" || w[0] === "env-cmd") { const dd = w.indexOf("--"); w = dd >= 0 ? w.slice(dd + 1) : w.slice(1).filter((x, i, arr) => !x.startsWith("-") && !(i > 0 && /^-[ef]$|^--file$/.test(arr[i - 1]))); continue; }
    if (PM.has(w[0]) && /^(?:exec|dlx|x)$/.test(w[1] || "")) { w = w.slice(2); if (w[0] === "--") w = w.slice(1); continue; }
    break;
  }
  return { w, preload };
}
function preloadsOf(args) {
  const need = [];
  for (let i = 0; i < args.length; i++) {
    const eq = PRELOAD_EQ.exec(args[i]);
    if (eq) need.push(eq[1]); else if (PRELOAD.test(args[i]) && args[i + 1]) need.push(args[++i]);
  }
  return need;
}

// What one step needs: { need:[paths], cmds:[sub-commands], script, configs:[...], unknown, moves, ok }.
function classify(raw, scripts, depth = 0) {
  if (depth > 8) return { need: [], cmds: [], configs: [], unknown: "nested package-manager call" };
  const { w, preload } = entry(raw);
  const r = { need: [...preload], cmds: [], configs: [] };
  if (!w.length) return r;
  const cmd = w[0], args = w.slice(1);
  if (cmd === "npx-package") { r.unknown = "npx --package"; return r; }
  if (cmd === "cd" || cmd === "pushd") { r.moves = args.find((a) => !a.startsWith("-")) || "~"; return r; }
  if (RUNTIMES.has(cmd)) {
    r.need.push(...preloadsOf(args));
    const inline = args.some((a) => /^(?:-e|--eval|-p|--print)$/.test(a));
    if (!inline) {
      for (let i = 0; i < args.length; i++) {
        if (PRELOAD.test(args[i])) { i++; continue; }
        if (args[i].startsWith("-")) continue;
        r.need.push(args[i]); break;
      }
    }
    return r;
  }
  if (SHELLS.has(cmd)) {
    const c = args.findIndex((a) => /^-\w*c\w*$/.test(a));
    if (c >= 0) { if (args[c + 1]) r.cmds.push(args[c + 1]); return r; }
    const f = args.find((a) => !a.startsWith("-"));
    if (f) r.need.push({ path: f, shell: true });
    return r;
  }
  if (cmd === "." || cmd === "source") { if (args[0]) r.need.push({ path: args[0], shell: true }); return r; }
  if (PM.has(cmd)) {
    // --prefix/-C/--dir/--cwd <d> anywhere: run the rest as if after `cd <d>`.
    // Only npm's own options: after `--` the arguments belong to the script.
    const ownEnd = args.indexOf("--") >= 0 ? args.indexOf("--") : args.length;
    for (let k = 0; k < ownEnd; k++) {
      const pre = /^(?:--prefix|-C|--dir|--cwd)(?:=(.+))?$/.exec(args[k]);
      if (!pre) continue;
      const to = pre[1] || args[k + 1];
      if (!to) return r;
      const rest = classify([cmd, ...args.slice(0, k), ...args.slice(k + (pre[1] ? 1 : 2))], scripts, depth + 1);
      // Repeated flags: the last one wins (npm/pnpm), which is the one the inner call saw.
      if (rest.moveFor === undefined) rest.moveFor = to;
      return rest;
    }
    let i = 0;
    for (; i < args.length && args[i].startsWith("-"); i++) if (PM_SCOPED.test(args[i])) { r.unknown = `${cmd} ${args[i]}`; return r; }
    const sub = args[i];
    if (!sub) { if (cmd === "yarn") r.installs = true; return r; }
    if (PM_BUILTIN.has(sub)) {
      // Installing a named package (or from a URL/path) pulls in code we can't see here.
      if (/^(?:install|i|add|ci)$/.test(sub) && args.slice(i + 1).some((a) => !a.startsWith("-"))) r.unknown = `${cmd} ${sub} ${args.slice(i + 1).find((a) => !a.startsWith("-"))}`;
      else if (/^(?:install|i|ci|add)$/.test(sub)) r.installs = true;
      return r;
    }
    let name = sub;
    if (sub === "run" || sub === "run-script") { let j = i + 1; while (j < args.length && args[j].startsWith("-")) { if (PM_SCOPED.test(args[j])) { r.unknown = `${cmd} ${args[j]}`; return r; } j++; } name = args[j]; if (!name) return r; }
    else if (cmd === "npm") name = SCRIPT_ALIASES[sub];
    if (!name) return r;
    if (typeof scripts[name] === "string") r.script = name;
    else if (cmd !== "npm" && sub !== "run" && sub !== "run-script") return classify(args.slice(i), scripts, depth + 1);
    else r.unknown = `${cmd} ${sub === "run" ? "run " : ""}${name}`;
    return r;
  }
  if (cmd === "git" && args.some((a) => a === "-c" || a.startsWith("--config"))) { r.unknown = "git -c"; return r; }
  if (/^\.{0,2}\//.test(cmd) || /\.(?:(?:c|m)?[jt]s|sh)$/.test(cmd)) { r.need.push({ path: cmd, shell: /\.sh$/.test(cmd) }); return r; }
  // A tool name the repo itself provides (committed node_modules/.bin, or a local file: package's
  // bin) is repo code wearing a familiar name: read that instead.
  if (LOCAL_BINS.has(cmd)) { r.need.push(LOCAL_BINS.get(cmd)); return r; }
  if (cmd === "node-gyp") { r.exact = ["binding.gyp"]; return r; }
  if (Object.hasOwn(TOOL_CONFIGS, cmd)) { r.configs.push(...TOOL_CONFIGS[cmd]); return r; }
  if (BENIGN.has(cmd)) return r;
  r.unknown = cmd.slice(0, 100);
  return r;
}

function candidates(abs) {
  const c = [abs, abs + ".js", abs + ".cjs", abs + ".mjs", abs + ".ts", abs + ".mts", abs + ".cts"];
  try {
    if (fs.statSync(abs).isDirectory()) {
      const pj = rj(path.join(abs, "package.json"));
      if (pj && typeof pj.main === "string") c.push(path.resolve(abs, pj.main), path.resolve(abs, pj.main) + ".js");
      c.push(path.join(abs, "index.js"));
    }
  } catch {}
  return c;
}

// Read one file named relative to base, never outside dir (symlinks resolved).
// Returns {txt, real}, {seen:true}, or null (flagging truncation on the entry where that's why).
function readCode(e, dir, base, rel, seen) {
  const abs = path.resolve(base, String(rel).replace(/\\/g, "/"));
  if (!inside(dir, abs)) return null;
  for (const c of candidates(abs)) {
    let real, st;
    try { real = fs.realpathSync(c); st = fs.statSync(real); if (!inside(dir, real) || !st.isFile()) continue } catch { continue }
    if (seen.has(real)) return { seen: true };
    if (e.files.length >= L.filesPerPkg) { e.truncated = true; return null }
    seen.add(real);
    if (++reads > L.maxReads) { partial = true; e.truncated = true; return null }
    if (st.size > L.perFile) e.truncated = true;
    const txt = readText(real, L.perFile);
    if (txt === null) return null;
    const f = { path: path.relative(dir, real).slice(0, 500), content: txt };
    const n = jb(f);
    if (bytes + n > L.totalBytes) { partial = true; e.truncated = true; return null }
    bytes += n; e.files.push(f);
    return { txt, real };
  }
  return null;
}

function collect(dir, name, version, hooks, trunc, isRoot, local, scripts, extra) {
  const e = { name, version, root: isRoot, local, hooks, files: [], truncated: trunc, unresolved: [] };
  const hb = jb(e);
  if (bytes + hb > L.hardBytes) { partial = true; return false }
  bytes += hb; out.push(e);
  const seen = new Set(), seenScript = new Set(), files = [];
  let misses = 0;
  const miss = (s) => { if (++misses > 300) { e.truncated = true; return } s = String(s).slice(0, 200); if (e.unresolved.length < 5 && !e.unresolved.includes(s)) e.unresolved.push(s) };
  const cmds = Object.entries(hooks).filter(([k]) => !k.startsWith(".") && k !== "binding.gyp").map(([, c]) => [c, 0, dir, scripts]);
  for (const x of extra.cmds) cmds.push([x, 0, dir, scripts]);
  const seenSub = new Set();
  for (const f of extra.files) files.push([dir, f.path, 0, f.named, !!f.shell]);
  const addScript = (k, d, base, sc) => {
    const key = base + "\u0000" + k;
    if (seenScript.has(key)) return;
    const v = sc[k];
    if (d >= L.scriptDepth || e.files.length >= L.filesPerPkg) { e.truncated = true; return }
    seenScript.add(key);
    if (v.length > L.perCmd) e.truncated = true;
    const rel = path.relative(dir, path.join(base, "package.json")).replace(/\\/g, "/");
    const f = { path: rel + " (scripts." + k.slice(0, 100) + ")", content: v.slice(0, L.perCmd) };
    const n = jb(f);
    if (bytes + n > L.totalBytes) { partial = true; e.truncated = true; return }
    bytes += n; e.files.push(f); cmds.push([v, d + 1, base, sc]);
  };
  const runCmd = (cmd, d, base0, sc0) => {
    if (d > L.scriptDepth + 2) { e.truncated = true; return }
    // Requires inside inline code (node -e "require(\"./x\")"): unescape quotes first.
    for (const r of String(cmd).replace(/\\(["'`])/g, "$1").matchAll(REQ_RE)) files.push([base0, r[1] || r[2] || r[3], 1, false, false]);
    if (/\b(?:node|nodejs|bun|deno|tsx)\b[^\n]{0,200}\s(?:-e|--eval|-p|--print)\s/.test(String(cmd)) && isDynamic(String(cmd).replace(/\\(["'`])/g, "$1"))) miss("dynamic require in inline code");
    const { list, subs } = steps(cmd);
    for (const sub of subs) cmds.push([sub, d + 1, base0, sc0]);
    let base = base0, sc = sc0, lost = false;
    for (const w of list) {
      const k = classify(w, sc);
      if (k.moves) {
        // Follow `cd <dir>` inside the package; anywhere else, later steps are unresolved.
        const to = path.resolve(base, k.moves);
        if (!lost && !k.moves.startsWith("~") && !k.moves.includes("$") && inside(dir, to) && fs.existsSync(to)) {
          base = to; sc = to === dir ? scripts : scriptsOf(rj(path.join(to, "package.json")));
        } else lost = true;
        continue;
      }
      if (k.moveFor) {
        const to = path.resolve(base, k.moveFor);
        if (k.moveFor.includes("$") || !inside(dir, to) || !fs.existsSync(to)) { miss(`${w.join(" ").slice(0, 150)}`); continue }
        if (k.installs && !seenSub.has(to)) { seenSub.add(to); const sp = rj(path.join(to, "package.json")); const [sh2, t2] = hooksOf(sp, CFG.rootHooks); if (t2) e.truncated = true; const subSc = scriptsOf(sp); for (const c of Object.values(sh2)) cmds.push([c, d + 1, to, subSc]) }
        if (k.script) { const subSc = scriptsOf(rj(path.join(to, "package.json"))); if (typeof subSc[k.script] === "string") addScript(k.script, d, to, subSc); else miss(w.join(" ").slice(0, 150)) }
        if (k.unknown) miss(k.unknown);
        continue;
      }
      const where = `cd ${path.relative(dir, base) || "."} && ${w.join(" ").slice(0, 150)}`;
      if (lost) { if (k.need.length || k.script || k.installs || k.cmds.length) miss(where); if (k.unknown) miss(k.unknown); continue }
      for (const n of k.need) {
        const p = typeof n === "string" ? n : n.path, sh = typeof n === "string" ? false : n.shell;
        files.push([base, p, 0, true, sh]);
      }
      for (const c of k.cmds) cmds.push([c, d + 1, base, sc]);
      for (const c of k.configs) for (const ext of [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"]) files.push([base, c + ext, 0, false, false]);
      for (const x of k.exact || []) files.push([base, x, 0, false, false]);
      if (k.script) addScript(k.script, d, base, sc);
      if (k.unknown) miss(k.unknown);
      // Installing in a subfolder runs that package's own hooks: read them too.
      if (k.installs && base !== dir && !seenSub.has(base)) {
        seenSub.add(base);
        const sp = rj(path.join(base, "package.json"));
        const [sh2, t2] = hooksOf(sp, CFG.rootHooks);
        if (t2) e.truncated = true;
        const subSc = scriptsOf(sp);
        for (const c of Object.values(sh2)) cmds.push([c, d + 1, base, subSc]);
      }
    }
  };
  for (;;) {
    if (Date.now() > DEADLINE) { e.truncated = true; partial = true; break }
    while (cmds.length) { const [c, d, b, sc] = cmds.shift(); runCmd(c, d, b || dir, sc || scripts) }
    if (!files.length) break;
    const [base, rel, d, named, shell] = files.shift();
    const got = readCode(e, dir, base, rel, seen);
    if (!got) { if (named) miss(rel); continue }
    if (got.seen) continue;
    const fdir = path.dirname(got.real);
    // A file run by a shell is more commands; a JS file may load more files or spawn commands.
    if (shell) { for (const line of got.txt.split("\n").slice(0, 500)) if (line.trim() && !line.trim().startsWith("#")) cmds.push([line, d + 1, fdir, scripts]); continue }
    if (/\.prisma$/.test(got.real)) {
      for (const m of got.txt.matchAll(/provider\s*=\s*"([^"]{1,200})"/g)) if (/[\s\/\\]/.test(m[1]) || LOCAL_BINS.has(m[1])) miss(`prisma generator ${m[1]}`);
      continue;
    }
    if (/binding\.gyp$/.test(got.real)) { if (/["']action["']\s*:/.test(got.txt)) miss("binding.gyp action"); continue }
    if (named && isDynamic(got.txt)) miss(`dynamic require in ${path.relative(dir, got.real).replace(/\\/g, "/")}`);
    let more = 0;
    for (const r of got.txt.matchAll(REQ_RE)) { if (d >= L.requireDepth) { e.truncated = true; break } files.push([fdir, r[1] || r[2] || r[3], d + 1, false, false]); if (++more > 200) break }
    for (const m of got.txt.matchAll(CHILD_RE)) {
      if (d >= L.requireDepth) { e.truncated = true; break }
      if (m[1] === "fork") files.push([fdir, m[2], d + 1, true, false]);
      else if (/^exec/.test(m[1]) || /\s/.test(m[2])) cmds.push([m[2], d + 1, fdir, scripts]);
      else if (!RUNTIMES.has(m[2]) && !SHELLS.has(m[2])) cmds.push([m[2], d + 1, fdir, scripts]);
    }
  }
  return true;
}

function hooksOf(pkg, list) {
  const s = (pkg && pkg.scripts) || {}, h = {};
  let t = false;
  for (const k of list) if (typeof s[k] === "string" && s[k].trim()) { if (s[k].length > L.perCmd) t = true; h[k] = s[k].slice(0, L.perCmd) }
  return [h, t];
}
const scriptsOf = (pkg) => {
  const s = pkg && pkg.scripts && typeof pkg.scripts === "object" ? pkg.scripts : {};
  return Object.fromEntries(Object.entries(s).filter(([, v]) => typeof v === "string"));
};
const nameOf = (pkg, d) => String((pkg && pkg.name) || d).slice(0, 214), verOf = (pkg) => String((pkg && pkg.version) || "").slice(0, 64);
const cwd = fs.realpathSync(process.cwd());
const LOCAL_BINS = new Map();
if (MODE === "root") {
  try { for (const b of fs.readdirSync(path.join(cwd, "node_modules", ".bin"))) LOCAL_BINS.set(b, path.join(cwd, "node_modules", ".bin", b)) } catch {}
  const rp = rj(path.join(cwd, "package.json")) || {};
  for (const sec of ["dependencies", "devDependencies", "optionalDependencies"]) {
    for (const [name, spec] of Object.entries(rp[sec] || {})) {
      const m = typeof spec === "string" && /^(?:file|link|portal):(.+)$/.exec(spec);
      if (!m) continue;
      const pd = path.resolve(cwd, m[1]);
      const lp = rj(path.join(pd, "package.json"));
      if (!lp) { LOCAL_BINS.set(name.split("/").pop(), path.join(pd, "MISSING")); continue }
      const bin = typeof lp.bin === "string" ? { [String(lp.name || name).split("/").pop()]: lp.bin } : lp.bin && typeof lp.bin === "object" ? lp.bin : {};
      for (const [bn, bp] of Object.entries(bin)) if (typeof bp === "string") LOCAL_BINS.set(bn, path.resolve(pd, bp));
    }
  }
}

// Install-time surfaces besides scripts: config files that make npm/pnpm/yarn run code.
function surfaces(dir, hooks) {
  const extra = { cmds: [], files: [] };
  const npmrc = readText(path.join(dir, ".npmrc"), 16000);
  if (npmrc) {
    const lines = npmrc.split("\n").filter((l) => /^\s*(?:node-options|script-shell)\s*=/.test(l));
    if (lines.length) {
      hooks[".npmrc"] = lines.join("\n").slice(0, L.perCmd);
      for (const l of lines) {
        const v = l.split("=").slice(1).join("=").trim().replace(/^["']|["']$/g, "");
        if (/^\s*node-options/.test(l)) for (const p of preloadsOf(v.split(/\s+/))) extra.files.push({ path: p, named: true });
        else extra.files.push({ path: v, named: true, shell: true });
      }
    }
  }
  for (const f of [".pnpmfile.cjs", ".pnpmfile.js"]) if (fs.existsSync(path.join(dir, f))) { hooks[".pnpmfile.cjs"] = `pnpm loads ${f} on every install, even with --ignore-scripts`; extra.files.push({ path: f, named: true }) }
  const yrc = readText(path.join(dir, ".yarnrc.yml"), 16000) || "";
  const y1 = readText(path.join(dir, ".yarnrc"), 16000) || "";
  const ypaths = [...yrc.matchAll(/^\s*(?:yarnPath|-\s*path)\s*:\s*["']?([^"'\n]{1,300})/gm), ...y1.matchAll(/^\s*yarn-path\s+["']?([^"'\n]{1,300})/gm)].map((m) => m[1].trim());
  if (ypaths.length) { hooks[".yarnrc.yml"] = `yarn runs: ${ypaths.join(", ")}`.slice(0, L.perCmd); for (const p of ypaths) extra.files.push({ path: p, named: true }) }
  if (fs.existsSync(path.join(dir, "binding.gyp")) && !hooks.install && !hooks.preinstall) { hooks["binding.gyp"] = "npm runs node-gyp rebuild for binding.gyp"; extra.files.push({ path: "binding.gyp", named: true }) }
  return extra;
}

try {
if (MODE === "root") {
  const pkg = rj("package.json");
  const committedNm = fs.existsSync(path.join(cwd, "node_modules"));
  const [h, t] = hooksOf(pkg, CFG.rootHooks);
  const extra = surfaces(cwd, h);
  if (fs.existsSync(path.join(cwd, "prisma", "schema.prisma"))) extra.files.push({ path: "prisma/schema.prisma", named: false });
  if (Object.keys(h).length && collect(cwd, nameOf(pkg, "(root)"), verOf(pkg), h, t, true, true, scriptsOf(pkg), extra) && committedNm) {
    const e = out[out.length - 1];
    if (e.unresolved.length < 5) e.unresolved.push("node_modules committed to the repo");
  }
} else {
  // Gather package dirs first (bounded), then visit local packages (inside the repo, outside
  // node_modules) before registry ones, so padding can't push a local one past maxPkgs.
  const seenPkg = new Set([cwd]), dirs = [];
  const add = (d) => { if (dirs.length >= L.maxDirs) { partial = true; return } let real; try { real = fs.realpathSync(d) } catch { return } if (seenPkg.has(real)) return; seenPkg.add(real); dirs.push(real) };
  const walkNm = (nm, depth) => {
    if (depth > 6 || reads > L.maxReads || dirs.length >= L.maxDirs) return;
    let ents; try { ents = fs.readdirSync(nm, { withFileTypes: true }) } catch { return }
    if (++reads > L.maxReads) { partial = true; return }
    for (const x of ents) {
      if (x.name === ".bin") continue;
      if (x.name === ".pnpm") { let st; try { st = fs.readdirSync(path.join(nm, ".pnpm")) } catch { continue } for (const s of st) walkNm(path.join(nm, ".pnpm", s, "node_modules"), depth + 1); continue }
      if (x.name.startsWith("@")) { let sc; try { sc = fs.readdirSync(path.join(nm, x.name)) } catch { continue } for (const s of sc) { add(path.join(nm, x.name, s)); walkNm(path.join(nm, x.name, s, "node_modules"), depth + 1) } continue }
      if (x.name.startsWith(".")) continue;
      add(path.join(nm, x.name)); walkNm(path.join(nm, x.name, "node_modules"), depth + 1);
    }
  };
  walkNm("node_modules", 0);
  const isLocal = (d) => inside(cwd, d) && !d.split(path.sep).includes("node_modules");
  dirs.sort((a, b) => Number(isLocal(b)) - Number(isLocal(a)));
  for (const d of dirs) {
    const pkg = rj(path.join(d, "package.json"));
    if (!pkg) continue;
    const [h, t] = hooksOf(pkg, CFG.depHooks);
    if (!Object.keys(h).length) continue;
    if (out.length >= L.maxPkgs) { partial = true; break }
    if (!collect(d, nameOf(pkg, path.basename(d)), verOf(pkg), h, t, false, isLocal(d), scriptsOf(pkg), { cmds: [], files: [] })) break;
  }
}
} catch {
  // A crash must not erase what was collected: mark it cut (the caller fails closed) and print.
  partial = true;
  if (out.length) out[out.length - 1].truncated = true;
}
process.stdout.write(JSON.stringify({ pkgs: out, partial }));
