// Report -> PDF (pdfkit, DejaVu fonts). Same content as the Markdown export. Every string from the
// report is untrusted: it is only ever drawn as text (no annotations or links built from it), after
// clean() and a glyph check. Screenshots are JPEG bytes the worker stored (signature-checked); pdfkit
// embeds them without decoding, and a malformed one is skipped.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ContainmentEntry, Evidence, Finding, Report, Severity } from "@vibeaudit/shared";
import PDFDocument from "pdfkit";
import { describeAttempt } from "../../components/audit/attempts";
import { CATEGORY, isAttempt, LH_LABEL, PROOF_LABEL, proofOf } from "../report-model";
import {
  clean,
  EXPORT_LIMITS,
  evidenceShown,
  modeLabel,
  modeSentence,
  partition,
  plantedText,
  receiptRows,
  reportUrl,
  sourceLabel,
  utc,
  verdictText,
} from "./shared";

/** Text budget for one PDF (it's laid out on VM 1's CPU: smaller than the Markdown budget). */
const PDF_BUDGET_CHARS = 150_000;
const yieldToLoop = () => new Promise<void>((r) => setImmediate(r));

/** Rough text size of one finding as drawn (the per-field caps clean() applies). */
function findingChars(f: Finding): number {
  let n = Math.min(f.title.length, L.title) + Math.min(f.description.length, L.body) + Math.min(f.fix?.length ?? 0, L.body) + 200;
  for (const e of evidenceShown(f)) {
    if (e.kind === "code") n += Math.min(e.snippet.length, L.snippet) + e.file.length;
    else if (e.kind === "http") n += Math.min(e.bodyExcerpt?.length ?? 0, L.body) + 600;
    else n += 400;
  }
  return n;
}

/** How many findings of `list` fit in `budget` (decided up front so "Fix these first" can tell). */
function fitCount(list: Finding[], budget: number): [count: number, used: number] {
  if (budget <= 0) return [0, 0];
  let used = 0;
  const max = Math.min(list.length, EXPORT_LIMITS.findings);
  for (let i = 0; i < max; i++) {
    const c = findingChars(list[i]!);
    if (used + c > budget && i > 0) return [i, used];
    used += c;
  }
  return [max, used];
}
const L = EXPORT_LIMITS.text;

const SEV_COLOR: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#a1a1aa",
};
const INK = "#18181b";
const MUTED = "#71717a";
const CODE_INK = "#3f3f46";
const GREEN = "#047857";
const RED = "#b91c1c";

type Doc = InstanceType<typeof PDFDocument>;
interface Fonts {
  sans: Buffer;
  bold: Buffer;
  mono: Buffer;
}

const fontCache = new Map<string, Fonts>();
function loadFonts(dir: string): Fonts {
  let f = fontCache.get(dir);
  if (!f) {
    f = {
      sans: readFileSync(join(dir, "DejaVuSans.ttf")),
      bold: readFileSync(join(dir, "DejaVuSans-Bold.ttf")),
      mono: readFileSync(join(dir, "DejaVuSansMono.ttf")),
    };
    fontCache.set(dir, f);
  }
  return f;
}

export interface PdfOptions {
  origin: string;
  /** Directory holding DejaVuSans.ttf, DejaVuSans-Bold.ttf and DejaVuSansMono.ttf. */
  fontDir: string;
  /** Screenshot bytes by artifact name (only the ones to embed). */
  images?: Map<string, Buffer>;
  now?: Date;
}

export async function reportToPdf(r: Report, opts: PdfOptions): Promise<Buffer> {
  const fonts = loadFonts(opts.fontDir);
  const doc: Doc = new PDFDocument({
    size: "A4",
    margins: { top: 50, bottom: 56, left: 50, right: 50 },
    bufferPages: true,
    // Our own font as the default: pdfkit then never reads its built-in AFM files.
    font: fonts.sans as unknown as string,
    info: { Title: `VibeAudit report: ${clean(sourceLabel(r), 200)}`, Author: "VibeAudit", Creator: "VibeAudit" },
  });
  doc.registerFont("sans", fonts.sans);
  doc.registerFont("bold", fonts.bold);
  doc.registerFont("mono", fonts.mono);

  const chunks: Buffer[] = [];
  const done = new Promise<Buffer>((resolve, reject) => {
    doc.on("data", (c: Buffer) => chunks.push(c));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
  });

  try {
    await new Writer(doc, r, opts).render();
  } finally {
    doc.end();
  }
  return done;
}

class Writer {
  private glyphs = new Map<string, Map<number, boolean>>();
  /** One parsed image per screenshot name (null = failed): pdfkit then embeds each JPEG once. */
  private images = new Map<string, { width: number; height: number } | null>();
  constructor(
    private doc: Doc,
    private r: Report,
    private opts: PdfOptions,
  ) {}

  private get left() {
    return this.doc.page.margins.left;
  }
  private get width() {
    return this.doc.page.width - this.doc.page.margins.left - this.doc.page.margins.right;
  }
  private get bottom() {
    return this.doc.page.height - this.doc.page.margins.bottom;
  }
  /** Start a new page unless `h` points still fit on this one. */
  private room(h: number) {
    if (this.doc.y + h > this.bottom) this.doc.addPage();
  }

  /** clean() plus: characters the font has no glyph for become "?" (DejaVu has no CJK/emoji). */
  private t(s: string | undefined | null, font: "sans" | "bold" | "mono", max: number = L.short): string {
    const text = clean(s, max);
    this.doc.font(font);
    const f = (this.doc as unknown as { _font?: { font?: { hasGlyphForCodePoint?: (c: number) => boolean } } })._font?.font;
    if (!f?.hasGlyphForCodePoint) return text;
    let cache = this.glyphs.get(font);
    if (!cache) this.glyphs.set(font, (cache = new Map()));
    let out = "";
    for (const ch of text) {
      const cp = ch.codePointAt(0)!;
      if (cp === 10 || cp === 9) {
        out += ch;
        continue;
      }
      let ok = cache.get(cp);
      if (ok === undefined) cache.set(cp, (ok = f.hasGlyphForCodePoint(cp)));
      out += ok ? ch : "?";
    }
    return out;
  }

  private text(s: string, font: "sans" | "bold" | "mono", size: number, color = INK, extra: PDFKit.Mixins.TextOptions = {}) {
    this.doc.font(font).fontSize(size).fillColor(color).text(s, this.left, this.doc.y, { width: this.width, ...extra });
  }
  private h2(s: string) {
    this.room(60);
    this.doc.moveDown(0.8);
    this.text(s, "bold", 15);
    this.doc.moveDown(0.3);
  }
  private h3(s: string) {
    this.room(40);
    this.doc.moveDown(0.5);
    this.text(s, "bold", 11);
    this.doc.moveDown(0.2);
  }
  private para(s: string | undefined | null, max: number = L.body, color = INK, size = 9.5) {
    if (!s) return;
    this.text(this.t(s, "sans", max), "sans", size, color, { lineGap: 1.5 });
    this.doc.moveDown(0.4);
  }
  private small(s: string, color = MUTED) {
    this.text(s, "sans", 8, color);
  }
  /** Mono block, indented, for anything copied from the repo/app/sandbox. */
  private block(s: string | undefined | null, max: number = L.snippet) {
    const body = this.t(s, "mono", max).replace(/\n+$/, "");
    if (!body) return;
    this.room(24);
    this.doc
      .font("mono")
      .fontSize(7.5)
      .fillColor(CODE_INK)
      .text(body, this.left + 10, this.doc.y, { width: this.width - 10, lineGap: 0.5 });
    this.doc.moveDown(0.5);
  }

  /** Severity tag + title on one line (the title wraps beside the tag). */
  private findingHead(f: Finding, label: string) {
    this.room(48);
    this.doc.moveDown(0.6);
    const sev = f.severity.toUpperCase();
    const doc = this.doc;
    doc.font("bold").fontSize(7.5);
    const tagW = doc.widthOfString(sev) + 8;
    const y = doc.y;
    doc.rect(this.left, y, tagW, 12).fill(SEV_COLOR[f.severity] ?? MUTED);
    doc.fillColor(f.severity === "medium" || f.severity === "low" || f.severity === "info" ? INK : "#ffffff").text(sev, this.left + 4, y + 2.5, {
      lineBreak: false,
    });
    doc
      .font("bold")
      .fontSize(10.5)
      .fillColor(INK)
      .text(`${label}. ${this.t(f.title, "bold", L.title)}`, this.left + tagW + 6, y, { width: this.width - tagW - 6 });
    doc.moveDown(0.15);
  }

  private evidence(e: Evidence, n: number) {
    const label = (s: string) => {
      this.room(30);
      this.text(s, "bold", 8.5, MUTED);
      this.doc.moveDown(0.15);
    };
    switch (e.kind) {
      case "code":
        label(`Evidence ${n}: code in ${this.t(`${e.file}${e.line ? `:${e.line}` : ""}`, "bold", 300)}`);
        this.block(e.snippet);
        return;
      case "http": {
        label(`Evidence ${n}: HTTP request against the running app`);
        const lines: string[] = [`${e.method} ${e.url}  ->  ${e.status}`];
        for (const h of e.request?.headers ?? []) lines.push(`sent ${h}`);
        if (e.request?.body) lines.push(`sent body ${e.request.body}`);
        if (e.headers) for (const [k, v] of Object.entries(e.headers)) lines.push(`${k}: ${v}`);
        if (e.bodyExcerpt) lines.push("", clean(e.bodyExcerpt, L.body));
        this.block(lines.join("\n"));
        return;
      }
      case "bundle":
        label(
          `Evidence ${n}: client bundle ${this.t(e.asset, "bold", 200)}${/AKIAVIBE/.test(e.match) ? " contains a planted canary secret (masked here)" : ""}`,
        );
        this.block(e.match, L.short);
        return;
      case "network":
        label(`Evidence ${n}: connection stopped by the ${e.control === "firewall" ? "firewall" : "egress proxy"} (${this.t(e.stage ?? "unknown stage", "bold", 40)}, ${utc(e.at)})`);
        this.block([e.target, e.detail].filter(Boolean).join("\n"), L.short);
        return;
      case "screenshot": {
        label(`Evidence ${n}: screenshot`);
        this.image(e.path);
        if (e.verdict) this.para(verdictText(e.verdict), L.short, CODE_INK, 8.5);
        return;
      }
      default:
        label(`Evidence ${n}: unknown kind (newer report format; see the live report)`);
    }
  }

  private image(name: string | undefined, maxW = 360, maxH = 230) {
    const buf = name ? this.opts.images?.get(name) : undefined;
    if (!buf) {
      this.small("(screenshot not embedded; see the live report)");
      this.doc.moveDown(0.3);
      return;
    }
    // openImage parses only the JPEG header (it throws on a malformed one). Reusing the object
    // makes pdfkit embed the bytes once however often the screenshot is referenced.
    let img = this.images.get(name!);
    if (img === undefined) {
      try {
        img = (this.doc as unknown as { openImage(b: Buffer): { width: number; height: number } }).openImage(buf);
        if (!(img.width > 0 && img.height > 0)) img = null;
      } catch {
        img = null;
      }
      this.images.set(name!, img);
    }
    if (!img) {
      this.small("(screenshot could not be embedded)");
      return;
    }
    this.room(maxH + 10);
    const y = this.doc.y;
    try {
      const k = Math.min(maxW / img.width, maxH / img.height, 1);
      const w = img.width * k;
      const h = img.height * k;
      this.doc.image(img as unknown as Buffer, this.left + 10, y, { width: w, height: h });
      this.doc.rect(this.left + 10, y, w, h).lineWidth(0.5).strokeColor("#d4d4d8").stroke();
      this.doc.y = y + h + 6;
    } catch {
      this.doc.y = y;
      this.small("(screenshot could not be embedded)");
    }
    this.doc.x = this.left;
  }

  private finding(f: Finding, label: string) {
    const proof = proofOf(f);
    this.findingHead(f, label);
    this.small(`ID ${this.t(f.id, "sans", 80)} · ${CATEGORY[f.category] ?? this.t(f.category, "sans", 40)} · ${PROOF_LABEL[proof]} · found by ${this.t(f.source, "sans", 40)}`, proof === "runtime" ? GREEN : MUTED);
    this.doc.moveDown(0.3);
    if (f.corroboratedBy?.length) {
      const refs = f.corroboratedBy.map((c) => `"${c.title}"${c.file ? ` (${c.file}${c.line ? `:${c.line}` : ""})` : ""}`).join(", ");
      this.para(`The LLM code review reported this independently${proof === "runtime" ? ", before the sandbox proved it" : ""}: ${refs}.`, L.body, "#6d28d9", 8.5);
    }
    this.para(f.description);
    const ev = evidenceShown(f);
    ev.forEach((e, i) => this.evidence(e, i + 1));
    if (f.evidence.length > ev.length) this.small(`(${f.evidence.length - ev.length} more evidence items in the live report.)`);
    if (f.fix) {
      this.room(24);
      this.doc.font("bold").fontSize(9.5).fillColor(INK).text("Fix: ", this.left, this.doc.y, { continued: true, width: this.width });
      this.doc.font("sans").text(this.t(f.fix, "sans", L.body), { lineGap: 1.5 });
      // `continued` switched fonts mid-line; make sure later calls start from the font we expect.
      this.doc.font("sans");
      this.doc.moveDown(0.4);
    }
  }

  private async findings(list: Finding[], prefix: string, count: number) {
    for (let i = 0; i < count; i++) {
      this.finding(list[i]!, `${prefix}${i + 1}`);
      if (i % 10 === 9) await yieldToLoop(); // don't hold the event loop (SSE streams) for a long render
    }
    if (list.length > count) this.para(`(${list.length - count} more not included: the export reached its size limit. See the live report.)`, 300, MUTED);
  }

  async render() {
    const { r, doc } = this;
    const { app, deps, hostile, counts } = partition(r);
    const live = reportUrl(this.opts.origin, r.auditId);

    // Header
    this.text("VibeAudit report", "bold", 9, MUTED);
    this.text(this.t(sourceLabel(r), "bold", L.title), "bold", 18);
    doc.moveDown(0.4);
    const s = Math.round(r.score);
    const y = doc.y;
    doc.font("bold").fontSize(34).fillColor(s >= 80 ? "#059669" : s >= 50 ? "#d97706" : RED).text(String(s), this.left, y, { lineBreak: false });
    const sw = doc.widthOfString(String(s));
    doc.font("sans").fontSize(10).fillColor(MUTED).text("/ 100", this.left + sw + 4, y + 22, { lineBreak: false });
    doc.font("bold").fontSize(11).fillColor(INK).text(modeLabel(r), this.left + sw + 50, y + 2, { width: this.width - sw - 50 });
    doc.font("sans").fontSize(8.5).fillColor(MUTED).text(`Finished ${utc(r.finishedAt)} · audit ${this.t(r.auditId, "sans", 80)}`, { width: this.width - sw - 50 });
    doc.fillColor("#2563eb").text(live, { link: live, underline: true, width: this.width - sw - 50 });
    doc.y = Math.max(doc.y, y + 44);
    doc.x = this.left;
    doc.moveDown(0.6);

    this.para(modeSentence(r));
    this.para(
      counts.length
        ? `Findings by severity: ${counts.map(([sv, n]) => `${n} ${sv}`).join(", ")}${deps.length ? ` (incl. ${deps.length} dependency advisor${deps.length === 1 ? "y" : "ies"})` : ""}.`
        : "No findings.",
    );
    const proven = app.filter((f) => proofOf(f) === "runtime").length;
    const attempts = r.containment.filter(isAttempt).length;
    this.para(
      `${proven} proven at runtime · ${app.length - proven} other app findings · ${attempts} attempt${attempts === 1 ? "" : "s"} stopped by the sandbox${r.pages?.length ? ` · ${r.pages.length} pages visited logged out` : ""}.`,
    );

    if (hostile.length) {
      this.room(70);
      doc.moveDown(0.3);
      this.text("Malicious install-time behaviour", "bold", 12, RED);
      this.para(
        `This project, or a package it installs, does something hostile when it is installed. Don't run npm install on it outside a sandbox${hostile.some((f) => f.severity === "critical") ? ", and the score is capped at 40 whatever else the audit found" : ""}.`,
        L.body,
        RED,
      );
      for (const f of hostile.slice(0, 20)) this.para(`•  ${f.title}`, L.title, RED);
      if (hostile.length > 20) this.small(`(${hostile.length - 20} more in the live report.)`, RED);
    }

    const [appCount, appUsed] = fitCount(app, PDF_BUDGET_CHARS);
    const [depCount] = fitCount(deps, Math.max(0, PDF_BUDGET_CHARS - appUsed));
    const top = app
      .slice(0, EXPORT_LIMITS.findings)
      .map((f, i) => [f, i + 1] as const)
      .filter(([f]) => f.severity === "critical" || f.severity === "high")
      .slice(0, 100);
    this.h2("Fix these first");
    if (!top.length) this.para("Nothing critical or high was found in the app itself.", 200, GREEN);
    for (const [f, n] of top)
      this.para(`${f.severity.toUpperCase()} · ${f.title}  (${n <= appCount ? `finding ${n}` : "only in the live report"}, ${PROOF_LABEL[proofOf(f)].toLowerCase()})`, L.title);

    this.h2("Findings");
    if (!app.length) this.para("No findings in the app itself.", 200, GREEN);
    await this.findings(app, "", appCount);

    if (deps.length) {
      this.h2("Dependencies");
      this.para(
        `${deps.length} package${deps.length === 1 ? "" : "s"} with known vulnerabilities, from OSV.dev advisories for the installed versions. They count at half weight, and at most 30 points together.`,
      );
      await this.findings(deps, "D", depCount);
    }

    await yieldToLoop();
    this.sandbox();

    if (r.pages?.length) {
      this.h2("Pages visited (logged out)");
      for (const p of r.pages.slice(0, EXPORT_LIMITS.pages)) {
        this.room(40);
        const landed = p.finalPath === null ? "left the app" : p.finalPath;
        this.text(this.t(`${p.path}   ${p.status || "no response"}${landed !== p.path ? `   -> ${landed}` : ""}`, "mono", 300), "mono", 8.5);
        if (p.title) this.small(this.t(p.title, "sans", 120));
        if (p.screenshot) this.image(p.screenshot, 300, 190);
        if (p.verdict) this.para(verdictText(p.verdict), 300, CODE_INK, 8.5);
        doc.moveDown(0.3);
      }
    }

    if (r.lighthouse) {
      const lh = r.lighthouse;
      this.h2("Lighthouse");
      this.para(Object.entries(lh.scores).map(([k, v]) => `${LH_LABEL[k] ?? k} ${Math.round(v)}`).join("  ·  "));
      const m = lh.metrics;
      const metrics = [m.lcpMs !== undefined ? `LCP ${Math.round(m.lcpMs)} ms` : null, m.cls !== undefined ? `CLS ${m.cls.toFixed(3)}` : null, m.tbtMs !== undefined ? `TBT ${Math.round(m.tbtMs)} ms` : null].filter(Boolean);
      if (metrics.length) this.para(metrics.join("  ·  "), 200, MUTED);
    }

    doc.moveDown(1);
    this.small(`Exported from VibeAudit on ${utc((this.opts.now ?? new Date()).toISOString())}. The live report also has the page replay, the attack console and the full activity log.`);

    this.footers();
  }

  private sandbox() {
    const { r } = this;
    this.h2("Sandbox");
    if (r.controls) {
      this.para(
        "Isolation the app container actually ran under, read back from the sandbox host's Docker daemon. Outside the container, the sandbox VM's firewall drops every packet except those to the egress proxy.",
        L.body,
        MUTED,
        8.5,
      );
      for (const [ok, label, value] of receiptRows(r.controls)) {
        this.room(14);
        this.doc
          .font("bold")
          .fontSize(8.5)
          .fillColor(ok ? GREEN : RED)
          .text(ok ? "✓  " : "✗  NOT APPLIED: ", this.left, this.doc.y, { continued: true, width: this.width });
        this.doc.fillColor(INK).text(`${label}  `, { continued: true });
        this.doc.font("mono").fillColor(MUTED).text(this.t(value, "mono", 300));
      }
      this.doc.font("sans");
      this.doc.moveDown(0.3);
      this.para(`Env: ${plantedText(r.controls)}`, L.short, MUTED, 8.5);
    }
    const flagged = r.containment.filter(isAttempt);
    const allowed = r.containment.filter((e): e is Extract<ContainmentEntry, { source: "proxy" }> => e.source === "proxy" && e.verdict === "allowed");
    if (!r.containment.length) this.para("The sandbox made no network requests and hit no limits.");
    else if (!flagged.length) this.para("Nothing was blocked: every request went to an allowed host.");
    else {
      this.h3("What the code tried, and what stopped it");
      for (const e of flagged.slice(0, EXPORT_LIMITS.containmentRows)) {
        const a = describeAttempt(e);
        if (!a) continue;
        this.room(36);
        this.text(this.t(a.attempt, "bold", L.title), "bold", 9, a.tone === "red" ? RED : INK);
        this.small(`✓ Stopped by ${this.t(a.control, "sans", 80)} · ${this.t(e.stage ?? "-", "sans", 40)} · ${utc(e.at)}`, GREEN);
        this.block(a.evidence, L.title);
      }
      if (flagged.length > EXPORT_LIMITS.containmentRows) this.small(`(${flagged.length - EXPORT_LIMITS.containmentRows} more rows in the live report.)`);
    }
    if (allowed.length) {
      this.h3("Allowed traffic by stage and host");
      this.block(
        allowed
          .slice(0, EXPORT_LIMITS.allowedRows)
          .map((e) => `${e.stage ?? "-"}  ${`${e.method ?? ""} ${e.host ?? ""}`.trim()}${e.keyVar ? ` (test key ${e.keyVar} swapped in)` : ""} x${e.repeat ?? 1}${(e.repeat ?? 1) > 20 ? "+" : ""}`)
          .join("\n") + (allowed.length > EXPORT_LIMITS.allowedRows ? `\n(${allowed.length - EXPORT_LIMITS.allowedRows} more in the live report.)` : ""),
        20_000,
      );
    }
  }

  private footers() {
    const { doc } = this;
    const range = doc.bufferedPageRange();
    const id = this.t(this.r.auditId, "sans", 80);
    for (let i = range.start; i < range.start + range.count; i++) {
      doc.switchToPage(i);
      const bottom = doc.page.margins.bottom;
      // Writing below the bottom margin would add a page: lift the margin while drawing the footer.
      doc.page.margins.bottom = 0;
      doc
        .font("sans")
        .fontSize(7.5)
        .fillColor(MUTED)
        .text(`VibeAudit · audit ${id} · page ${i - range.start + 1} of ${range.count}`, this.left, doc.page.height - 34, {
          width: this.width,
          align: "center",
          lineBreak: false,
        });
      doc.page.margins.bottom = bottom;
    }
  }
}
