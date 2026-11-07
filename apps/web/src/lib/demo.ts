import "server-only";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ARTIFACT_NAME_RE } from "./report-model";
import type { AuditEventView, AuditView } from "./view";
import vulnEvents from "../../demo-data/dednztomddj2xfgtr5c2/events.json";
import vulnView from "../../demo-data/dednztomddj2xfgtr5c2/view.json";
import malEvents from "../../demo-data/xgiengqylqdrxpzbxj2n/events.json";
import malView from "../../demo-data/xgiengqylqdrxpzbxj2n/view.json";

/**
 * Read-only demo (VIBEAUDIT_DEMO=1): the site serves a fixed set of finished audits, snapshotted
 * from the live instance with scripts/demo-snapshot.mjs, and needs no database, worker or sandbox.
 * Starting or approving an audit answers 503. Screenshots are static files under public/demo/.
 */
export const DEMO = process.env.VIBEAUDIT_DEMO === "1";

export const DEMO_MESSAGE =
  "This is a read-only demo of VibeAudit. Live audits need the two sandbox VMs, which are offline; the reports below are real results from the live run.";

const DATA: Record<string, { view: AuditView; events: AuditEventView[] }> = {
  dednztomddj2xfgtr5c2: { view: vulnView as unknown as AuditView, events: vulnEvents as AuditEventView[] },
  xgiengqylqdrxpzbxj2n: { view: malView as unknown as AuditView, events: malEvents as AuditEventView[] },
};

const own = (id: string) => Object.prototype.hasOwnProperty.call(DATA, id);

export function demoView(id: string): AuditView | null {
  return own(id) ? { ...DATA[id]!.view, isOwner: false } : null;
}

export function demoEvents(id: string): AuditEventView[] {
  return own(id) ? DATA[id]!.events : [];
}

/** Public path of a snapshotted screenshot, or null for anything else. */
export function demoArtifactPath(id: string, name: string): string | null {
  return own(id) && ARTIFACT_NAME_RE.test(name) ? `/demo/${id}/${name}` : null;
}

/** Screenshot bytes for the PDF export, read from public/demo/ (null when missing). */
export async function demoArtifactBytes(id: string, name: string): Promise<Buffer | null> {
  if (!demoArtifactPath(id, name)) return null;
  return readFile(join(process.cwd(), "public", "demo", id, name)).catch(() => null);
}
