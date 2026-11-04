// Leaf module with no dependencies (no zod), so client components can import the stage
// list without pulling the schemas into the browser bundle (@vibeaudit/shared/stages).

/** Pipeline stages, in order. The proxy allowlist is keyed on these too. */
export const AUDIT_STAGES = [
  "intake",
  "plan",
  "approve",
  "static",
  "install",
  "build",
  "run",
  "dynamic",
  "verify",
  "report",
] as const;
