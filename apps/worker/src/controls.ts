import { SandboxControls } from "@vibeaudit/shared";

/**
 * Turn `docker inspect` output for the app container into the report's isolation receipt.
 * Only config fields are read (dockerd sets them from the worker's flags; the app can't change
 * them). Env VALUES are never copied: only whether the proxy vars are present. Returns null if
 * the shape is unexpected rather than reporting a half-read receipt.
 */
export function parseInspectControls(raw: unknown, planted: { canaries: number; placeholders: number }): SandboxControls | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const hc = obj(r.HostConfig);
  const cfg = obj(r.Config);
  if (!hc || !cfg) return null;
  const env = Array.isArray(cfg.Env) ? cfg.Env.filter((e): e is string => typeof e === "string") : [];
  const envNames = new Set(env.map((e) => e.split("=", 1)[0]));
  const secOpt = strs(hc.SecurityOpt);
  const mounts = Array.isArray(r.Mounts)
    ? r.Mounts.flatMap((m) => {
        const o = obj(m);
        return o && typeof o.Destination === "string" ? [{ destination: o.Destination.slice(0, 200), rw: o.RW === true }] : [];
      }).slice(0, 20)
    : [];
  const candidate = {
    runtime: str(hc.Runtime) || "runc",
    user: str(cfg.User) || "root",
    privileged: hc.Privileged === true,
    capDrop: strs(hc.CapDrop).slice(0, 50),
    capAdd: strs(hc.CapAdd).slice(0, 50),
    noNewPrivileges: secOpt.some((s) => /^no-new-privileges(?:[:=]true)?$/.test(s)),
    pidsLimit: typeof hc.PidsLimit === "number" && hc.PidsLimit > 0 ? hc.PidsLimit : null,
    memoryBytes: typeof hc.Memory === "number" && hc.Memory > 0 ? hc.Memory : 0,
    cpus: typeof hc.NanoCpus === "number" && hc.NanoCpus > 0 ? hc.NanoCpus / 1e9 : 0,
    network: typeof hc.NetworkMode === "string" ? hc.NetworkMode.slice(0, 80) : "",
    mounts,
    egressProxy: envNames.has("HTTPS_PROXY") && envNames.has("HTTP_PROXY"),
    planted,
  };
  const parsed = SandboxControls.safeParse(candidate);
  return parsed.success ? parsed.data : null;
}

const obj = (v: unknown): Record<string, unknown> | null => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null);
const str = (v: unknown): string => (typeof v === "string" ? v.slice(0, 40) : "");
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((s): s is string => typeof s === "string").map((s) => s.slice(0, 40)) : []);
