import type { ContainmentEntry } from "@vibeaudit/shared";

/**
 * Plain-language reading of one containment log row: what the code in the sandbox tried, which
 * control stopped it, and the raw evidence. Every field of `e` came from the sandbox side
 * (hosts, paths, reasons) or VM 2's kernel log: it's rendered as text only.
 */
export interface Attempt {
  attempt: string;
  control: string;
  evidence: string;
  tone: "red" | "orange" | "amber";
}

/** Planted canaries are fakes, but mask them like findings do so a report never prints one whole. */
const maskCanary = (s: string) => s.replace(/AKIAVIBE[0-9A-F]{4,}/gi, "AKIAVIBE…");

const METADATA_IPS = new Set(["169.254.169.254", "fd00:ec2::254", "100.100.100.200"]);

export function describeAttempt(e: ContainmentEntry): Attempt | null {
  if (e.source === "proxy") {
    if (e.verdict === "allowed") return null;
    const host = e.host ?? "an external host";
    const target = `${e.method ?? ""} ${e.host ?? ""}${e.path ?? ""}`.trim() || "(unknown)";
    const evidence = maskCanary([target, e.reason, e.repeat ? `×${e.repeat}` : null].filter(Boolean).join(" · "));
    if (e.verdict === "exfil") {
      return {
        attempt: e.keyVar ? `Send the ${e.keyVar} key placeholder to ${host}` : `Smuggle a planted secret out through ${host}`,
        control: "Egress proxy: secret scan",
        evidence,
        tone: "red",
      };
    }
    const r = e.reason ?? "";
    let attempt: string;
    let control = "Egress proxy";
    if (/^host not allowed/.test(r)) {
      attempt = `Contact ${host}`;
      control = "Egress proxy: host allowlist";
    } else if (/^IP-literal/.test(r)) attempt = `Connect straight to an IP address (${host})`;
    else if (/^port \d+ not allowed/.test(r)) attempt = `Connect to ${host} on a non-web port`;
    else if (/^raw TCP/.test(r)) attempt = "Open a raw TCP tunnel through the proxy";
    else if (/^UDP/.test(r)) attempt = "Send UDP traffic through the proxy";
    else if (/Host header/.test(r)) attempt = `Disguise a request to ${host} (domain fronting)`;
    else if (/not allowed in stage/.test(r)) attempt = `${e.method ?? "A request"} to ${host} during ${e.stage ?? "a locked stage"}`;
    else if (/body|encoded/.test(r)) attempt = `Send an uninspectable request body to ${host}`;
    else if (/^\d+ more/.test(r)) attempt = "More blocked requests (not listed one by one)";
    else attempt = `Reach ${host}`;
    return { attempt, control, evidence, tone: "orange" };
  }
  if (e.source === "firewall") {
    const where = `${e.proto} ${e.dst}${e.dport ? `:${e.dport}` : ""}`;
    if (e.direction === "host") {
      const attempt =
        e.dport === 2375 || e.dport === 2376
          ? "Reach the Docker API on the sandbox host"
          : e.dport === 22
            ? "SSH into the sandbox host"
            : `Reach the sandbox host${e.dport ? ` on port ${e.dport}` : ""}`;
      return { attempt, control: "VM 2 firewall: host lock", evidence: where, tone: "red" };
    }
    const attempt = METADATA_IPS.has(e.dst)
      ? "Reach the cloud metadata service (where VM credentials live)"
      : e.dport === 53
        ? `Resolve names directly via ${e.dst}, skipping the proxy`
        : `Connect directly to ${e.dst}${e.dport ? `:${e.dport}` : ""}, skipping the proxy`;
    return { attempt, control: "VM 2 firewall: egress lock", evidence: where, tone: METADATA_IPS.has(e.dst) ? "red" : "orange" };
  }
  const LIMIT: Record<typeof e.limit, string> = {
    pids: "Spawn too many processes",
    memory: "Use too much memory",
    cpu_time: "Use too much CPU",
    stage_timeout: "Run past the stage time limit",
    audit_timeout: "Run past the whole-audit time limit",
    disk: "Fill the disk",
  };
  return { attempt: LIMIT[e.limit], control: "Resource cap", evidence: e.detail, tone: "amber" };
}
