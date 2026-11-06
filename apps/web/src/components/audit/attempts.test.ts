import { describe, expect, it } from "vitest";
import { describeAttempt } from "./attempts";

const at = "2026-11-06T10:00:00.000Z";

describe("describeAttempt", () => {
  it("names the attack and the control for each demo-malicious move", () => {
    expect(describeAttempt({ source: "proxy", at, stage: "install", verdict: "exfil", method: "GET", host: "registry.npmjs.org", path: "/-/v1/search", reason: "canary secret in outbound request" })).toMatchObject({
      attempt: "Smuggle a planted secret out through registry.npmjs.org",
      control: "Egress proxy: secret scan",
      tone: "red",
    });
    expect(describeAttempt({ source: "firewall", at, stage: "install", direction: "egress", proto: "tcp", dst: "169.254.169.254", dport: 80 })?.attempt).toMatch(/cloud metadata/);
    expect(describeAttempt({ source: "firewall", at, stage: "install", direction: "egress", proto: "tcp", dst: "192.0.2.1", dport: 443 })).toMatchObject({
      attempt: "Connect directly to 192.0.2.1:443, skipping the proxy",
      control: "VM 2 firewall: egress lock",
    });
    expect(describeAttempt({ source: "firewall", at, stage: "install", direction: "host", proto: "tcp", dst: "172.30.0.1", dport: 2375 })).toMatchObject({
      attempt: "Reach the Docker API on the sandbox host",
      control: "VM 2 firewall: host lock",
    });
    expect(describeAttempt({ source: "firewall", at, stage: "install", direction: "host", proto: "tcp", dst: "172.30.0.1", dport: 22 })?.attempt).toBe("SSH into the sandbox host");
  });

  it("reads proxy block reasons and limits", () => {
    expect(describeAttempt({ source: "proxy", at, stage: "run", verdict: "blocked", method: "CONNECT", host: "api.openai.com:443", reason: "host not allowed in stage run" })).toMatchObject({
      attempt: "Contact api.openai.com:443",
      control: "Egress proxy: host allowlist",
    });
    expect(describeAttempt({ source: "proxy", at, stage: "install", verdict: "blocked", reason: "raw TCP not allowed" })?.attempt).toMatch(/raw TCP/);
    expect(describeAttempt({ source: "limit", at, stage: "build", limit: "stage_timeout", detail: "build exceeded 600s" })).toMatchObject({ control: "Resource cap", evidence: "build exceeded 600s" });
    expect(describeAttempt({ source: "proxy", at, stage: "install", verdict: "allowed", host: "registry.npmjs.org" })).toBeNull();
  });
});

describe("canary masking", () => {
  it("never prints a planted canary whole", () => {
    const a = describeAttempt({ source: "proxy", at, stage: "install", verdict: "exfil", method: "GET", host: "registry.npmjs.org", path: "/-/v1/search?size=1&text=AKIAVIBE0123456789ABCDEF01", reason: "canary secret in outbound request" })!;
    expect(a.evidence).toContain("AKIAVIBE…");
    expect(a.evidence).not.toContain("0123456789ABCDEF");
  });
});
