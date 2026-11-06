import { describe, expect, it } from "vitest";
import { parseInspectControls } from "./controls";

const inspect = {
  Config: { User: "1000:1000", Env: ["HTTP_PROXY=http://10.1.96.4:8080", "HTTPS_PROXY=http://10.1.96.4:8080", "OPENAI_API_KEY=AKIAVIBEXYZ"] },
  HostConfig: {
    Runtime: "runsc",
    Privileged: false,
    CapDrop: ["ALL"],
    CapAdd: null,
    SecurityOpt: ["no-new-privileges"],
    PidsLimit: 1024,
    Memory: 3221225472,
    NanoCpus: 1500000000,
    NetworkMode: "va-abc",
  },
  Mounts: [
    { Type: "bind", Source: "/opt/vibeaudit/proxy-ca-cert.pem", Destination: "/etc/vibeaudit/proxy-ca.pem", RW: false },
    { Type: "bind", Source: "/srv/vibeaudit/ws/abc", Destination: "/workspace", RW: true },
  ],
};

describe("parseInspectControls", () => {
  it("reads the isolation dockerd applied, without env values or host paths", () => {
    const c = parseInspectControls(inspect, { canaries: 3, placeholders: 0 })!;
    expect(c).toMatchObject({
      runtime: "runsc",
      user: "1000:1000",
      privileged: false,
      capDrop: ["ALL"],
      capAdd: [],
      noNewPrivileges: true,
      pidsLimit: 1024,
      memoryBytes: 3221225472,
      cpus: 1.5,
      network: "va-abc",
      egressProxy: true,
      planted: { canaries: 3, placeholders: 0 },
    });
    expect(c.mounts).toEqual([
      { destination: "/etc/vibeaudit/proxy-ca.pem", rw: false },
      { destination: "/workspace", rw: true },
    ]);
    expect(JSON.stringify(c)).not.toContain("AKIAVIBE");
    expect(JSON.stringify(c)).not.toContain("/srv/vibeaudit");
  });

  it("reports weak settings as they are (runc, root, no pids cap)", () => {
    const c = parseInspectControls({ Config: { Env: [] }, HostConfig: { CapDrop: [], SecurityOpt: [], PidsLimit: 0, Memory: 0 } }, { canaries: 0, placeholders: 0 })!;
    expect(c).toMatchObject({ runtime: "runc", user: "root", noNewPrivileges: false, pidsLimit: null, memoryBytes: 0, egressProxy: false });
  });

  it("returns null for garbage", () => {
    expect(parseInspectControls(null, { canaries: 0, placeholders: 0 })).toBeNull();
    expect(parseInspectControls({ Config: {} }, { canaries: 0, placeholders: 0 })).toBeNull();
    expect(parseInspectControls("x", { canaries: 0, placeholders: 0 })).toBeNull();
  });
});
