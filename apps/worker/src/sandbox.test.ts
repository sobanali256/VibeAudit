import { describe, expect, it, vi } from "vitest";
import { type DockerExec, type ExecResult, Sandbox } from "./sandbox";

function recorder(result: Partial<ExecResult> = {}) {
  const calls: string[][] = [];
  const exec: DockerExec = vi.fn(async (args: string[]) => {
    calls.push(args);
    return { code: 0, stdout: "", stderr: "", timedOut: false, ...result };
  });
  return { exec, calls };
}
const find = (calls: string[][], verb: string) => calls.find((c) => c[0] === verb);

describe("Sandbox", () => {
  it("rejects a bad audit id", () => {
    expect(() => new Sandbox("bad id", "http://p", recorder().exec)).toThrow();
  });

  it("setup creates a labelled network and a 1000-owned workspace subdir", async () => {
    const { exec, calls } = recorder();
    const sb = new Sandbox("aud1", "http://10.1.96.4:8080", exec);
    await sb.setup();
    const net = find(calls, "network")!;
    expect(net).toEqual(expect.arrayContaining(["network", "create", "--label", "vibeaudit.audit=aud1", "va-aud1"]));
    expect(net).not.toContain("--internal");
    const mk = calls.find((c) => c[0] === "run" && c.join(" ").includes("mkdir"))!;
    expect(mk.join(" ")).toContain("mkdir -p /ws/aud1/app");
    expect(mk).toEqual(expect.arrayContaining(["--runtime=runsc", "--network", "none", "--user", "1000:1000"]));
  });

  it("run() applies every mandatory container flag and the workspace mount for app", async () => {
    const { exec, calls } = recorder();
    const sb = new Sandbox("aud1", "http://10.1.96.4:8080", exec);
    await sb.run({ role: "app", image: "node:22", cmd: ["node", "-v"], timeoutMs: 1000, env: { FOO: "bar" } });
    const run = calls.find((c) => c.includes("node:22"))!;
    for (const f of ["--runtime=runsc", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=1000:1000", "--network=va-aud1", "--label=vibeaudit.audit=aud1", "--memory=3221225472", "--env=HTTPS_PROXY=http://10.1.96.4:8080"]) {
      expect(run).toContain(f);
    }
    expect(run).toContain("--volume=/srv/vibeaudit/ws/aud1:/workspace");
    expect(run).toContain("--env=FOO=bar");
    // image then cmd, in order, at the end
    expect(run.slice(run.indexOf("node:22"))).toEqual(["node:22", "node", "-v"]);
  });

  it("browser role gets no workspace mount and uses -i only with input", async () => {
    const { exec, calls } = recorder();
    const sb = new Sandbox("aud1", "http://p:8080", exec);
    await sb.run({ role: "browser", image: "curlimages/curl", cmd: ["-sS", "x"], timeoutMs: 1000 });
    const run = calls.find((c) => c.includes("curlimages/curl"))!;
    expect(run.some((a) => a.startsWith("--volume=/srv/vibeaudit/ws"))).toBe(false);
    expect(run).toContain("--init");
    expect(run).not.toContain("-i");
  });

  it("run() removes the container when the CLI was killed (timeout or output cap), not otherwise", async () => {
    for (const [result, removed] of [[{ timedOut: true, code: null }, true], [{ truncated: true, code: 1 }, true], [{ code: 1 }, false]] as const) {
      const { exec, calls } = recorder(result);
      const sb = new Sandbox("aud1", "http://p:8080", exec);
      await sb.run({ role: "browser", image: "img", cmd: ["x"], timeoutMs: 1000, maxOutput: 6 * 1024 * 1024, name: "va-aud1-browser" });
      expect(calls.some((c) => c[0] === "rm" && c.includes("va-aud1-browser"))).toBe(removed);
    }
  });

  it("teardown removes containers by label, the network and the workspace", async () => {
    const { exec, calls } = recorder({ stdout: "c1\nc2\n" });
    const sb = new Sandbox("aud1", "http://p:8080", exec);
    await sb.teardown();
    expect(find(calls, "ps")).toEqual(expect.arrayContaining(["--filter", "label=vibeaudit.audit=aud1"]));
    expect(calls.find((c) => c[0] === "rm" && c.includes("c1"))).toEqual(["rm", "-f", "c1", "c2"]);
    expect(find(calls, "network")).toEqual(["network", "rm", "va-aud1"]);
    expect(calls.some((c) => c.join(" ").includes("rm -rf /ws/aud1"))).toBe(true);
  });

  it("teardown runs only once and never throws", async () => {
    const exec: DockerExec = vi.fn(async () => {
      throw new Error("docker down");
    });
    const sb = new Sandbox("aud1", "http://p:8080", exec);
    await expect(sb.teardown()).resolves.toBeUndefined();
    await sb.teardown();
    expect((exec as unknown as ReturnType<typeof vi.fn>).mock.calls.length).toBeGreaterThan(0);
  });

  it("ipOf uses index() for the hyphenated network name", async () => {
    const { exec, calls } = recorder({ stdout: "172.30.0.5\n" });
    await new Sandbox("aud1", "http://p", exec).ipOf("x");
    const inspect = calls.find((c) => c[0] === "inspect")!;
    expect(inspect.join(" ")).toContain('index .NetworkSettings.Networks "va-aud1"');
  });

  it("ipOf validates the returned address", async () => {
    const { exec } = recorder({ stdout: "172.30.0.5\n" });
    expect(await new Sandbox("aud1", "http://p", exec).ipOf("x")).toBe("172.30.0.5");
    const bad = recorder({ stdout: "not-an-ip\n" });
    expect(await new Sandbox("aud1", "http://p", bad.exec).ipOf("x")).toBeNull();
  });
});
