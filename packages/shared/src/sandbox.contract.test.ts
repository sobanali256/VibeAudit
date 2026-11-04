// Contract test: the worker-side schema must agree with the deployed egress proxy.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { AUDIT_STAGES } from "./audit";
import { AUDIT_ID_RE, ENV_VAR_RE, HEADER_NAME_RE, HOST_RE, KEY_STAGES, SECRET_VALUE_RE } from "./ids";

const py = readFileSync(
  fileURLToPath(new URL("../../../infra/cp/proxy/vibeaudit_proxy.py", import.meta.url)),
  "utf8",
);

function pyRegex(name: string): string {
  const m = new RegExp(`^${name} = re\\.compile\\(r"(.*)"\\)$`, "m").exec(py);
  if (!m) throw new Error(`${name} not found in proxy`);
  return m[1]!;
}
function pySet(name: string): string[] {
  const m = new RegExp(`^${name} = \\{([^}]*)\\}`, "m").exec(py);
  if (!m) throw new Error(`${name} not found in proxy`);
  return [...m[1]!.matchAll(/"([^"]+)"/g)].map((x) => x[1]!).sort();
}

describe("proxy contract", () => {
  it.each([
    ["AUDIT_ID_RE", AUDIT_ID_RE],
    ["VAR_RE", ENV_VAR_RE],
    ["HOST_RE", HOST_RE],
    ["HEADER_RE", HEADER_NAME_RE],
    ["SECRET_VALUE_RE", SECRET_VALUE_RE],
  ])("%s is identical", (pyName, re) => {
    expect(pyRegex(pyName)).toBe(re.source);
  });

  it("uses the same placeholder format", () => {
    expect(py).toContain('f"sk-PLACEHOLDER-{var}-{audit_id}"');
  });

  it("agrees on which stages may use keys", () => {
    expect(pySet("KEY_STAGES")).toEqual([...KEY_STAGES].sort());
  });

  it("only names stages that exist", () => {
    const m = /^STAGE_HOSTS: dict\[str, set\[str\]\] = \{([\s\S]*?)^\}/m.exec(py);
    expect(m).not.toBeNull();
    const stages = [...m![1]!.matchAll(/^\s+"([a-z]+)":/gm)].map((x) => x[1]!);
    expect(stages.length).toBeGreaterThan(0);
    for (const s of stages) expect(AUDIT_STAGES).toContain(s);
  });

  it("uses fullmatch for state validation (no trailing-newline acceptance)", () => {
    const parse = py.slice(py.indexOf("def _parse_state"), py.indexOf("class VibeAuditProxy"));
    expect(parse).not.toMatch(/_RE\.match\(/);
  });
});
