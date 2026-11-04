import { describe, expect, it } from "vitest";
import { loadConfig } from "./config";

const base = {
  DATABASE_URL: "postgres://u:p@localhost:5432/vibeaudit",
  VULTR_INFERENCE_API_KEY: "k",
  PLANNER_MODEL: "glm-5.3",
  SANDBOX_DOCKER_HOST: "ssh://root@10.1.96.3",
  SANDBOX_PROXY_URL: "http://10.1.96.4:8080",
};

describe("loadConfig", () => {
  it("accepts a valid env and applies defaults", () => {
    const c = loadConfig(base);
    expect(c.VULTR_INFERENCE_BASE_URL).toBe("https://api.vultrinference.com/v1");
    expect(c.GITHUB_TOKEN).toBeUndefined();
  });

  it("treats empty strings as unset", () => {
    const c = loadConfig({ ...base, GITHUB_TOKEN: "", VISION_MODEL: "  ", VULTR_INFERENCE_BASE_URL: "" });
    expect(c.GITHUB_TOKEN).toBeUndefined();
    expect(c.VISION_MODEL).toBeUndefined();
    expect(c.VULTR_INFERENCE_BASE_URL).toBe("https://api.vultrinference.com/v1");
    expect(() => loadConfig({ ...base, VULTR_INFERENCE_API_KEY: "" })).toThrow(/VULTR_INFERENCE_API_KEY/);
  });

  it.each(["ssh://root@10.1.96.3:22", "ssh://deploy@vibe-sbx", "ssh://root@sbx.internal"])(
    "accepts docker host %s",
    (h) => expect(loadConfig({ ...base, SANDBOX_DOCKER_HOST: h }).SANDBOX_DOCKER_HOST).toBe(h),
  );

  it.each([
    "ssh://10.1.96.3",
    "ssh://root@10.1.96.3/path",
    "ssh://root@10.1.96.3:99999",
    "ssh://root@-oProxyCommand=x",
    "ssh://root@host -o x",
    "tcp://10.1.96.3:2375",
  ])("rejects docker host %s", (h) => {
    expect(() => loadConfig({ ...base, SANDBOX_DOCKER_HOST: h })).toThrow(/SANDBOX_DOCKER_HOST/);
  });

  it("rejects non-http proxy and non-postgres db urls, without echoing values", () => {
    expect(() => loadConfig({ ...base, SANDBOX_PROXY_URL: "file:///etc/passwd" })).toThrow(/SANDBOX_PROXY_URL/);
    expect(() => loadConfig({ ...base, DATABASE_URL: "mysql://secret@x/y" })).toThrow(
      expect.objectContaining({ message: expect.not.stringContaining("secret") }),
    );
  });
});
