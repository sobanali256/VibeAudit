import { z } from "zod";

// `FOO=` in a .env file yields "" — treat that as unset, not as a valid value.
const blankToUndefined = (v: unknown) => (typeof v === "string" && v.trim() === "" ? undefined : v);
const req = <T extends z.ZodType>(schema: T) => z.preprocess(blankToUndefined, schema);
const opt = <T extends z.ZodType>(schema: T) => z.preprocess(blankToUndefined, schema.optional());

const httpUrl = z.url({ protocol: /^https?$/ });

// ssh://user@host[:port] with a plain hostname or IPv4: no path, query or extra options,
// since this string ends up in `docker context create --docker host=...`.
const SSH_HOST_RE =
  /^ssh:\/\/[a-z_][a-z0-9_-]{0,31}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)(?::(?:[1-9]\d{0,4}))?$/;

const Env = z.object({
  DATABASE_URL: req(z.url({ protocol: /^postgres(ql)?$/ })),
  VULTR_INFERENCE_BASE_URL: req(z.url({ protocol: /^https$/ }).default("https://api.vultrinference.com/v1")),
  VULTR_INFERENCE_API_KEY: req(z.string().min(1)),
  PLANNER_MODEL: req(z.string().min(1)),
  VISION_MODEL: opt(z.string().min(1)),
  SANDBOX_DOCKER_HOST: req(
    z
      .string()
      .regex(SSH_HOST_RE, "must be ssh://user@host[:port]")
      .refine((v) => {
        const port = /:(\d+)$/.exec(v.slice("ssh://".length))?.[1];
        return port === undefined || Number(port) <= 65535;
      }, "port out of range"),
  ),
  SANDBOX_PROXY_URL: req(httpUrl),
  GITHUB_TOKEN: opt(z.string().min(1)),
});
export type Config = z.infer<typeof Env>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = Env.safeParse(env);
  if (!parsed.success) {
    // Name the variable and the problem, never echo the value (it may be a secret).
    const problems = parsed.error.issues.map((i) => `${i.path.join(".")} (${i.message})`).join(", ");
    throw new Error(`Invalid worker environment: ${problems}`);
  }
  return parsed.data;
}
