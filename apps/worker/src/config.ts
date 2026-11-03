import { z } from "zod";

const Env = z.object({
  DATABASE_URL: z.string().url(),
  VULTR_INFERENCE_BASE_URL: z.string().url().default("https://api.vultrinference.com/v1"),
  VULTR_INFERENCE_API_KEY: z.string().min(1),
  PLANNER_MODEL: z.string().min(1),
  VISION_MODEL: z.string().optional(),
  SANDBOX_DOCKER_HOST: z.string().startsWith("ssh://"),
  SANDBOX_PROXY_URL: z.string().url(),
  GITHUB_TOKEN: z.string().optional(),
});
export type Config = z.infer<typeof Env>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = Env.safeParse(env);
  if (!parsed.success) {
    const missing = parsed.error.issues.map((i) => i.path.join(".")).join(", ");
    throw new Error(`Invalid worker environment: ${missing}`);
  }
  return parsed.data;
}
