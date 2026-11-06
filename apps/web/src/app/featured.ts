/**
 * Finished audits shown on the landing page, so a visitor sees a full report in one click
 * instead of waiting for a fresh run. Ids of real, completed audits on the live instance; a
 * missing or unfinished one is simply not shown.
 */
export interface Featured {
  id: string;
  repo: string;
  blurb: string;
}

export const FEATURED: Featured[] = [
  {
    id: "rmrzni2qqpflmgvosg34",
    repo: "sobanali256/demo-vulnerable",
    blurb: "A notes app with every classic AI-generated hole, most of them proven by attacking the running app.",
  },
  {
    id: "yzbiidz2nuojh4ovxqr5",
    repo: "sobanali256/demo-malicious",
    blurb: "A harmless-looking weather app whose install script attacks the sandbox. See which control stopped each move.",
  },
  {
    id: "7t2aw5hgajppunojwwbl",
    repo: "julykim777/my-ai-chatbot",
    blurb: "A real public Express chatbot. Its OpenAI proxy is open to anyone, proven with a live request.",
  },
  {
    id: "vgyawa325gxxkbbphbzr",
    repo: "Ksdeng1559/Commercialkonnect",
    blurb: "A real public Next.js 15 + Clerk app. Built and run in the sandbox; nothing critical found.",
  },
];

/** Demo repos the landing page can audit in one click. */
export const DEMO_REPOS = [
  { url: "https://github.com/sobanali256/demo-malicious", label: "demo-malicious", hint: "hostile installer: untick ignore-scripts" },
  { url: "https://github.com/sobanali256/demo-vulnerable", label: "demo-vulnerable", hint: "insecure app" },
];
