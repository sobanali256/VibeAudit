export interface GitHubRepoRef {
  owner: string;
  repo: string;
  /**
   * Branch, tag or commit SHA when the URL names one (`/tree/<ref>`, `/blob/<ref>`,
   * `/commit/<sha>`). This is the FIRST path segment after the keyword: GitHub URLs
   * can't tell `tree/feature/x` (branch "feature/x") from `tree/feature/x` (branch
   * "feature", dir "x"), so intake must try longer candidates via `refCandidates`
   * against the branches API when this ref doesn't resolve.
   */
  ref?: string;
  /** Remaining path after `ref`, e.g. `src/app` in `/tree/main/src/app`. */
  subpath?: string;
}

/**
 * Every possible split of `ref` + `subpath` into a ref, longest first, e.g.
 * `feature/x/src` → `["feature/x/src", "feature/x", "feature"]`.
 */
export function refCandidates(r: GitHubRepoRef): string[] {
  if (!r.ref) return [];
  const parts = [r.ref, ...(r.subpath ? r.subpath.split("/") : [])];
  const out: string[] = [];
  for (let n = parts.length; n >= 1; n--) out.push(parts.slice(0, n).join("/"));
  return out;
}

// GitHub rules: owner is 1-39 alphanumerics or single hyphens; repo is [A-Za-z0-9._-]{1,100}.
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
// Conservative ref charset. It's interpolated into an API path, so no `..`, spaces or control chars.
const REF_RE = /^[A-Za-z0-9._\/-]{1,200}$/;

/**
 * Parse a user-supplied GitHub repo URL. Returns null for anything that isn't
 * unambiguously a github.com repository. The result is safe to interpolate into
 * `https://api.github.com/repos/{owner}/{repo}/tarball/{ref}`.
 *
 * Accepts: https://github.com/o/r, .git suffix, trailing slash, /tree/<ref>,
 * www.github.com, git@github.com:o/r.git, bare github.com/o/r.
 */
export function parseGitHubUrl(input: string): GitHubRepoRef | null {
  const raw = input.trim();
  if (!raw || raw.length > 500) return null;
  // Backslashes, whitespace and control chars get normalised away or turned into "/"
  // by WHATWG URL parsing (`evil/x\..\..\vercel\next.js` resolves to vercel/next.js),
  // so reject them before anything else looks at the string.
  if (/[\s\\\u0000-\u001f\u007f]/.test(raw)) return null;
  // Reject dot segments (raw or percent-encoded) up front: WHATWG URL parsing would
  // silently resolve them and point at a different repo than the user typed.
  if (/(^|[\/:])(\.|%2e){1,2}(?=[\/?#]|$)/i.test(raw)) return null;

  let segments: string[];
  const ssh = /^git@github\.com:(.+)$/i.exec(raw);
  if (ssh) {
    segments = ssh[1]!.split("/").filter(Boolean);
  } else {
    let url: URL;
    try {
      url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
    } catch {
      return null;
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    const host = url.hostname.toLowerCase();
    if (host !== "github.com" && host !== "www.github.com") return null;
    if (url.username || url.password || url.port) return null;
    // Decode per segment so an encoded "/" (%2F) can't create new segments.
    try {
      segments = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    } catch {
      return null;
    }
    if (segments.some((s) => s.includes("/"))) return null;
  }

  if (segments.length < 2) return null;

  const owner = segments[0]!;
  const repo = segments[1]!.replace(/\.git$/i, "");
  if (!OWNER_RE.test(owner) || !REPO_RE.test(repo) || repo === "." || repo === "..") return null;

  if (segments.length === 2) return { owner, repo };

  if (["tree", "blob", "commit"].includes(segments[2]!)) {
    if (segments.length < 4) return null;
    const rest = segments.slice(3);
    if (rest.some((s) => s === "." || s === ".." || !REF_RE.test(s))) return null;
    const ref = rest[0]!;
    const subpath = rest.slice(1).join("/");
    if (subpath.length > 200) return null;
    return subpath ? { owner, repo, ref, subpath } : { owner, repo, ref };
  }

  // Other sub-pages (issues, blob, pulls, ...): still the same repo, default branch.
  return { owner, repo };
}
