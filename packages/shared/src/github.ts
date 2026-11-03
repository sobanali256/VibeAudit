export interface GitHubRepoRef {
  owner: string;
  repo: string;
  /** Branch, tag or commit SHA when the URL names one (`/tree/<ref>`). */
  ref?: string;
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

  if (segments[2] === "tree" && segments.length >= 4) {
    const ref = segments.slice(3).join("/");
    if (!REF_RE.test(ref) || ref.split("/").some((s) => s === "." || s === "..")) return null;
    return { owner, repo, ref };
  }

  // Other sub-pages (issues, blob, pulls, ...): still the same repo, default branch.
  return { owner, repo };
}
