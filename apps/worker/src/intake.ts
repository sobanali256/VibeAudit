import { Readable } from "node:stream";
import {
  type GitHubRepoRef,
  MAX_GITHUB_TARBALL_BYTES,
  refCandidates,
} from "@vibeaudit/shared";

/**
 * Resolve a user-supplied GitHub repo+ref to a concrete tarball, and download it with a hard
 * byte cap, on VM 1. VM 1 NEVER opens the tarball (CLAUDE.md invariant): it streams the bytes
 * to a sandbox container on VM 2, which unpacks them and enforces the entry-count cap.
 *
 * `fetchImpl` is injectable for tests; defaults to global fetch.
 */
export interface IntakeOptions {
  token?: string;
  fetchImpl?: typeof fetch;
  maxBytes?: number;
  /** Abort signal for the download. */
  signal?: AbortSignal;
}

export interface ResolvedRepo {
  owner: string;
  repo: string;
  /** The ref that actually exists on GitHub (branch, tag or commit sha). */
  ref: string;
  /** Path within the repo the URL pointed at, if any (informational; we still fetch the whole repo). */
  subpath?: string;
  tarballUrl: string;
}

const API = "https://api.github.com";
const UA = "VibeAudit";

function headers(token?: string): Record<string, string> {
  const h: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": UA,
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

export class IntakeError extends Error {
  constructor(
    message: string,
    readonly code:
      | "not_found"
      | "ref_not_found"
      | "rate_limited"
      | "too_large"
      | "network"
      | "forbidden",
  ) {
    super(message);
    this.name = "IntakeError";
  }
}

/** Does `ref` exist in the repo? Uses the commits endpoint, which resolves branch/tag/sha alike. */
async function refExists(
  ref: GitHubRepoRef,
  candidate: string,
  opts: IntakeOptions,
): Promise<boolean> {
  const f = opts.fetchImpl ?? fetch;
  const url = `${API}/repos/${ref.owner}/${ref.repo}/commits/${encodeURIComponent(candidate)}`;
  const res = await f(url, { headers: headers(opts.token), signal: opts.signal });
  if (res.status === 200) return true;
  if (res.status === 404 || res.status === 422) return false;
  throwForStatus(res);
  return false;
}

function throwForStatus(res: Response): never {
  if (res.status === 403 || res.status === 429) {
    const remaining = res.headers.get("x-ratelimit-remaining");
    if (remaining === "0" || res.status === 429) {
      throw new IntakeError("GitHub API rate limit reached", "rate_limited");
    }
    throw new IntakeError("GitHub API forbidden", "forbidden");
  }
  if (res.status === 404) throw new IntakeError("repository not found", "not_found");
  throw new IntakeError(`GitHub API error ${res.status}`, "network");
}

/**
 * Turn a parsed GitHubRepoRef into a concrete, existing ref. A URL like /tree/feature/x is
 * ambiguous (branch "feature/x", or branch "feature" + dir "x"), so we try the longest
 * ref first via refCandidates. With no ref, use the repo's default branch.
 */
export async function resolveRepo(ref: GitHubRepoRef, opts: IntakeOptions = {}): Promise<ResolvedRepo> {
  const f = opts.fetchImpl ?? fetch;
  let resolvedRef: string;
  let subpath: string | undefined;

  if (!ref.ref) {
    const res = await f(`${API}/repos/${ref.owner}/${ref.repo}`, {
      headers: headers(opts.token),
      signal: opts.signal,
    });
    if (!res.ok) throwForStatus(res);
    const body = (await res.json()) as { default_branch?: string };
    if (!body.default_branch) throw new IntakeError("repository has no default branch", "not_found");
    resolvedRef = body.default_branch;
  } else {
    const candidates = refCandidates(ref);
    let found: string | undefined;
    for (const cand of candidates) {
      if (await refExists(ref, cand, opts)) {
        found = cand;
        break;
      }
    }
    if (!found) throw new IntakeError(`ref not found: ${ref.ref}`, "ref_not_found");
    resolvedRef = found;
    // Whatever of ref+subpath we didn't consume as the ref is the in-repo path.
    const full = [ref.ref, ...(ref.subpath ? ref.subpath.split("/") : [])];
    const consumed = found.split("/").length;
    const rest = full.slice(consumed).join("/");
    subpath = rest || undefined;
  }

  return {
    owner: ref.owner,
    repo: ref.repo,
    ref: resolvedRef,
    subpath,
    tarballUrl: `${API}/repos/${ref.owner}/${ref.repo}/tarball/${encodeURIComponent(resolvedRef)}`,
  };
}

export interface TarballStream {
  /** Node Readable of the gzipped tar bytes. Pipe straight to the sandbox; do not open on VM 1. */
  stream: Readable;
  /** Resolves with the byte count once the stream ends; rejects with IntakeError "too_large". */
  done: Promise<number>;
}

/**
 * Open the tarball as a capped stream. Reading past maxBytes destroys the stream and rejects
 * `done`, so a repo that lies about its size (or a decompression bomb upstream) can't flood
 * VM 1 or the sandbox host. The caller pipes `stream` to VM 2 and awaits `done`.
 */
export async function openTarball(resolved: ResolvedRepo, opts: IntakeOptions = {}): Promise<TarballStream> {
  const f = opts.fetchImpl ?? fetch;
  const maxBytes = opts.maxBytes ?? MAX_GITHUB_TARBALL_BYTES;
  const res = await f(resolved.tarballUrl, {
    headers: headers(opts.token),
    redirect: "follow",
    signal: opts.signal,
  });
  if (!res.ok) throwForStatus(res);
  if (!res.body) throw new IntakeError("empty tarball response", "network");

  // Trust the header only as an early reject; the real enforcement is the running count.
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new IntakeError(`tarball too large (${declared} bytes)`, "too_large");
  }

  let count = 0;
  let resolveDone: (n: number) => void;
  let rejectDone: (e: unknown) => void;
  const done = new Promise<number>((res2, rej) => {
    resolveDone = res2;
    rejectDone = rej;
  });

  const source = res.body.getReader();
  const stream = new Readable({
    read() {
      source
        .read()
        .then(({ done: finished, value }) => {
          if (finished) {
            this.push(null);
            resolveDone(count);
            return;
          }
          count += value.byteLength;
          if (count > maxBytes) {
            const err = new IntakeError(`tarball exceeded ${maxBytes} bytes`, "too_large");
            source.cancel().catch(() => {});
            this.destroy(err);
            return;
          }
          this.push(Buffer.from(value));
        })
        .catch((e) => this.destroy(e instanceof Error ? e : new IntakeError(String(e), "network")));
    },
    destroy(err, cb) {
      source.cancel().catch(() => {});
      if (err) rejectDone(err);
      cb(err);
    },
  });

  return { stream, done };
}
