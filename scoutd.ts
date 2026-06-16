#!/usr/bin/env bun
/**
 * scoutd — the read daemon for claude-box (the --scout door).
 *
 * Listens on a unix socket, handles repo/pr/issue/fetch requests.
 * Owns: read tokens (GitHub), fetch policy, content caching.
 *
 * The box asks scoutd for content; scoutd returns bytes, never credentials.
 * This is the READ twin of keeperd (WRITES) — see SCOUT.md.
 *
 * Usage:
 *   scoutd serve                     # foreground, default socket
 *   scoutd serve --socket /path.sock # custom socket path
 *   scoutd serve --token /path       # GitHub token file (read-only scope!)
 */

import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { createHash } from "node:crypto";
import type { Socket } from "bun";

// Import shared daemon infrastructure
import {
  defaultSocketPath,
  prepareSocket,
  createLogger,
  type RequestEnvelope,
  type ResponseEnvelope,
  ok,
  err,
} from "./lib/runtime";

// The guest-room capability engine: attenuation + its enforcement combinator.
import {
  attenuate,
  checkCaveats,
  unix,
  type DoorGrant,
  type CaveatVerifiers,
} from "./guest-room/mod.ts";

const log = createLogger("scoutd");

// ── Config ───────────────────────────────────────────────────────────────────

const VERSION = "0.1.0";

// Default allowlist: GitHub + common registries
const DEFAULT_ALLOW = [
  "github.com",
  ".github.com",
  "api.github.com",
  "raw.githubusercontent.com",
  "objects.githubusercontent.com",
  "codeload.github.com",
  "registry.npmjs.org",
  "pypi.org",
];

function defaultTokenPath(): string {
  const home = process.env.HOME ?? "/tmp";
  return `${home}/.claude-box/scout_github_token`;
}

// ── Egress mode ────────────────────────────────────────────────────────────
// When SCOUTD_PROXY is set (an HTTP proxy URL — a netd door), EVERY outbound
// fetch is routed through it (see egressFetch below), so scoutd can run with NO
// network of its own and netd stays the single egress chokepoint. In that mode
// netd is the allowlist SOURCE OF TRUTH; scoutd does not enforce a second,
// drift-prone copy. Unset ⇒ direct egress (dev / TCP mode), enforced here.
const EGRESS_PROXY = process.env.SCOUTD_PROXY || undefined;

// ── Allowlist (a door caveat, enforced by the engine) ────────────────────────

const ALLOW = (process.env.SCOUTD_ALLOW?.split(",").map((s) => s.trim()).filter(Boolean) ?? [])
  .length
  ? process.env.SCOUTD_ALLOW!.split(",").map((s) => s.trim()).filter(Boolean)
  : DEFAULT_ALLOW;

// The scout door's grant, carrying the allowlist as a single `host=` caveat
// (comma = OR). This is the SAME caveat shape the rulebook renders via
// grantedDoorLines — so what the agent is TOLD it may reach is exactly what
// scoutd ENFORCES (granted == enforced, one source of truth). In proxy mode the
// door carries no host caveat (netd is the boundary), so checkCaveats allows.
const scoutDoor: DoorGrant = attenuate(
  {
    name: "scout",
    host: unix("(broker)"),
    guest: unix("/run/scoutd.sock"),
    env: "SCOUTD_SOCK",
    grants: "external reads via scoutd",
    use: "Read external content through the scout door.",
  },
  EGRESS_PROXY ? [] : [`host=${ALLOW.join(",")}`],
);

// The broker owns the `host` grammar (the engine never reads it): comma = OR,
// exact or leading-dot suffix, case-insensitive.
const scoutVerifiers: CaveatVerifiers<{ hostname: string }> = {
  host: (value, ctx) => {
    const h = ctx.hostname.toLowerCase();
    return value
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .some((a) => (a.startsWith(".") ? h === a.slice(1) || h.endsWith(a) : h === a));
  },
};

/** Is `host` reachable through the scout door? Enforcement flows through the
 *  guest-room engine combinator (checkCaveats) over the door's caveats — not a
 *  bespoke list — so it is fail-closed and identical to what the rulebook shows.
 *  Proxy mode: the door has no host caveat ⇒ allows (netd is the boundary). */
function allowed(host: string): boolean {
  return checkCaveats(scoutDoor, { hostname: host }, scoutVerifiers).ok;
}

// ── GitHub Token ─────────────────────────────────────────────────────────────

let githubToken: string | null = null;

function loadToken(tokenPath: string): void {
  // Source-agnostic injection (SCOUT-POD.md): an injected env secret — `gh auth
  // token`, `op read`, or a cloud secret manager — takes priority over a host
  // file path, so the daemon carries NO host assumption and lifts into the cloud
  // unchanged. The token VALUE is never logged (it must not enter a transcript).
  const envToken = (
    process.env.SCOUTD_TOKEN ||
    process.env.GH_TOKEN ||
    process.env.GITHUB_TOKEN ||
    ""
  ).trim();
  if (envToken) {
    githubToken = envToken;
    log("INFO", "loaded GitHub token from env (injected secret)");
    return;
  }
  if (existsSync(tokenPath)) {
    githubToken = readFileSync(tokenPath, "utf-8").trim();
    log("INFO", `loaded GitHub token from ${tokenPath}`);
    return;
  }
  githubToken = null;
  log("INFO", "no GitHub token (public repos only)");
}

// ── Utility ──────────────────────────────────────────────────────────────────

function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Parse a GitHub URL/spec into owner/repo. */
function parseGitHubRepo(input: string): { owner: string; repo: string } | null {
  // Handle: owner/repo, github.com/owner/repo, https://github.com/owner/repo
  const patterns = [
    /^(?:https?:\/\/)?github\.com\/([^\/]+)\/([^\/]+?)(?:\.git)?$/,
    /^([^\/]+)\/([^\/]+)$/,
  ];
  for (const p of patterns) {
    const m = input.match(p);
    if (m) return { owner: m[1], repo: m[2] };
  }
  return null;
}

// ── Egress ───────────────────────────────────────────────────────────────────
// scoutd's only outward path. When EGRESS_PROXY is set (defined above), EVERY
// outbound fetch is routed through it, so scoutd can run with NO network of its
// own (`--network=none`) and netd stays the single egress chokepoint
// (CAPABILITIES.md "network is a door, not a NIC"). Unset ⇒ direct egress
// (dev / TCP mode), where the scout door's host caveat is enforced here.

/** fetch(), routed through netd (SCOUTD_PROXY) when configured. */
function egressFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const opts: RequestInit & { proxy?: string } = { ...init };
  if (EGRESS_PROXY) opts.proxy = EGRESS_PROXY;
  return fetch(url, opts);
}

// ── GitHub API ───────────────────────────────────────────────────────────────

async function githubFetch(path: string): Promise<Response> {
  const headers: Record<string, string> = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "scoutd/0.1.0",
  };
  if (githubToken) {
    headers["Authorization"] = `Bearer ${githubToken}`;
  }
  return egressFetch(`https://api.github.com${path}`, { headers });
}

// ── Method handlers ──────────────────────────────────────────────────────────

type MethodHandler = (params: Record<string, unknown>) => Promise<unknown>;

const startedAt = new Date();

async function handleStatus(_params: Record<string, unknown>): Promise<unknown> {
  return {
    version: VERSION,
    uptime: Math.floor((Date.now() - startedAt.getTime()) / 1000),
    hasToken: !!githubToken,
    allowlist: ALLOW,
  };
}

/**
 * Fetch a GitHub repository tree/tarball.
 * Returns metadata + download URL or error.
 */
async function handleRepo(params: Record<string, unknown>): Promise<unknown> {
  const url = params.url as string;
  const ref = (params.ref as string) || "HEAD";

  if (!url) {
    throw { code: "INVALID_PARAMS", message: "url required" };
  }

  const parsed = parseGitHubRepo(url);
  if (!parsed) {
    throw { code: "INVALID_REPO", message: "could not parse GitHub repo from url" };
  }

  if (!allowed("api.github.com")) {
    log("DENY", `repo ${url} (api.github.com not allowed)`);
    throw { code: "NOT_ALLOWED", message: "GitHub API not in allowlist" };
  }

  const { owner, repo } = parsed;
  log("ALLOW", `repo ${owner}/${repo}@${ref}`);

  // Fetch repo metadata
  const repoResp = await githubFetch(`/repos/${owner}/${repo}`);
  if (!repoResp.ok) {
    throw { code: "GITHUB_ERROR", message: `GitHub API error: ${repoResp.status}` };
  }
  const repoData = await repoResp.json() as any;

  // Get the tarball URL for the ref
  const tarballUrl = `https://api.github.com/repos/${owner}/${repo}/tarball/${ref}`;

  return {
    owner,
    repo,
    ref,
    defaultBranch: repoData.default_branch,
    description: repoData.description,
    tarballUrl,
    // Don't include token in response - client uses this URL through us
  };
}

/**
 * Fetch a GitHub PR.
 * Returns PR metadata + diff/comments.
 */
async function handlePr(params: Record<string, unknown>): Promise<unknown> {
  const repoSpec = params.repo as string;
  const number = params.number as number;
  const includeDiff = params.diff as boolean ?? false;
  const includeComments = params.comments as boolean ?? false;

  if (!repoSpec || !number) {
    throw { code: "INVALID_PARAMS", message: "repo and number required" };
  }

  const parsed = parseGitHubRepo(repoSpec);
  if (!parsed) {
    throw { code: "INVALID_REPO", message: "could not parse GitHub repo" };
  }

  if (!allowed("api.github.com")) {
    log("DENY", `pr ${repoSpec}#${number} (api.github.com not allowed)`);
    throw { code: "NOT_ALLOWED", message: "GitHub API not in allowlist" };
  }

  const { owner, repo } = parsed;
  log("ALLOW", `pr ${owner}/${repo}#${number}`);

  // Fetch PR
  const prResp = await githubFetch(`/repos/${owner}/${repo}/pulls/${number}`);
  if (!prResp.ok) {
    throw { code: "GITHUB_ERROR", message: `GitHub API error: ${prResp.status}` };
  }
  const pr = await prResp.json() as any;

  const result: Record<string, unknown> = {
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    user: pr.user?.login,
    head: { ref: pr.head?.ref, sha: pr.head?.sha },
    base: { ref: pr.base?.ref, sha: pr.base?.sha },
    createdAt: pr.created_at,
    updatedAt: pr.updated_at,
    additions: pr.additions,
    deletions: pr.deletions,
    changedFiles: pr.changed_files,
  };

  if (includeDiff) {
    const diffResp = await egressFetch(pr.diff_url, {
      headers: githubToken ? { Authorization: `Bearer ${githubToken}` } : {},
    });
    if (diffResp.ok) {
      result.diff = await diffResp.text();
    }
  }

  if (includeComments) {
    const commentsResp = await githubFetch(`/repos/${owner}/${repo}/pulls/${number}/comments`);
    if (commentsResp.ok) {
      const comments = await commentsResp.json() as any;
      result.comments = comments.map((c: Record<string, unknown>) => ({
        user: (c.user as Record<string, unknown>)?.login,
        body: c.body,
        path: c.path,
        createdAt: c.created_at,
      }));
    }
  }

  return result;
}

/**
 * Fetch a GitHub issue.
 */
async function handleIssue(params: Record<string, unknown>): Promise<unknown> {
  const repoSpec = params.repo as string;
  const number = params.number as number;
  const includeComments = params.comments as boolean ?? false;

  if (!repoSpec || !number) {
    throw { code: "INVALID_PARAMS", message: "repo and number required" };
  }

  const parsed = parseGitHubRepo(repoSpec);
  if (!parsed) {
    throw { code: "INVALID_REPO", message: "could not parse GitHub repo" };
  }

  if (!allowed("api.github.com")) {
    log("DENY", `issue ${repoSpec}#${number} (api.github.com not allowed)`);
    throw { code: "NOT_ALLOWED", message: "GitHub API not in allowlist" };
  }

  const { owner, repo } = parsed;
  log("ALLOW", `issue ${owner}/${repo}#${number}`);

  const issueResp = await githubFetch(`/repos/${owner}/${repo}/issues/${number}`);
  if (!issueResp.ok) {
    throw { code: "GITHUB_ERROR", message: `GitHub API error: ${issueResp.status}` };
  }
  const issue = await issueResp.json() as any;

  const result: Record<string, unknown> = {
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    user: issue.user?.login,
    labels: issue.labels?.map((l: Record<string, unknown>) => l.name),
    createdAt: issue.created_at,
    updatedAt: issue.updated_at,
  };

  if (includeComments) {
    const commentsResp = await githubFetch(`/repos/${owner}/${repo}/issues/${number}/comments`);
    if (commentsResp.ok) {
      const comments = await commentsResp.json() as any;
      result.comments = comments.map((c: Record<string, unknown>) => ({
        user: (c.user as Record<string, unknown>)?.login,
        body: c.body,
        createdAt: c.created_at,
      }));
    }
  }

  return result;
}

/**
 * Fetch an arbitrary URL (with allowlist enforcement).
 * Returns the response body as text or base64.
 */
async function handleFetch(params: Record<string, unknown>): Promise<unknown> {
  const url = params.url as string;
  const binary = params.binary as boolean ?? false;
  const maxSize = (params.maxSize as number) ?? 10 * 1024 * 1024; // 10MB default

  if (!url) {
    throw { code: "INVALID_PARAMS", message: "url required" };
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw { code: "INVALID_URL", message: "could not parse URL" };
  }

  if (!allowed(parsed.hostname)) {
    log("DENY", `fetch ${url} (${parsed.hostname} not allowed)`);
    throw { code: "NOT_ALLOWED", message: `host ${parsed.hostname} not in allowlist` };
  }

  log("ALLOW", `fetch ${url}`);

  const resp = await egressFetch(url, {
    headers: {
      "User-Agent": "scoutd/0.1.0",
    },
  });

  if (!resp.ok) {
    throw { code: "FETCH_ERROR", message: `HTTP ${resp.status}` };
  }

  const contentLength = resp.headers.get("content-length");
  if (contentLength && parseInt(contentLength) > maxSize) {
    throw { code: "TOO_LARGE", message: `response exceeds ${maxSize} bytes` };
  }

  const buffer = await resp.arrayBuffer();
  if (buffer.byteLength > maxSize) {
    throw { code: "TOO_LARGE", message: `response exceeds ${maxSize} bytes` };
  }

  return {
    url,
    status: resp.status,
    contentType: resp.headers.get("content-type"),
    size: buffer.byteLength,
    body: binary
      ? Buffer.from(buffer).toString("base64")
      : new TextDecoder().decode(buffer),
  };
}

/**
 * Download a file from GitHub (tarball, file content, etc).
 * Streams through scoutd so the box never needs auth.
 */
async function handleDownload(params: Record<string, unknown>): Promise<unknown> {
  const url = params.url as string;
  const maxSize = (params.maxSize as number) ?? 100 * 1024 * 1024; // 100MB default

  if (!url) {
    throw { code: "INVALID_PARAMS", message: "url required" };
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw { code: "INVALID_URL", message: "could not parse URL" };
  }

  if (!allowed(parsed.hostname)) {
    log("DENY", `download ${url} (${parsed.hostname} not allowed)`);
    throw { code: "NOT_ALLOWED", message: `host ${parsed.hostname} not in allowlist` };
  }

  log("ALLOW", `download ${url}`);

  const headers: Record<string, string> = {
    "User-Agent": "scoutd/0.1.0",
  };
  // Add auth for GitHub API URLs
  if (githubToken && parsed.hostname === "api.github.com") {
    headers["Authorization"] = `Bearer ${githubToken}`;
    headers["Accept"] = "application/vnd.github+json";
  }

  const resp = await egressFetch(url, { headers, redirect: "follow" });

  if (!resp.ok) {
    throw { code: "FETCH_ERROR", message: `HTTP ${resp.status}` };
  }

  const contentLength = resp.headers.get("content-length");
  if (contentLength && parseInt(contentLength) > maxSize) {
    throw { code: "TOO_LARGE", message: `response exceeds ${maxSize} bytes` };
  }

  const buffer = await resp.arrayBuffer();
  if (buffer.byteLength > maxSize) {
    throw { code: "TOO_LARGE", message: `response exceeds ${maxSize} bytes` };
  }

  return {
    url,
    size: buffer.byteLength,
    contentType: resp.headers.get("content-type"),
    sha256: sha256(Buffer.from(buffer).toString("binary")),
    data: Buffer.from(buffer).toString("base64"),
  };
}

const METHODS: Record<string, MethodHandler> = {
  status: handleStatus,
  repo: handleRepo,
  pr: handlePr,
  issue: handleIssue,
  fetch: handleFetch,
  download: handleDownload,
};

// ── Request handling ─────────────────────────────────────────────────────────
// Protocol types (RequestEnvelope, ResponseEnvelope) imported from lib/runtime

async function handleRequest(line: string): Promise<ResponseEnvelope> {
  let req: RequestEnvelope;
  try {
    req = JSON.parse(line);
  } catch {
    return err("", "PARSE_ERROR", "invalid JSON");
  }

  const { id, method, params } = req;

  if (!id || !method) {
    return err(id ?? "", "INVALID_REQUEST", "id and method required");
  }

  const handler = METHODS[method];
  if (!handler) {
    return err(id, "UNKNOWN_METHOD", `unknown method: ${method}`);
  }

  try {
    const result = await handler(params ?? {});
    return ok(id, result);
  } catch (e) {
    const error = e as { code?: string; message?: string };
    return err(id, error.code ?? "INTERNAL_ERROR", error.message ?? String(e));
  }
}

// ── Socket server ────────────────────────────────────────────────────────────

const socketHandler = {
  async data(socket: Socket, data: Buffer) {
    const lines = data.toString().split("\n").filter(Boolean);
    for (const line of lines) {
      const resp = await handleRequest(line);
      socket.write(JSON.stringify(resp) + "\n");
    }
  },
  open(_socket: Socket) {},
  close(_socket: Socket) {},
  error(_socket: Socket, error: Error) {
    log("ERR", `socket error: ${error}`);
  },
};

async function serveUnix(socketPath: string): Promise<void> {
  const dir = dirname(socketPath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  prepareSocket(socketPath);
  log("INFO", `listening unix ${socketPath} allow=${ALLOW.slice(0, 3).join(",")}... (fail-closed)`);

  Bun.listen({
    unix: socketPath,
    socket: socketHandler,
  });

  await new Promise(() => {});
}

// Bind to 0.0.0.0 so podman machine VM can reach us via host.containers.internal
async function serveTcp(port: number, host: string = "0.0.0.0"): Promise<void> {
  log("INFO", `listening tcp ${host}:${port} allow=${ALLOW.slice(0, 3).join(",")}... (fail-closed)`);

  Bun.listen({
    hostname: host,
    port,
    socket: socketHandler,
  });

  await new Promise(() => {});
}

// ── CLI ──────────────────────────────────────────────────────────────────────

async function main(): Promise<number> {
  const args = Bun.argv.slice(2);
  const cmd = args[0];

  if (cmd === "serve") {
    let socketPath = defaultSocketPath("scoutd");
    let tokenPath = defaultTokenPath();
    let port: number | undefined;

    for (let i = 1; i < args.length; i++) {
      if (args[i] === "--socket" || args[i] === "-s") {
        socketPath = args[++i]!;
      } else if (args[i] === "--token" || args[i] === "-t") {
        tokenPath = args[++i]!;
      } else if (args[i] === "--port" || args[i] === "-p") {
        port = Number(args[++i]);
      }
    }

    // Load GitHub token (optional)
    loadToken(tokenPath);

    if (port) {
      await serveTcp(port);
    } else {
      await serveUnix(socketPath);
    }
    return 0;
  }

  console.log(`scoutd — read daemon for claude-box

Usage:
  scoutd serve                     start daemon (foreground, unix socket)
  scoutd serve --port PORT         listen on TCP (for testing)
  scoutd serve --socket PATH       custom socket path
  scoutd serve --token PATH        GitHub token file (read-only scope!)

The daemon listens for NDJSON requests:
  - status      health check + allowlist
  - repo        fetch GitHub repo metadata + tarball URL
  - pr          fetch PR metadata, diff, comments
  - issue       fetch issue metadata + comments
  - fetch       fetch arbitrary URL (allowlist enforced)
  - download    download file content (base64)

Environment:
  SCOUTD_ALLOW  comma-separated allowlist (default: github.com, npm, pypi)
  SCOUTD_TOKEN / GH_TOKEN / GITHUB_TOKEN
                injected GitHub token (takes priority over --token file; never
                logged). Source-agnostic: gh auth token / op / a cloud secret.

See SCOUT.md and SCOUT-POD.md for details.`);

  return cmd === "-h" || cmd === "--help" ? 0 : 1;
}

// ── Exports for testing ──────────────────────────────────────────────────────

export {
  handleRequest,
  handleStatus,
  handleRepo,
  handlePr,
  handleIssue,
  handleFetch,
  handleDownload,
  loadToken,
  allowed,
  scoutDoor,
  scoutVerifiers,
  socketHandler,
  parseGitHubRepo,
  VERSION,
};

export type { RequestEnvelope, ResponseEnvelope };

if (import.meta.main) {
  process.exit(await main());
}
