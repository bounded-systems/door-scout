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
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import type { Socket } from "bun";

// Import shared daemon infrastructure
import {
  defaultSocketPath,
  prepareSocket,
  createLogger,
  call,
  type RequestEnvelope,
  type ResponseEnvelope,
  ok,
  err,
} from "./lib/runtime";

// The guest-room capability engine: attenuation + its enforcement combinator,
// plus transit-grant verification (signed grants on tcp/vsock).
import {
  attenuate,
  checkCaveats,
  unix,
  verifyGrantWithKeys,
  type DoorGrant,
  type CaveatVerifiers,
  type IssuerKeys,
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

/**
 * POST a GraphQL query to the GitHub API — the only way to read Projects v2
 * (the `project` method's transport; no REST equivalent exists). Same token,
 * same allowlist host (api.github.com) as githubFetch's REST calls.
 */
async function githubGraphQL(
  query: string,
  variables: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "User-Agent": "scoutd/0.1.0",
  };
  if (githubToken) {
    headers["Authorization"] = `Bearer ${githubToken}`;
  }
  const resp = await egressFetch("https://api.github.com/graphql", {
    method: "POST",
    headers,
    body: JSON.stringify({ query, variables }),
  });
  if (!resp.ok) {
    throw { code: "GITHUB_ERROR", message: `GitHub API error: ${resp.status}` };
  }
  const body = await resp.json() as {
    data?: Record<string, unknown>;
    errors?: Array<{ message: string }>;
  };
  if (body.errors?.length) {
    throw { code: "GITHUB_ERROR", message: body.errors.map((e) => e.message).join("; ") };
  }
  if (!body.data) {
    throw { code: "GITHUB_ERROR", message: "GraphQL response had no data" };
  }
  return body.data;
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

/** One item on a Projects v2 board, as returned by the `project` method. */
type ProjectItemResult = {
  number: number;
  title: string;
  url: string;
  repo: string;
  contentType: "Issue" | "PullRequest";
  state: string;
  fields: Record<string, string | number>;
};

/**
 * Fetch items from a GitHub Projects v2 board (e.g. Front Desk). GraphQL-only
 * — there is no REST equivalent for Projects v2. Read-only: no mutation is
 * exposed here (setting Status/Score stays a host-side, App-token operation —
 * writes go through a lease-token door, e.g. prx's forge-d; this door only
 * lets the box SEE the board, not write to it).
 *
 * Returns raw field values per item; the board's own view-level sort (e.g.
 * "Ready (ranked)" by Score) isn't queryable through this API, so the caller
 * sorts client-side.
 */
async function handleProject(params: Record<string, unknown>): Promise<unknown> {
  const org = params.org as string;
  const number = params.number as number;
  const first = Math.min((params.first as number) ?? 50, 100);
  const after = (params.after as string) ?? null;

  if (!org || !number) {
    throw { code: "INVALID_PARAMS", message: "org and number required" };
  }

  if (!allowed("api.github.com")) {
    log("DENY", `project ${org}/${number} (api.github.com not allowed)`);
    throw { code: "NOT_ALLOWED", message: "GitHub API not in allowlist" };
  }

  log("ALLOW", `project ${org}#${number}`);

  const data = await githubGraphQL(
    `query($org:String!,$num:Int!,$first:Int!,$after:String){
      organization(login:$org){ projectV2(number:$num){
        title
        items(first:$first, after:$after){
          pageInfo{ hasNextPage endCursor }
          nodes{
            content{
              __typename
              ... on Issue{ number title url state repository{ nameWithOwner } }
              ... on PullRequest{ number title url state repository{ nameWithOwner } }
            }
            fieldValues(first:20){ nodes{
              ... on ProjectV2ItemFieldSingleSelectValue{
                field{ ... on ProjectV2FieldCommon{ name } } name
              }
              ... on ProjectV2ItemFieldNumberValue{
                field{ ... on ProjectV2FieldCommon{ name } } number
              }
              ... on ProjectV2ItemFieldTextValue{
                field{ ... on ProjectV2FieldCommon{ name } } text
              }
            } }
          }
        }
      } }
    }`,
    { org, num: number, first, after },
  );

  const proj = (data.organization as Record<string, unknown>)?.projectV2 as
    | Record<string, unknown>
    | undefined;
  if (!proj) {
    throw { code: "NOT_FOUND", message: `no project #${number} for org ${org}` };
  }

  const itemsConn = proj.items as {
    pageInfo: { hasNextPage: boolean; endCursor: string | null };
    nodes: Array<{
      content: {
        __typename?: string;
        number?: number;
        title?: string;
        url?: string;
        state?: string;
        repository?: { nameWithOwner?: string };
      } | null;
      fieldValues: {
        nodes: Array<
          {
            field?: { name?: string };
            name?: string | null;
            number?: number | null;
            text?: string | null;
          }
        >;
      };
    }>;
  };

  const items: ProjectItemResult[] = [];
  for (const n of itemsConn.nodes) {
    if (!n.content?.number) continue; // draft issues have no repo/number
    const fields: Record<string, string | number> = {};
    for (const fv of n.fieldValues.nodes) {
      const name = fv.field?.name;
      if (!name) continue;
      if (fv.name != null) fields[name] = fv.name;
      else if (fv.number != null) fields[name] = fv.number;
      else if (fv.text != null) fields[name] = fv.text;
    }
    items.push({
      number: n.content.number,
      title: n.content.title ?? "",
      url: n.content.url ?? "",
      repo: n.content.repository?.nameWithOwner ?? "",
      contentType: (n.content.__typename as "Issue" | "PullRequest") ?? "Issue",
      state: n.content.state ?? "",
      fields,
    });
  }

  return {
    title: proj.title,
    items,
    pageInfo: itemsConn.pageInfo,
  };
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
  project: handleProject,
  fetch: handleFetch,
  download: handleDownload,
};

// ── Transit-grant gate (tcp/vsock only) ──────────────────────────────────────
// On a unix door the held socket reference IS authority (the mount is the grant)
// — no per-request check. On tcp/vsock the kernel gives no peer identity, so a
// caller must present a SIGNED grant (req.grant) the concierge minted; we verify
// it against the concierge's PUBLISHED keys (keyless, fetched + cached) for THIS
// room and door. See the transport-split ADR / CONCIERGE.md §7. Set by serveTcp.
let grantRequired = false;

function conciergeSocket(): string {
  if (process.env.CONCIERGE_SOCK) return process.env.CONCIERGE_SOCK;
  const runtime = process.env.XDG_RUNTIME_DIR;
  if (runtime) return `${runtime}/concierged.sock`;
  return `${process.env.HOME ?? "/tmp"}/.claude-box/concierged.sock`;
}

let issuerKeys: IssuerKeys | null = null;
async function fetchIssuerKeys(force = false): Promise<IssuerKeys> {
  if (issuerKeys && !force) return issuerKeys;
  issuerKeys = await call<IssuerKeys>(conciergeSocket(), "keys");
  return issuerKeys;
}

const verifyWith = (data: string, signature: string, publicKeyPem: string): boolean =>
  edVerify(null, Buffer.from(data), createPublicKey(publicKeyPem), Buffer.from(signature, "base64"));

/** Gate a request on a tcp/vsock door: verify the presented signed grant against
 *  the concierge's published keys. Re-fetches keys ONCE on an unknown key (the
 *  issuer rotated). Returns ok, or a reason for the denial. */
async function gateGrant(req: RequestEnvelope): Promise<{ ok: boolean; reason?: string }> {
  if (!grantRequired) return { ok: true }; // unix: reference is authority
  const grant = req.grant;
  if (!grant) return { ok: false, reason: "no-grant" };
  if (grant.name !== "scout") return { ok: false, reason: "wrong-door" };
  const ctx = { audience: process.env.ROOM_ID ?? "", now: Date.now() };
  let v = verifyGrantWithKeys(grant, ctx, await fetchIssuerKeys(), verifyWith);
  if (!v.ok && v.reason === "unknown-key") {
    v = verifyGrantWithKeys(grant, ctx, await fetchIssuerKeys(true), verifyWith); // rotation
  }
  return v;
}

// ── Request handling ─────────────────────────────────────────────────────────
// Protocol types (RequestEnvelope, ResponseEnvelope) imported from lib/runtime

// ── wire-contract shadow validation (log-only) ───────────────────────────────
// The published scout-wire agreement, bundled next to scoutd in the image. When
// absent (running the source in tests) it's null and the check is skipped. It
// NEVER rejects: a mismatch is LOGGED (surfacing spec↔handler drift), request
// handling is unaffected.
interface WireManifest {
  methods: string[];
  params: Record<string, string[]>;
}
let wireManifest: WireManifest | null = (() => {
  try {
    const p = new URL("./scout-wire.manifest.json", import.meta.url).pathname;
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
})();

/** Test seam: inject (or clear) the agreement manifest. */
export function __setWireManifest(m: WireManifest | null): void {
  wireManifest = m;
}

/**
 * Shadow-validate a request's params against the published agreement — LOG ONLY.
 * Warns on params the contract doesn't declare (drift); never rejects. `kind` is
 * the request-envelope discriminator, not a verb param.
 */
export function shadowCheckParams(
  method: string,
  params: Record<string, unknown>,
): void {
  if (!wireManifest) return;
  const declared = wireManifest.params[method];
  if (!declared) return;
  const allow = new Set([...declared, "kind"]);
  const unexpected = Object.keys(params).filter((k) => !allow.has(k));
  if (unexpected.length) {
    console.warn(
      `scout-wire: request "${method}" sends undeclared param(s): ${
        unexpected.join(", ")
      } — spec/handler drift`,
    );
  }
}

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

  // Transit-grant gate: on tcp/vsock, no valid signed grant ⇒ no handler reached.
  const gate = await gateGrant(req);
  if (!gate.ok) {
    return err(id, "UNAUTHORIZED", `signed grant rejected: ${gate.reason}`);
  }

  const handler = METHODS[method];
  if (!handler) {
    return err(id, "UNKNOWN_METHOD", `unknown method: ${method}`);
  }

  shadowCheckParams(method, params ?? {});

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
  // tcp/vsock has no kernel peer identity ⇒ require a verified signed grant.
  grantRequired = true;
  log("INFO", `listening tcp ${host}:${port} allow=${ALLOW.slice(0, 3).join(",")}... (signed-grant gate, fail-closed)`);

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
  - project     fetch Projects v2 board items (read-only; GraphQL)
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
  handleProject,
  handleFetch,
  handleDownload,
  loadToken,
  allowed,
  scoutDoor,
  scoutVerifiers,
  socketHandler,
  gateGrant,
  parseGitHubRepo,
  VERSION,
};

/** Test seams: drive the tcp/vsock grant gate without a live concierge. */
export function __setGrantRequired(v: boolean): void {
  grantRequired = v;
}
export function __setIssuerKeys(k: IssuerKeys | null): void {
  issuerKeys = k;
}

export type { RequestEnvelope, ResponseEnvelope };

if (import.meta.main) {
  process.exit(await main());
}
