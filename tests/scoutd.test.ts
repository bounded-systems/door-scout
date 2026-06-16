/**
 * scoutd tests — unit tests for the external read daemon.
 *
 * Tests the request handling, allowlist logic, and GitHub parsing.
 * Does NOT test actual network fetches (those need integration tests).
 *
 *   nix run nixpkgs#bun -- test tests/scoutd.test.ts
 */
import { test, expect, beforeAll, afterAll } from "bun:test";
import {
  handleRequest,
  handleStatus,
  loadToken,
  allowed,
  scoutDoor,
  scoutVerifiers,
  parseGitHubRepo,
  VERSION,
} from "../scoutd.ts";
import { checkCaveats, grantedDoorLines } from "../guest-room/mod.ts";

// ── Parsing tests ────────────────────────────────────────────────────────────

test("parseGitHubRepo parses owner/repo", () => {
  const result = parseGitHubRepo("owner/repo");
  expect(result).toEqual({ owner: "owner", repo: "repo" });
});

test("parseGitHubRepo parses github.com/owner/repo", () => {
  const result = parseGitHubRepo("github.com/owner/repo");
  expect(result).toEqual({ owner: "owner", repo: "repo" });
});

test("parseGitHubRepo parses https://github.com/owner/repo", () => {
  const result = parseGitHubRepo("https://github.com/owner/repo");
  expect(result).toEqual({ owner: "owner", repo: "repo" });
});

test("parseGitHubRepo parses https://github.com/owner/repo.git", () => {
  const result = parseGitHubRepo("https://github.com/owner/repo.git");
  expect(result).toEqual({ owner: "owner", repo: "repo" });
});

test("parseGitHubRepo returns null for invalid input", () => {
  expect(parseGitHubRepo("invalid")).toBeNull();
  expect(parseGitHubRepo("")).toBeNull();
  expect(parseGitHubRepo("just-one-part")).toBeNull();
});

// ── Allowlist tests ──────────────────────────────────────────────────────────

test("allowed: exact match", () => {
  expect(allowed("github.com")).toBe(true);
  expect(allowed("api.github.com")).toBe(true);
});

test("allowed: suffix match", () => {
  expect(allowed("raw.githubusercontent.com")).toBe(true);
  expect(allowed("objects.githubusercontent.com")).toBe(true);
});

test("allowed: not in allowlist", () => {
  expect(allowed("evil.com")).toBe(false);
  expect(allowed("malware.io")).toBe(false);
  expect(allowed("example.com")).toBe(false);
});

test("allowed: case insensitive", () => {
  expect(allowed("GITHUB.COM")).toBe(true);
  expect(allowed("GitHub.Com")).toBe(true);
});

// ── granted == enforced (the scout door's caveat drives both surfaces) ────────

test("scoutDoor carries the allowlist as a host= caveat", () => {
  expect(scoutDoor.caveats).toHaveLength(1);
  expect(scoutDoor.caveats![0]).toMatch(/^host=/);
  // the same patterns allowed() checks are inside the caveat the rulebook renders
  expect(scoutDoor.caveats![0]).toContain("github.com");
});

test("the rulebook line and enforcement are driven by the SAME caveat", () => {
  // what the agent is TOLD (rendered rulebook):
  const [line] = grantedDoorLines([scoutDoor]);
  expect(line).toContain("RESTRICTED to: host=");
  // what scoutd ENFORCES (same door, same caveat) — one source of truth:
  expect(checkCaveats(scoutDoor, { hostname: "api.github.com" }, scoutVerifiers).ok).toBe(true);
  const denied = checkCaveats(scoutDoor, { hostname: "evil.com" }, scoutVerifiers);
  expect(denied.ok).toBe(false);
  if (!denied.ok) expect(denied.caveat).toBe(scoutDoor.caveats![0]); // cites the rendered caveat
});

test("KEYSTONE: a caveat scoutd has no verifier for fails closed (denies)", () => {
  // attenuating the scout door with an unknown key must DENY, never silently allow
  const stricter = { ...scoutDoor, caveats: [...(scoutDoor.caveats ?? []), "mode=readonly"] };
  const v = checkCaveats(stricter, { hostname: "github.com" }, scoutVerifiers);
  expect(v).toEqual({ ok: false, caveat: "mode=readonly", reason: "uninterpretable" });
});

// ── Protocol tests ───────────────────────────────────────────────────────────

test("handleRequest returns parse error for invalid JSON", async () => {
  const resp = await handleRequest("not json");
  expect(resp.ok).toBe(false);
  expect(resp.error?.code).toBe("PARSE_ERROR");
});

test("handleRequest returns invalid request for missing id", async () => {
  const resp = await handleRequest(JSON.stringify({ method: "status" }));
  expect(resp.ok).toBe(false);
  expect(resp.error?.code).toBe("INVALID_REQUEST");
});

test("handleRequest returns invalid request for missing method", async () => {
  const resp = await handleRequest(JSON.stringify({ id: "1" }));
  expect(resp.ok).toBe(false);
  expect(resp.error?.code).toBe("INVALID_REQUEST");
});

test("handleRequest returns unknown method for bad method", async () => {
  const resp = await handleRequest(JSON.stringify({ id: "1", method: "not-a-method" }));
  expect(resp.ok).toBe(false);
  expect(resp.error?.code).toBe("UNKNOWN_METHOD");
});

test("handleStatus returns version and uptime", async () => {
  const result = await handleStatus({}) as { version: string; uptime: number; hasToken: boolean; allowlist: string[] };
  expect(result.version).toBe(VERSION);
  expect(typeof result.uptime).toBe("number");
  expect(result.uptime).toBeGreaterThanOrEqual(0);
  expect(Array.isArray(result.allowlist)).toBe(true);
});

test("status via handleRequest", async () => {
  const resp = await handleRequest(JSON.stringify({ id: "test-1", method: "status" }));
  expect(resp.ok).toBe(true);
  expect(resp.id).toBe("test-1");
  const result = resp.result as { version: string };
  expect(result.version).toBe(VERSION);
});

// ── Validation tests ─────────────────────────────────────────────────────────

test("repo: missing url returns error", async () => {
  const resp = await handleRequest(JSON.stringify({ id: "1", method: "repo", params: {} }));
  expect(resp.ok).toBe(false);
  expect(resp.error?.code).toBe("INVALID_PARAMS");
});

test("pr: missing repo returns error", async () => {
  const resp = await handleRequest(JSON.stringify({ id: "1", method: "pr", params: { number: 1 } }));
  expect(resp.ok).toBe(false);
  expect(resp.error?.code).toBe("INVALID_PARAMS");
});

test("pr: missing number returns error", async () => {
  const resp = await handleRequest(JSON.stringify({ id: "1", method: "pr", params: { repo: "a/b" } }));
  expect(resp.ok).toBe(false);
  expect(resp.error?.code).toBe("INVALID_PARAMS");
});

test("issue: missing repo returns error", async () => {
  const resp = await handleRequest(JSON.stringify({ id: "1", method: "issue", params: { number: 1 } }));
  expect(resp.ok).toBe(false);
  expect(resp.error?.code).toBe("INVALID_PARAMS");
});

test("fetch: missing url returns error", async () => {
  const resp = await handleRequest(JSON.stringify({ id: "1", method: "fetch", params: {} }));
  expect(resp.ok).toBe(false);
  expect(resp.error?.code).toBe("INVALID_PARAMS");
});

test("fetch: invalid url returns error", async () => {
  const resp = await handleRequest(JSON.stringify({ id: "1", method: "fetch", params: { url: "not-a-url" } }));
  expect(resp.ok).toBe(false);
  expect(resp.error?.code).toBe("INVALID_URL");
});

test("fetch: blocked host returns error", async () => {
  const resp = await handleRequest(JSON.stringify({ id: "1", method: "fetch", params: { url: "https://evil.com/file" } }));
  expect(resp.ok).toBe(false);
  expect(resp.error?.code).toBe("NOT_ALLOWED");
});

test("download: missing url returns error", async () => {
  const resp = await handleRequest(JSON.stringify({ id: "1", method: "download", params: {} }));
  expect(resp.ok).toBe(false);
  expect(resp.error?.code).toBe("INVALID_PARAMS");
});

test("download: blocked host returns error", async () => {
  const resp = await handleRequest(JSON.stringify({ id: "1", method: "download", params: { url: "https://malware.io/file" } }));
  expect(resp.ok).toBe(false);
  expect(resp.error?.code).toBe("NOT_ALLOWED");
});

// ── Token injection (SCOUT-POD: source-agnostic, no host path) ────────────────

const NO_FILE = "/nonexistent/scoutd-token-file";
const TOKEN_ENVS = ["SCOUTD_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"] as const;

/** Run fn with all token env vars cleared, restoring them (and the daemon's
 *  loaded token) afterward so global state never leaks across tests. */
async function withTokenEnv(
  set: Partial<Record<(typeof TOKEN_ENVS)[number], string>>,
  fn: () => Promise<void>,
): Promise<void> {
  const saved = Object.fromEntries(TOKEN_ENVS.map((k) => [k, process.env[k]]));
  try {
    for (const k of TOKEN_ENVS) delete process.env[k];
    for (const [k, v] of Object.entries(set)) process.env[k] = v;
    await fn();
  } finally {
    for (const k of TOKEN_ENVS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k]!;
    }
    loadToken(NO_FILE); // reset the daemon's token (no env, no file ⇒ null)
  }
}

const hasToken = async () =>
  ((await handleStatus({})) as { hasToken: boolean }).hasToken;

test("loadToken: an injected env secret is used with NO host file", async () => {
  await withTokenEnv({ SCOUTD_TOKEN: "ghs_injected_test_value" }, async () => {
    loadToken(NO_FILE);
    expect(await hasToken()).toBe(true);
  });
});

test("loadToken: GH_TOKEN and GITHUB_TOKEN are accepted too", async () => {
  await withTokenEnv({ GH_TOKEN: "gho_test" }, async () => {
    loadToken(NO_FILE);
    expect(await hasToken()).toBe(true);
  });
  await withTokenEnv({ GITHUB_TOKEN: "ghp_test" }, async () => {
    loadToken(NO_FILE);
    expect(await hasToken()).toBe(true);
  });
});

test("loadToken: no env + no file ⇒ no token (public only)", async () => {
  await withTokenEnv({}, async () => {
    loadToken(NO_FILE);
    expect(await hasToken()).toBe(false);
  });
});

// Note: We don't test actual GitHub API calls here (that requires network + token).
// Integration tests would run scoutd as a server and make real requests.
