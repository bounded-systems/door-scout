// scoutd's org-wide reads — `repos`, `orgOpenWork`, `orgMergedPrs` (Projects v2
// sweeps that let a box see the org's work without holding a token). Mocks global
// fetch, dispatching by GraphQL query text, to cover shaping + the fail-closed
// visibility filter + per-repo resilience.
//
//   nix run nixpkgs#bun -- test tests/scoutd-org.test.ts
import { afterAll, describe, expect, test } from "bun:test";
import {
  handleOrgMergedPrs,
  handleOrgOpenWork,
  handleRepos,
} from "../scoutd.ts";

function gql(data: unknown): Response {
  return new Response(JSON.stringify({ data }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function gqlError(message: string): Response {
  return new Response(JSON.stringify({ errors: [{ message }] }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

type Route = { match: (query: string) => boolean; resp: () => Response };

function routeByQuery(routes: Route[]): typeof fetch {
  return ((_url: string, init?: RequestInit) => {
    const body = JSON.parse(init!.body as string) as { query: string };
    const route = routes.find((r) => r.match(body.query));
    return Promise.resolve(route ? route.resp() : gql({}));
  }) as unknown as typeof fetch;
}

const reposPage = (nodes: unknown[]) => ({
  organization: {
    repositories: { pageInfo: { hasNextPage: false, endCursor: null }, nodes },
  },
});

describe("handleRepos", () => {
  const saved = globalThis.fetch;
  afterAll(() => {
    globalThis.fetch = saved;
  });

  test("fail-closed: only explicitly-public repos by default", async () => {
    globalThis.fetch = routeByQuery([{
      match: (q) => q.includes("repositories("),
      resp: () =>
        gql(reposPage([
          { id: "R_pub", name: "pub", isPrivate: false },
          { id: "R_priv", name: "priv", isPrivate: true },
        ])),
    }]);
    const res = await handleRepos({ org: "o" }) as { repos: unknown[] };
    expect(res.repos).toEqual([{ id: "R_pub", name: "pub", isPrivate: false }]);
  });

  test("includePrivate returns private repos too", async () => {
    globalThis.fetch = routeByQuery([{
      match: (q) => q.includes("repositories("),
      resp: () =>
        gql(reposPage([
          { id: "R_pub", name: "pub", isPrivate: false },
          { id: "R_priv", name: "priv", isPrivate: true },
        ])),
    }]);
    const res = await handleRepos(
      { org: "o", includePrivate: true },
    ) as { repos: Array<{ name: string }> };
    expect(res.repos.map((r) => r.name)).toEqual(["pub", "priv"]);
  });

  test("rejects a missing org", async () => {
    let code: string | undefined;
    try {
      await handleRepos({});
    } catch (e) {
      code = (e as { code?: string }).code;
    }
    expect(code).toBe("INVALID_PARAMS");
  });
});

describe("handleOrgOpenWork", () => {
  const saved = globalThis.fetch;
  afterAll(() => {
    globalThis.fetch = saved;
  });

  test("shapes issues + PRs across the org's repos", async () => {
    globalThis.fetch = routeByQuery([
      {
        match: (q) => q.includes("repositories("),
        resp: () => gql(reposPage([{ id: "R", name: "repo-a", isPrivate: false }])),
      },
      {
        match: (q) => q.includes("conn:") && q.includes("issues("),
        resp: () =>
          gql({
            repository: {
              conn: {
                pageInfo: { hasNextPage: false, endCursor: null },
                nodes: [{
                  id: "I1",
                  number: 1,
                  title: "iss",
                  labels: { nodes: [{ name: "bug" }] },
                  subIssues: { totalCount: 2 },
                }],
              },
            },
          }),
      },
      {
        match: (q) => q.includes("conn:") && q.includes("pullRequests("),
        resp: () =>
          gql({
            repository: {
              conn: {
                pageInfo: { hasNextPage: false, endCursor: null },
                nodes: [{ id: "P1", number: 2, title: "pr", labels: { nodes: [] } }],
              },
            },
          }),
      },
    ]);

    const work = await handleOrgOpenWork({ org: "o" }) as {
      items: unknown[];
      skipped: unknown[];
    };
    expect(work.skipped).toEqual([]);
    expect(work.items).toEqual([
      {
        id: "I1",
        kind: "Issue",
        repo: "repo-a",
        number: 1,
        title: "iss",
        labels: ["bug"],
        hasSubIssues: true,
      },
      {
        id: "P1",
        kind: "PullRequest",
        repo: "repo-a",
        number: 2,
        title: "pr",
        labels: [],
        hasSubIssues: false,
      },
    ]);
  });

  test("a repo whose read fails is skipped, not fatal", async () => {
    globalThis.fetch = routeByQuery([
      {
        match: (q) => q.includes("repositories("),
        resp: () => gql(reposPage([{ id: "R", name: "repo-a", isPrivate: false }])),
      },
      // both the subIssues attempt and the retry hit this → repo is skipped
      { match: (q) => q.includes("conn:"), resp: () => gqlError("boom") },
    ]);
    const work = await handleOrgOpenWork({ org: "o" }) as {
      items: unknown[];
      skipped: Array<{ repo: string; reason: string }>;
    };
    expect(work.items).toEqual([]);
    expect(work.skipped).toEqual([
      { repo: "repo-a", reason: expect.stringContaining("boom") },
    ]);
  });
});

describe("handleOrgMergedPrs", () => {
  const saved = globalThis.fetch;
  afterAll(() => {
    globalThis.fetch = saved;
  });

  test("shapes merged PRs with closing-issue counts", async () => {
    globalThis.fetch = routeByQuery([
      {
        match: (q) => q.includes("repositories("),
        resp: () => gql(reposPage([{ id: "R", name: "repo-a", isPrivate: false }])),
      },
      {
        match: (q) => q.includes("pullRequests(") && q.includes("MERGED"),
        resp: () =>
          gql({
            repository: {
              pullRequests: {
                pageInfo: { hasNextPage: false, endCursor: null },
                nodes: [{
                  number: 5,
                  title: "merged",
                  author: { login: "alice" },
                  labels: { nodes: [{ name: "x" }] },
                  closingIssuesReferences: { totalCount: 1 },
                }],
              },
            },
          }),
      },
    ]);
    const merged = await handleOrgMergedPrs({ org: "o" }) as { items: unknown[] };
    expect(merged.items).toEqual([{
      repo: "repo-a",
      number: 5,
      title: "merged",
      authorLogin: "alice",
      labels: ["x"],
      closingIssueCount: 1,
    }]);
  });
});
