// scoutd's `project` method (Projects v2, read-only) — the door that lets a
// box see a GitHub Projects v2 board (e.g. Front Desk) without holding a token
// itself. Mocks global fetch to test response shaping/pagination/error paths
// (the surrounding tests/scoutd.test.ts sticks to validation-only per its own
// note — this file is the deliberate exception, since GraphQL shaping logic is
// worth covering directly).
//
//   nix run nixpkgs#bun -- test tests/scoutd-project.test.ts
import { afterAll, describe, expect, test } from "bun:test";
import { handleProject } from "../scoutd.ts";

function graphQLResponse(data: unknown): Response {
  return new Response(JSON.stringify({ data }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

const boardFixture = {
  organization: {
    projectV2: {
      title: "Front Desk",
      items: {
        pageInfo: { hasNextPage: false, endCursor: null },
        nodes: [
          {
            content: {
              __typename: "Issue",
              number: 62,
              title: "front-desk-health: scorecard computation + CLI",
              url: "https://github.com/bounded-systems/gh-project-room/issues/62",
              state: "CLOSED",
              repository: { nameWithOwner: "bounded-systems/gh-project-room" },
            },
            fieldValues: {
              nodes: [
                { field: { name: "Status" }, name: "Done" },
                { field: { name: "Kind" }, name: "epic" },
                { field: { name: "Score" }, number: 3 },
              ],
            },
          },
          // A draft issue: no repo/number — must be filtered out.
          {
            content: null,
            fieldValues: { nodes: [] },
          },
        ],
      },
    },
  },
};

describe("handleProject", () => {
  const savedFetch = globalThis.fetch;
  afterAll(() => {
    globalThis.fetch = savedFetch;
  });

  test("shapes board items, flattening field values by name", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    globalThis.fetch = ((_url: string, init?: RequestInit) => {
      capturedBody = JSON.parse(init!.body as string);
      return Promise.resolve(graphQLResponse(boardFixture));
    }) as unknown as typeof fetch;

    const result = (await handleProject({ org: "bounded-systems", number: 2 })) as {
      title: string;
      items: Array<Record<string, unknown>>;
      pageInfo: { hasNextPage: boolean; endCursor: string | null };
    };

    expect(result.title).toBe("Front Desk");
    expect(result.items).toHaveLength(1); // the draft item was dropped
    expect(result.items[0]).toEqual({
      number: 62,
      title: "front-desk-health: scorecard computation + CLI",
      url: "https://github.com/bounded-systems/gh-project-room/issues/62",
      repo: "bounded-systems/gh-project-room",
      contentType: "Issue",
      state: "CLOSED",
      fields: { Status: "Done", Kind: "epic", Score: 3 },
    });
    expect(result.pageInfo).toEqual({ hasNextPage: false, endCursor: null });

    expect(capturedBody?.variables).toEqual({
      org: "bounded-systems",
      num: 2,
      first: 50,
      after: null,
    });
  });

  test("passes through first/after for pagination", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    globalThis.fetch = ((_url: string, init?: RequestInit) => {
      capturedBody = JSON.parse(init!.body as string);
      return Promise.resolve(graphQLResponse(boardFixture));
    }) as unknown as typeof fetch;

    await handleProject({ org: "bounded-systems", number: 2, first: 10, after: "cursor-1" });

    expect(capturedBody?.variables).toEqual({
      org: "bounded-systems",
      num: 2,
      first: 10,
      after: "cursor-1",
    });
  });

  test("caps first at 100 even if a larger value is requested", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    globalThis.fetch = ((_url: string, init?: RequestInit) => {
      capturedBody = JSON.parse(init!.body as string);
      return Promise.resolve(graphQLResponse(boardFixture));
    }) as unknown as typeof fetch;

    await handleProject({ org: "bounded-systems", number: 2, first: 500 });

    expect((capturedBody?.variables as { first: number }).first).toBe(100);
  });

  test("surfaces NOT_FOUND when the org has no such project number", async () => {
    globalThis.fetch = ((): Promise<Response> =>
      Promise.resolve(graphQLResponse({ organization: { projectV2: null } }))) as unknown as typeof fetch;

    let err: { code?: string } | undefined;
    try {
      await handleProject({ org: "bounded-systems", number: 999 });
    } catch (e) {
      err = e as { code?: string };
    }
    expect(err?.code).toBe("NOT_FOUND");
  });

  test("surfaces GraphQL errors as GITHUB_ERROR", async () => {
    globalThis.fetch = (() =>
      Promise.resolve(
        new Response(
          JSON.stringify({ errors: [{ message: "Could not resolve to an Organization" }] }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      )) as unknown as typeof fetch;

    let err: { code?: string; message?: string } | undefined;
    try {
      await handleProject({ org: "nonexistent-org", number: 2 });
    } catch (e) {
      err = e as { code?: string; message?: string };
    }
    expect(err?.code).toBe("GITHUB_ERROR");
    expect(err?.message).toContain("Could not resolve to an Organization");
  });
});
