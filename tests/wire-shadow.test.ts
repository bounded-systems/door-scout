import { expect, test } from "bun:test";
import { __setWireManifest, shadowCheckParams } from "../scoutd.ts";

test("shadowCheckParams: log-only, warns on undeclared params, allows kind", () => {
  __setWireManifest({
    methods: ["repo"],
    params: { repo: ["url", "ref"] },
  });
  const warns: string[] = [];
  const orig = console.warn;
  console.warn = (m?: unknown) => void warns.push(String(m));
  try {
    shadowCheckParams("repo", { kind: "repo", url: "x", ref: "main" });
    expect(warns.length).toBe(0);
    shadowCheckParams("repo", { url: "x", bogusField: 1 });
    expect(warns.some((w) => w.includes("bogusField"))).toBe(true);
    shadowCheckParams("status", { anything: 1 }); // not in agreement → skipped
  } finally {
    console.warn = orig;
    __setWireManifest(null);
  }
  shadowCheckParams("repo", { whatever: 1 }); // no manifest → no-op
});
