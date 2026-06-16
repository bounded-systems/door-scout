/**
 * scoutd OCAP proof — the live-DENY teeth behind checkCaveats.
 *
 * Unlike scoutd.test.ts (which calls handleRequest in-process), this file boots
 * an ACTUAL listener using scoutd's exported `socketHandler` and speaks the
 * NDJSON wire protocol to it over a real socket. It proves that the scout door's
 * `host=` caveat is enforced at the door at runtime — a host outside the
 * allowlist is refused over the live socket, not merely by a unit matcher — and
 * that the denial is driven by the SAME caveat the rulebook (grantedDoorLines)
 * renders. This is the end-to-end "granted == enforced" guarantee.
 *
 * The denial path short-circuits before any egress, so this test makes no
 * network calls (the allow path is covered network-free by scoutd.test.ts).
 * Assumes the default allowlist (no SCOUTD_ALLOW / SCOUTD_PROXY override).
 *
 *   nix run nixpkgs#bun -- test tests/scoutd.ocap.test.ts
 */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { socketHandler, scoutDoor } from "../scoutd.ts";
import { grantedDoorLines } from "../guest-room/mod.ts";

// These tests assume the door carries its default host= caveat (direct egress).
const DEFAULT_DOOR_IN_FORCE = !process.env.SCOUTD_ALLOW && !process.env.SCOUTD_PROXY;

let port = 0;
let listener: { port: number; stop: (closeActive?: boolean) => void } | undefined;

beforeAll(() => {
  // Ephemeral TCP port; socketHandler enforces the module's scout door caveat.
  listener = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: socketHandler as never }) as {
    port: number;
    stop: (closeActive?: boolean) => void;
  };
  port = listener!.port;
});

afterAll(() => {
  listener?.stop(true);
});

/** Send one NDJSON request to the live door and resolve its parsed response. */
function rpc(
  method: string,
  params: Record<string, unknown> = {},
  timeoutMs = 8000,
): Promise<{ ok: boolean; result?: unknown; error?: { code: string; message: string } }> {
  const req = JSON.stringify({ id: "ocap-1", method, params }) + "\n";
  return new Promise((resolve, reject) => {
    let buf = "";
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(() => finish(() => reject(new Error(`door timed out: ${method}`))), timeoutMs);
    Bun.connect({
      hostname: "127.0.0.1",
      port,
      socket: {
        open(s) {
          s.write(req);
        },
        data(s, chunk) {
          buf += Buffer.from(chunk).toString("utf-8");
          const nl = buf.indexOf("\n");
          if (nl !== -1) {
            const line = buf.slice(0, nl);
            s.end();
            finish(() => resolve(JSON.parse(line)));
          }
        },
        error(_s, e) {
          finish(() => reject(e));
        },
      },
    }).catch((e) => finish(() => reject(e)));
  });
}

describe("scoutd OCAP proof (live door, default allowlist)", () => {
  test("default scout door caveat is in force for these tests", () => {
    expect(DEFAULT_DOOR_IN_FORCE).toBe(true);
    expect(scoutDoor.caveats?.[0]).toMatch(/^host=.*github\.com/);
  });

  test("the live door answers status (it is actually serving)", async () => {
    const resp = await rpc("status");
    expect(resp.ok).toBe(true);
    expect((resp.result as { allowlist: string[] }).allowlist).toContain("github.com");
  });

  // The OCAP teeth: a host outside the door's host= caveat is refused by the
  // LIVE door, not merely by a unit matcher.
  test("DENIES fetch of an out-of-caveat host over the live socket", async () => {
    const resp = await rpc("fetch", { url: "https://evil.example/payload" });
    expect(resp.ok).toBe(false);
    expect(resp.error?.code).toBe("NOT_ALLOWED");
  });

  test("DENIES download of an out-of-caveat host over the live socket", async () => {
    const resp = await rpc("download", { url: "https://malware.invalid/blob" });
    expect(resp.ok).toBe(false);
    expect(resp.error?.code).toBe("NOT_ALLOWED");
  });

  // granted == enforced: the rulebook the agent is handed and the live door's
  // refusal are the same caveat. evil.example is absent from the rendered
  // RESTRICTED line, and the live door refuses it.
  test("the live denial matches the rendered rulebook (one source of truth)", async () => {
    const [line] = grantedDoorLines([scoutDoor]);
    expect(line).toContain("RESTRICTED to: host=");
    expect(line).not.toContain("evil.example");
    const resp = await rpc("fetch", { url: "https://evil.example/x" });
    expect(resp.error?.code).toBe("NOT_ALLOWED");
  });
});
