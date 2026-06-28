// grant-gate tests — scoutd's transit-grant gate (tcp/vsock only). On unix the
// held reference is authority (gate off); on tcp/vsock a request must carry a
// signed grant that verifies against the concierge's published keys, for THIS
// room (ROOM_ID) and door ("scout").
//
//   nix run nixpkgs#bun -- test tests/grant-gate.test.ts
import { test, expect, describe, beforeEach, afterAll } from "bun:test";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { signGrant, unix, type DoorGrant, type GrantBinding, type IssuerKeys, type SignedGrant } from "../guest-room/mod.ts";
import { gateGrant, __setGrantRequired, __setIssuerKeys } from "../scoutd.ts";
import type { RequestEnvelope } from "../scoutd.ts";

const kp = generateKeyPairSync("ed25519");
const pem = kp.publicKey.export({ type: "spki", format: "pem" }) as string;
const sign = (d: string): string => nodeSign(null, Buffer.from(d), kp.privateKey).toString("base64");
const keys: IssuerKeys = { keys: [{ kid: "k1", publicKeyPem: pem }] };

const scoutDoor: DoorGrant = {
  name: "scout",
  host: unix("/tmp/scoutd.sock"),
  guest: unix("/run/doors/scoutd.sock"),
  env: "SCOUTD_SOCK",
  grants: "external reads",
  use: "read via scout",
};
const grant = (over: Partial<GrantBinding> = {}, door = scoutDoor): SignedGrant =>
  signGrant(door, { audience: "room-A", exp: Date.now() + 60_000, nonce: "n1", keyId: "k1", ...over }, sign);
const req = (g?: SignedGrant): RequestEnvelope => ({ id: "1", method: "fetch", grant: g });

beforeEach(() => {
  process.env.ROOM_ID = "room-A";
  __setGrantRequired(true);
  __setIssuerKeys(keys); // pre-seed so the gate doesn't dial a live concierge
});
afterAll(() => __setGrantRequired(false));

describe("scoutd transit-grant gate", () => {
  test("unix mode (gate off): any request passes — the held reference is authority", async () => {
    __setGrantRequired(false);
    expect((await gateGrant(req(undefined))).ok).toBe(true);
  });

  test("tcp: a valid grant for this room and door is accepted", async () => {
    expect(await gateGrant(req(grant()))).toEqual({ ok: true });
  });

  test("tcp: no grant is rejected", async () => {
    expect(await gateGrant(req(undefined))).toEqual({ ok: false, reason: "no-grant" });
  });

  test("tcp: a grant for another door is rejected", async () => {
    const keeper = grant({}, { ...scoutDoor, name: "keeper" });
    expect(await gateGrant(req(keeper))).toEqual({ ok: false, reason: "wrong-door" });
  });

  test("tcp: a grant minted for another room is rejected (audience)", async () => {
    expect((await gateGrant(req(grant({ audience: "room-B" })))).reason).toBe("audience-mismatch");
  });

  test("tcp: an expired grant is rejected", async () => {
    expect((await gateGrant(req(grant({ exp: Date.now() - 1_000 })))).reason).toBe("expired");
  });
});
