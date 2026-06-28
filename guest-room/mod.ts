/**
 * @module
 * guest-room — a guest-agnostic room+door capability runtime.
 *
 * This module knows nothing about any particular guest: no guest identity, no
 * image, no container runtime. A ROOM is walls plus a furnished set of DOORS; a
 * DOOR is a single (name, socket) capability brokered by a daemon that holds the
 * authority the room never does. A door may be ATTENUATED — narrowed by opaque
 * caveats the broker enforces — and attenuation is append-only, so a door can
 * only ever be handed onward equally or more restricted, never wider. The room
 * hands its guest a RULEBOOK keyed to exactly the doors present — a card per
 * granted door (how to use it, and any restriction on it) and a card per denied
 * door (there is no rule; do not attempt).
 *
 * A consumer supplies the door CATALOG and the room bundles; guest-room resolves
 * grants, derives the honest granted/denied surface, and renders the rulebook
 * lines. The consumer keeps its own launch mechanics (which runtime, which
 * image, how state mounts) — those are the guest, not the room.
 *
 * Extraction note: this directory is a self-contained internal dependency. When
 * it graduates to its own repo, it moves as-is and consumers flip the import
 * path; nothing here names a guest — a test enforces that the engine source is
 * guest-agnostic, so the seam can't silently re-couple.
 */

/** A door name lands in a mount path (`/run/<name>.sock`) and an env var, so it
 *  must be path-safe — no `/`, no `..`, no injection into the mount spec. */
export const DOOR_NAME_RE = /^[a-z0-9][a-z0-9-]*$/;

// ── Door transport ───────────────────────────────────────────────────────────
// How a door socket is addressed. The capability model is transport-agnostic;
// the substrate (container, microVM, remote) determines which transport is used.
//
//   unix:  same-machine socket (container or native substrates)
//   vsock: cross-VM socket (microVM substrates)
//   tcp:   cross-network socket (distributed/remote doors)

/** Unix domain socket — same-machine, the current default. */
export type UnixTransport = { kind: "unix"; path: string };

/** Virtio socket — crosses the VM boundary (host CID 2, guest CID 3+). */
export type VsockTransport = { kind: "vsock"; cid: number; port: number };

/** TCP socket — crosses the network (remote doors). */
export type TcpTransport = { kind: "tcp"; host: string; port: number };

/** A door's transport address. */
export type DoorTransport = UnixTransport | VsockTransport | TcpTransport;

/** Construct a unix socket transport. */
export function unix(path: string): UnixTransport {
  return { kind: "unix", path };
}

/** Construct a vsock transport (for microVM substrates). */
export function vsock(cid: number, port: number): VsockTransport {
  return { kind: "vsock", cid, port };
}

/** Construct a tcp transport (for remote doors). */
export function tcp(host: string, port: number): TcpTransport {
  return { kind: "tcp", host, port };
}

/** Render a transport as a human-readable string (for logs/errors). */
export function transportString(t: DoorTransport): string {
  switch (t.kind) {
    case "unix": return t.path;
    case "vsock": return `vsock:${t.cid}:${t.port}`;
    case "tcp": return `tcp:${t.host}:${t.port}`;
  }
}

/** Environment variables (a map of names to values or undefined). */
export type Env = Record<string, string | undefined>;

/** Default host socket for a daemon, private-dir-first. Pure (no I/O) so door
 *  resolution stays testable; the launch site enforces the fail-closed
 *  world-writable-dir check. */
export function defaultHostSock(daemon: string, env: Env): string {
  return `${env.XDG_RUNTIME_DIR ?? "/tmp"}/${daemon}.sock`;
}

/** A door the room knows by name: canonical in-room path, env, and rulebook. */
export type DoorPreset = {
  flag: string; // the launcher sugar flag (e.g. "--keeper")
  inBox: string; // where the room looks for the socket
  env: string; // env var pointing the room at the in-room socket
  hostDefault: string; // host socket path (overridable so the same launch works across transports)
  grants: string; // one-line capability, for the manifest
  use: string; // rulebook when GRANTED — how the guest uses this door
  deny: string; // rulebook when DENIED — there is no rule; do not attempt
};

/** A door actually granted to a launch (resolved from a preset, or generic).
 *  Transport-agnostic: works across unix sockets, vsock (microVM), or tcp (remote). */
export type DoorGrant = {
  name: string;
  host: DoorTransport;   // broker side (where the daemon listens)
  guest: DoorTransport;  // in-box side (where the guest connects)
  env: string;           // env var pointing at the guest transport
  grants: string;        // one-line capability description
  use: string;           // rulebook when granted
  caveats?: string[];    // opaque constraints; engine carries, daemon enforces
};

// ── Attenuation ──────────────────────────────────────────────────────────────
// A door can be narrowed by appending caveats. Append-only: you can add
// constraints, never remove them, so authority is monotonically non-increasing.
// The engine carries caveats; it doesn't interpret them — that's the daemon's
// job. This separation keeps the engine guest-agnostic (no door-specific
// vocabulary) while enabling real capability attenuation.

/** Parse a caveat string (k=v or k:v format) into key and value. */
export function parseCaveat(s: string): { key: string; value: string } | null {
  const eq = s.indexOf("=");
  const colon = s.indexOf(":");
  const sep = eq >= 0 && (colon < 0 || eq < colon) ? eq : colon;
  if (sep < 1) return null; // no separator or empty key
  return { key: s.slice(0, sep), value: s.slice(sep + 1) };
}

/** The product's door catalog: the doors this kind of room can furnish. */
export type DoorCatalog = Record<string, DoorPreset>;

/** A room: a named bundle of doors for a KIND of work. */
export type RoomPreset = { doors: string[]; about: string };

/** The product's room catalog. */
export type RoomCatalog = Record<string, RoomPreset>;

/** Resolve a door by name to a concrete grant. A name in the catalog gets its
 *  canonical path + rulebook; any other name becomes a generic service door at
 *  /run/<name>.sock (you hold the door, not the service's keys). An explicit
 *  host transport overrides the default.
 *
 *  The hostOverride parameter accepts either a DoorTransport or a string (unix
 *  path) for backward compatibility. */
export function resolveDoor(
  catalog: DoorCatalog,
  name: string,
  hostOverride: DoorTransport | string | undefined,
  env: Env,
): DoorGrant {
  if (!DOOR_NAME_RE.test(name)) {
    throw new Error(`invalid door name "${name}" (expected [a-z0-9][a-z0-9-]*)`);
  }
  // Normalize hostOverride: string → unix transport
  const hostTransport: DoorTransport | undefined =
    hostOverride === undefined ? undefined :
    typeof hostOverride === "string" ? unix(hostOverride) :
    hostOverride;

  const known = catalog[name];
  if (known) {
    return {
      name,
      host: hostTransport ?? unix(known.hostDefault),
      guest: unix(known.inBox),
      env: known.env,
      grants: known.grants,
      use: known.use,
    };
  }
  const ENV = `${name.toUpperCase().replace(/-/g, "_")}_SOCK`;
  const guestPath = `/run/${name}.sock`;
  return {
    name,
    host: hostTransport ?? unix(env[ENV] ?? defaultHostSock(name, env)),
    guest: unix(guestPath),
    env: ENV,
    grants: `service door "${name}"`,
    use: `Reach the ${name} service at ${guestPath} ($${ENV}). You hold the door, not the service's keys.`,
  };
}

/** Attenuation — derive a strictly *narrower* door from one you already hold.
 *  A caveat is an opaque restriction (e.g. a single host, a read-only mode): the
 *  engine carries and renders it, but never interprets it — the broker behind
 *  the door enforces it, and the catalog owner owns its grammar. Append-only by
 *  construction, so authority is monotonically non-increasing: a holder can add
 *  caveats but never drop them, and so can pass a door onward (e.g. to a
 *  sub-room) only equally or more restricted, never wider. This is the
 *  object-capability attenuation rule; the caveats are macaroon-shaped. Blank
 *  caveats are dropped; attenuating by nothing returns the grant unchanged. */
export function attenuate(grant: DoorGrant, caveats: string[]): DoorGrant {
  const add = caveats.map((c) => c.trim()).filter(Boolean);
  if (!add.length) return grant;
  return { ...grant, caveats: [...(grant.caveats ?? []), ...add] };
}

// ── Enforcement ──────────────────────────────────────────────────────────────
// Attenuation is only real if the caveats a door carries are actually checked
// against each request — otherwise the rulebook says "RESTRICTED to: …" while
// nothing stops a wider call (granted ≠ enforced). This is the enforcement side
// of `attenuate`, and it keeps the same separation of concerns: the engine owns
// the COMBINATOR (conjunction across caveats + fail-closed on any caveat it
// cannot get a verdict for), and the broker behind the door owns the GRAMMAR
// (one verifier per caveat key it understands). The engine never reads a
// caveat's value, so it stays guest-agnostic; the verifiers carry no engine
// state, so policy stays with the broker that holds the authority.

/** Interprets ONE caveat's value against a request context, returning true iff
 *  the caveat is satisfied. Supplied by the broker (the catalog owner): it owns
 *  its value grammar (e.g. a comma-separated OR-set). The engine never inspects
 *  `value`. */
export type CaveatVerifier<Ctx> = (value: string, ctx: Ctx) => boolean;

/** The verifier set a broker registers — one per caveat key it understands. */
export type CaveatVerifiers<Ctx> = Record<string, CaveatVerifier<Ctx>>;

/** The verdict: allowed, or denied with the offending caveat and why. */
export type CaveatVerdict =
  | { ok: true }
  | { ok: false; caveat: string; reason: "unsatisfied" | "uninterpretable" };

/** Enforce a door's caveats against a request context. Fail-closed by
 *  construction — the OCAP guarantee that makes the rendered rulebook honest:
 *    - no caveats              → allowed (the door is unattenuated; the door's
 *                                mere reachability is the coarse capability)
 *    - a caveat won't parse    → DENIED ("uninterpretable")
 *    - no verifier for its key → DENIED ("uninterpretable") — you must not allow
 *                                what you cannot interpret
 *    - a verifier returns false → DENIED ("unsatisfied")
 *    - every caveat holds       → allowed
 *  Conjunction across caveats mirrors `attenuate`'s append-only rule: each added
 *  caveat can only narrow, so authority is monotonically non-increasing. The
 *  first failing caveat short-circuits and is the one reported. */
export function checkCaveats<Ctx>(
  grant: DoorGrant,
  ctx: Ctx,
  verifiers: CaveatVerifiers<Ctx>,
): CaveatVerdict {
  for (const raw of grant.caveats ?? []) {
    const parsed = parseCaveat(raw);
    if (!parsed) return { ok: false, caveat: raw, reason: "uninterpretable" };
    const verify = verifiers[parsed.key];
    if (!verify) return { ok: false, caveat: raw, reason: "uninterpretable" };
    if (!verify(parsed.value, ctx)) return { ok: false, caveat: raw, reason: "unsatisfied" };
  }
  return { ok: true };
}

// ── Signed grants (authority in transit) ─────────────────────────────────────
// On a unix transport the held reference IS the authority (you can't reach a
// socket you weren't handed). Across a vsock/tcp boundary you can't pass an fd,
// so reachability stops being authority and the authority must travel IN the
// grant: a signature the SERVING room verifies before honoring a call. See the
// consuming product's ADR-CAPABILITY-TRANSPORT and CONCIERGE.md §7.
//
// The engine stays key-agnostic: signing/verification are INJECTED functions
// (the issuer's signer lives outside the engine, in a dedicated signing door).
// The engine owns
// only the CANONICAL BYTES and the binding checks, so issuer and verifier agree
// on exactly what a signature covers. A signed grant is a bearer token, so it is
// bound to an `audience` (which room may present it), an `exp`, and a `nonce`.

/** The binding a signature covers alongside the grant's authority: who may
 *  present it, until when, a freshness nonce, and the issuer key id (the
 *  verifier selects the matching public key). */
export type GrantBinding = {
  audience: string; // room id permitted to present this grant
  exp: number; // expiry, epoch ms
  nonce: string; // single-use freshness token
  keyId: string; // issuer key identity
};

/** A DoorGrant plus the issuer binding + signature that make it authority in
 *  transit. `host` (broker-side) is deliberately NOT signed — only the granted
 *  reference and its constraints are. */
export type SignedGrant = DoorGrant & { binding: GrantBinding; signature: string };

export type GrantVerdict = { ok: true } | { ok: false; reason: string };

/** The canonical bytes a grant signature covers: the AUTHORITY-bearing fields
 *  (name, the guest reference being granted, sorted caveats) plus the full
 *  binding. Cosmetic fields (grants/use/env) and the broker-side `host` are
 *  excluded, so re-describing or re-homing a door cannot change what was signed.
 *  Issuer and verifier MUST compute these identically — hence one shared fn. */
export function grantSigningBytes(grant: DoorGrant, binding: GrantBinding): string {
  return JSON.stringify({
    name: grant.name,
    guest: grant.guest,
    caveats: [...(grant.caveats ?? [])].sort(),
    binding,
  });
}

/** Attach an issuer binding + signature to a grant. `sign` is injected — the
 *  engine never holds a key. */
export function signGrant(
  grant: DoorGrant,
  binding: GrantBinding,
  sign: (data: string) => string,
): SignedGrant {
  return { ...grant, binding, signature: sign(grantSigningBytes(grant, binding)) };
}

/** Verify a signed grant at the SERVING room before honoring a call. Order:
 *  signature (over the canonical bytes) → audience match → expiry. `verify` is
 *  injected (the verifier holds the issuer pubkey for `grant.binding.keyId`).
 *  Single-use of the nonce needs cross-call state, so it is the caller's job;
 *  `verifyGrant` reports the binding it accepted so the caller can record it.
 *  Pair with `checkCaveats` for full enforcement (signature THEN caveats). */
export function verifyGrant(
  grant: SignedGrant,
  ctx: { audience: string; now: number },
  verify: (data: string, signature: string) => boolean,
): GrantVerdict {
  if (!grant.signature || !grant.binding) return { ok: false, reason: "unsigned" };
  if (!verify(grantSigningBytes(grant, grant.binding), grant.signature)) {
    return { ok: false, reason: "bad-signature" };
  }
  if (grant.binding.audience !== ctx.audience) return { ok: false, reason: "audience-mismatch" };
  if (ctx.now > grant.binding.exp) return { ok: false, reason: "expired" };
  return { ok: true };
}

// ── Issuer keys (keyless, published-key verification) ────────────────────────
// A signed grant names its issuer key by `kid` (binding.keyId). Rather than
// pre-share a secret, a verifier holds the issuer's PUBLISHED public keys — a
// set the issuer can rotate (publish a new key, retire an old one). The verifier
// selects the key the grant names and validates against it: no shared secret,
// identity-by-published-key. This is the keyless model the project's release
// tooling already uses, adapted to a door system — the key set travels over a
// door, not an HTTPS discovery endpoint. The engine models only the set +
// selection; the crypto stays injected.

/** One published issuer public key, selected by `kid`. */
export type IssuerKey = { kid: string; publicKeyPem: string };

/** An issuer's published key set. Multiple entries support rotation/overlap. */
export type IssuerKeys = { keys: IssuerKey[] };

/** Select the public key a grant names (`binding.keyId`); null if unknown. */
export function resolveIssuerKey(keys: IssuerKeys, kid: string): IssuerKey | null {
  return keys.keys.find((k) => k.kid === kid) ?? null;
}

/** Verify a signed grant against an issuer's PUBLISHED key set (no shared
 *  secret): resolve `binding.keyId` in `keys`, then apply the same checks as
 *  `verifyGrant`. `verifyWith` is injected — (data, signature, publicKeyPem) →
 *  bool. An unknown `kid` fails closed (`unknown-key`). */
export function verifyGrantWithKeys(
  grant: SignedGrant,
  ctx: { audience: string; now: number },
  keys: IssuerKeys,
  verifyWith: (data: string, signature: string, publicKeyPem: string) => boolean,
): GrantVerdict {
  if (!grant.signature || !grant.binding) return { ok: false, reason: "unsigned" };
  const key = resolveIssuerKey(keys, grant.binding.keyId);
  if (!key) return { ok: false, reason: "unknown-key" };
  return verifyGrant(grant, ctx, (d, s) => verifyWith(d, s, key.publicKeyPem));
}

// ── Room attenuation ─────────────────────────────────────────────────────────
// attenuate() narrows ONE door handed onward; this is the same rule lifted to
// the SET of doors a parent hands to a sub-room. A child set attenuates from its
// parent iff every child door (a) exists in the parent and (b) is equally or
// more restricted — its caveats a SUPERSET of the parent door's. Dropping a
// parent caveat WIDENS authority and is refused. A name-only ⊆ check misses
// that case, so the engine owns this comparison to keep the invariant in one
// place. Append-only at the set level: a sub-room can only ever be narrower.

/** A door in the child set that breaks attenuation: either it has no counterpart
 *  in the parent, or it dropped one or more of the parent door's caveats. */
export type AttenuationViolation =
  | { door: string; reason: "absent-in-parent" }
  | { door: string; reason: "widened-caveats"; dropped: string[] };

/** The verdict of `attenuatesDoors`: true if child is a valid attenuation of parent, false with violations. */
export type AttenuationVerdict =
  | { ok: true }
  | { ok: false; violations: AttenuationViolation[] };

/** Does `child` attenuate from `parent`? True iff no child door widens authority
 *  — each exists in the parent and keeps all of the parent door's caveats (it
 *  may add more). Reports EVERY violation so the caller can explain the full
 *  refusal. Doors are matched by name; the parent is indexed by name (a parent
 *  listing a name twice keeps the last). */
export function attenuatesDoors(child: DoorGrant[], parent: DoorGrant[]): AttenuationVerdict {
  const parentByName = new Map(parent.map((d) => [d.name, d]));
  const violations: AttenuationViolation[] = [];
  for (const c of child) {
    const p = parentByName.get(c.name);
    if (!p) {
      violations.push({ door: c.name, reason: "absent-in-parent" });
      continue;
    }
    const childCaveats = new Set(c.caveats ?? []);
    const dropped = (p.caveats ?? []).filter((cav) => !childCaveats.has(cav));
    if (dropped.length) violations.push({ door: c.name, reason: "widened-caveats", dropped });
  }
  return violations.length ? { ok: false, violations } : { ok: true };
}

// ── Introduction (the concierge core) ────────────────────────────────────────
// Delegation by message, not by spawn: a consumer is INTRODUCED to a capability
// rather than inheriting it. A registry maps a capability to the providers that
// serve it (a door the provider listens on) under a liveness lease. `resolve`
// hands back the first live provider's door, attenuated by the caller's
// requested narrowing — never wider than the provider's ceiling — or null when
// nothing live serves it (fail closed). The engine owns this pure resolution;
// the broker (concierge daemon) owns the mutable registry, the clock, and the
// policy that pre-orders providers. See CONCIERGE.md.

/** A capability provider in the concierge registry: the door it serves (its
 *  ceiling authority) and its lease expiry (epoch ms). */
export type ProviderEntry = { capability: string; door: DoorGrant; expiresAt: number };

/** Live providers for a capability — those whose lease has not expired
 *  (expiresAt > now). Order is preserved so the daemon can pre-rank by policy. */
export function liveProviders(
  entries: ProviderEntry[],
  capability: string,
  now: number,
): ProviderEntry[] {
  return entries.filter((e) => e.capability === capability && e.expiresAt > now);
}

/** Introduce a consumer to a capability: the first live provider's door,
 *  attenuated by the caller's requested narrowing `want`. Append-only, so the
 *  result is never wider than the provider's ceiling. Returns null when no live
 *  provider serves it — a dead or absent capability is never silently granted. */
export function resolveProvider(
  entries: ProviderEntry[],
  capability: string,
  want: string[],
  now: number,
): DoorGrant | null {
  const live = liveProviders(entries, capability, now);
  if (!live.length) return null;
  return attenuate(live[0]!.door, want);
}

// ── Confinement ──────────────────────────────────────────────────────────────
// The property the whole design turns on: a capability never becomes durable
// authority owned by its holder. Authority is valid only while a live provider
// backs it, and only within that provider's ceiling — so it dies with the
// workcell (the lease lapses) and can never be captured wider than it was lent.
// This is the engine-side statement of "an agent does not become a new actor
// type": a held grant is a capability checked against the live registry, never a
// standing property of whoever holds it.
//
// TCB note: this proves the ALGEBRA of confinement (lease-gated + ceiling-bound)
// purely, and it is RELATIVE TO THE REGISTRY: it trusts each provider's declared
// ceiling. It does not prove (a) the runtime cannot stash a socket fd past
// teardown, nor (b) that a provider's ceiling was legitimate to register. Both
// reduce to the broker/substrate, not this engine: workcell isolation, the lease
// clock, and PROVIDER ADMISSION (who may register a door, and how its ceiling is
// bounded) are the broker's. A too-wide ceiling makes confinement vacuous at that
// root — the engine will faithfully attenuate from broken authority. The gap is
// named, not closed: see docs/authority-and-attenuation.md.

/** Is `held` a capability the concierge could legitimately have handed out at
 *  `now` — i.e. backed by a LIVE provider for `capability` and no wider than that
 *  provider's ceiling? False once every backing lease has lapsed (the capability
 *  does not outlive its provider) or if `held` widened past the ceiling (it was
 *  never a derivation the concierge could grant). Mirrors `resolveProvider`'s
 *  guarantee from the verification side: what was handed out stays confined. */
export function isConfined(
  held: DoorGrant,
  entries: ProviderEntry[],
  capability: string,
  now: number,
): boolean {
  const live = liveProviders(entries, capability, now);
  return live.some((p) => attenuatesDoors([held], [p.door]).ok);
}

/** Expand a named room to its door grants. Throws (fail closed, not a silent
 *  empty launch) if the room is unknown — a typo must never widen authority. */
export function expandRoom(
  rooms: RoomCatalog,
  catalog: DoorCatalog,
  name: string,
  env: Env,
): DoorGrant[] {
  const room = rooms[name];
  if (!room) {
    throw new Error(`unknown room "${name}" (known: ${Object.keys(rooms).join(", ")})`);
  }
  return room.doors.map((d) => resolveDoor(catalog, d, undefined, env));
}

/** The honest denial set: every catalog door NOT granted, minus any explicitly
 *  suppressed (e.g. an ambient-egress escape suppresses the "no network" denial
 *  so the surface can't claim there's no network when there is). */
export function deniedDoors(
  catalog: DoorCatalog,
  granted: Set<string>,
  suppress: Set<string> = new Set(),
): { name: string; flag: string; deny: string }[] {
  return Object.entries(catalog)
    .filter(([name]) => !granted.has(name) && !suppress.has(name))
    .map(([name, p]) => ({ name, flag: p.flag, deny: p.deny }));
}

// ── The rulebook the room hands its guest ────────────────────────────────────
// The room is credential-free by construction; the guest acts ONLY through the
// cards (doors) it holds. These render the cards: a line per granted door (how
// to translate this symbol) and a line per denied door (a symbol with no rule).

/** The preamble: "your authority is EXACTLY this, generated from the actual
 *  mounts, so it is ground truth." Parameterized by the workcell name. */
export function capabilityPreamble(workcell: string): string[] {
  return [
    `[${workcell} — capability surface for THIS launch]`,
    `You are running inside ${workcell}, a credential-free OCAP workcell. Your authority is EXACTLY the capabilities listed below — nothing is ambient. This list is generated from the actual mounts of this launch, so it is ground truth: if something is not GRANTED, you do not have it — do not attempt it and do not claim it succeeded.`,
  ];
}

/** One card per granted door: name, what it grants, and how to use it. An
 *  attenuated door also states its restriction, so the surface stays honest —
 *  a narrowed door must not read as if it were the full grant. */
export function grantedDoorLines(doors: DoorGrant[]): string[] {
  return doors.map((d) => {
    const card = `- ${d.name}: ${d.grants}. ${d.use}`;
    return d.caveats?.length
      ? `${card} RESTRICTED to: ${d.caveats.join("; ")} — requests outside this are denied.`
      : card;
  });
}

/** The DENIED section: a card per absent door (no rule; do not attempt), or an
 *  explicit "nothing named" note that authority is still only what's granted. */
export function deniedDoorSection(denied: { name: string; deny: string }[]): string[] {
  if (!denied.length) {
    return ["DENIED: nothing named — but authority is still ONLY what is GRANTED above."];
  }
  return [
    "DENIED (the capability is physically absent from this box — do not attempt):",
    ...denied.map((d) => `- ${d.name}: ${d.deny}`),
  ];
}
