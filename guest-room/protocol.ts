/**
 * @module
 * door-protocol.ts — the generic door protocol (JSON-over-socket).
 *
 * Every door daemon speaks the same wire format:
 *   - Newline-delimited JSON
 *   - Request envelope: { id, method, params? }
 *   - Response envelope: { id, ok, result?, error? }
 *
 * This module extracts the protocol so daemons stay focused on their domain
 * logic (what methods they handle), not the envelope parsing.
 */

import { Buffer } from "node:buffer";
import { createHmac } from "node:crypto";
import { verifyGrantWithKeys, type SignedGrant, type IssuerKeys } from "./mod.ts";

// This module's server half is transport-neutral; its client half (`call`)
// targets Bun's socket API. Rather than depend on `@types/bun` (a bare "bun"
// specifier JSR cannot resolve), we declare the minimal structural surface we
// touch locally — Bun's real types are structurally assignable, so consumers on
// Bun are unaffected and the module carries no unresolvable dependency.

/** The subset of a connection socket the server handlers use: a per-connection
 *  `data` bag plus `write`. Bun's `Socket<Cx>` is structurally assignable. */
export interface DoorSocket<Cx> {
  /** Per-connection state bag (context data). */
  data: Cx;
  /** Write data (string or bytes) to the socket; returns bytes written. */
  write(data: string | Uint8Array): number;
}

/** The subset of a Bun client socket `call` uses. */
interface ClientSocket {
  write(data: string | Uint8Array): number;
  end(): void;
}

/** Bun's runtime global, declared locally with only the shape `call` needs (so
 *  the module type-checks without @types/bun). At runtime this is Bun's global,
 *  so `call` runs under the Bun runtime. */
declare const Bun: {
  connect(options: {
    unix: string;
    socket: {
      data(socket: ClientSocket, chunk: Uint8Array): void;
      open(socket: ClientSocket): void;
      error(socket: ClientSocket, error: Error): void;
      close(socket: ClientSocket): void;
    };
  }): Promise<{ catch(onrejected: (reason: unknown) => void): unknown }>;
};

// ── Protocol types (shared across all doors) ────────────────────────────────

/** JSON-RPC 2.0-like request envelope: method call with id, method name, and optional params. */
export type RequestEnvelope = {
  id: string;
  method: string;
  params?: Record<string, unknown>;
  /** Optional per-request authenticator. On a unix socket the kernel vouches for
   *  the peer (filesystem perms + peer credentials), so this is unused; on a
   *  tcp/vsock door — where the kernel gives no peer identity — the broker can
   *  require it (see {@link tokenAuthorizer}) so "only the intended guest can
   *  knock" survives the move off the filesystem. A bearer token today; an
   *  HMAC-over-the-request later, same field. */
  auth?: string;
  /** Optional SIGNED grant the caller presents to a tcp/vsock serving room (see
   *  {@link signedGrantAuthorizer}): on those transports a reachable socket is
   *  not authority, so authority rides in this signed, audience/exp/nonce-bound
   *  grant. Unused on a unix door (the held reference IS the authority). */
  grant?: SignedGrant;
};

/** Response envelope: result (if ok=true) or error object (if ok=false). */
export type ResponseEnvelope = {
  id: string;
  ok: boolean;
  result?: unknown;
  error?: { code: string; message: string };
};

// ── Response helpers ────────────────────────────────────────────────────────

/** Create a success response */
export function ok(id: string, result?: unknown): ResponseEnvelope {
  return { id, ok: true, result };
}

/** Create an error response */
export function err(id: string, code: string, message: string): ResponseEnvelope {
  return { id, ok: false, error: { code, message } };
}

// ── Authentication helpers ───────────────────────────────────────────────────
// A unix-socket door is authenticated by the kernel: filesystem permissions gate
// it and the broker can read the peer's credentials. A tcp/vsock door has no such
// gate — anyone who can route to it can connect — so the authority a unix socket
// carried for free has to be reconstructed on the wire. These give a broker a
// minimal, fail-closed way to do that. The grammar is intentionally tiny; the
// engine of policy stays the broker's.

/** Constant-time string equality: compares every byte regardless of where the
 *  first difference falls, so comparison time doesn't leak how much of a secret
 *  matched. Unequal lengths return false without short-circuiting on content. */
export function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf-8");
  const bb = Buffer.from(b, "utf-8");
  let diff = ab.length ^ bb.length;
  const len = Math.max(ab.length, bb.length);
  for (let i = 0; i < len; i++) diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  return diff === 0;
}

/** A bearer-token {@link RequestAuthorizer}: accept a request iff it carries
 *  exactly `expected` in its `auth` field (constant-time compared). This is the
 *  per-launch token a tcp/vsock door needs so only the intended guest can knock —
 *  the wire-level stand-in for the kernel peer-authentication a unix socket gives
 *  for free. It proves possession of the secret, but the secret travels on every
 *  request, so a captured request can be REPLAYED verbatim. {@link hmacAuthorizer}
 *  closes that — same signature, stronger proof. */
export function tokenAuthorizer(expected: string): RequestAuthorizer {
  return (req) => typeof req.auth === "string" && constantTimeEqual(req.auth, expected);
}

/** The bytes an HMAC signs: the request's identity-bearing content, with object
 *  keys sorted so client and server canonicalize identically. `auth` itself is
 *  excluded (it's the signature). Including `id` (a fresh per-request UUID) binds
 *  the signature to THIS request, which is what makes replay detectable. */
export function canonicalRequest(req: RequestEnvelope): string {
  return stableStringify({ id: req.id, method: req.method, params: req.params ?? {} });
}

/** Deterministic JSON: object keys sorted recursively, so the same logical value
 *  always serializes to the same string (plain JSON.stringify is key-order
 *  dependent, which would make two equal requests produce different MACs). */
function stableStringify(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return "[" + v.map(stableStringify).join(",") + "]";
  const o = v as Record<string, unknown>;
  return "{" + Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + stableStringify(o[k])).join(",") + "}";
}

/** A client-side signer for `call`'s `sign` option: produces the hex HMAC-SHA256
 *  of {@link canonicalRequest} under the per-launch `key`. Pair it with
 *  {@link hmacAuthorizer} holding the same key on the broker. */
export function hmacSigner(key: string): (req: RequestEnvelope) => string {
  return (req) => createHmac("sha256", key).update(canonicalRequest(req)).digest("hex");
}

/** An HMAC-per-request {@link RequestAuthorizer}: accept a request iff its `auth`
 *  is a valid HMAC-SHA256 of the request content under `key` AND its `id` has not
 *  been seen before. The key never travels — only a signature over THIS request —
 *  so a captured request can't be reused (the signature is right, but its `id` is
 *  already spent) and can't be tampered (any change to method/params breaks the
 *  MAC). Replay state is the broker's: a bounded FIFO of recent ids (`replayCap`,
 *  default 4096); on a per-launch key this is all the window you need. */
export function hmacAuthorizer(key: string, opts: { replayCap?: number } = {}): RequestAuthorizer {
  const cap = opts.replayCap ?? 4096;
  const seen = new Set<string>();
  const order: string[] = [];
  return (req) => {
    if (typeof req.auth !== "string") return false;
    const expected = createHmac("sha256", key).update(canonicalRequest(req)).digest("hex");
    if (!constantTimeEqual(req.auth, expected)) return false;
    if (seen.has(req.id)) return false; // replay: this request was already served
    seen.add(req.id);
    order.push(req.id);
    if (order.length > cap) seen.delete(order.shift()!);
    return true;
  };
}

/** A SIGNED-GRANT {@link RequestAuthorizer}: accept a request iff it carries a
 *  `grant` that verifies against the issuer's PUBLISHED keys (verifyGrantWithKeys)
 *  for THIS serving room. The transport-split answer for tcp/vsock doors — where
 *  the kernel gives no peer identity — authority rides in the grant, not the
 *  socket. Keyless: the room holds the issuer's published key set (fetched from
 *  the concierge), no shared secret. `verifyWith` does the crypto (injected);
 *  `now` defaults to wall-clock. When `door` is set, the grant's `name` must
 *  match it, so a grant minted for one door can't be presented at another. */
export function signedGrantAuthorizer(opts: {
  keys: IssuerKeys;
  audience: string;
  verifyWith: (data: string, signature: string, publicKeyPem: string) => boolean;
  now?: () => number;
  door?: string;
}): RequestAuthorizer {
  const clock = opts.now ?? (() => Date.now());
  return (req) => {
    const grant = req.grant;
    if (!grant) return false;
    if (opts.door !== undefined && grant.name !== opts.door) return false;
    return verifyGrantWithKeys(grant, { audience: opts.audience, now: clock() }, opts.keys, opts.verifyWith).ok;
  };
}

// ── Connection handler ──────────────────────────────────────────────────────

/** A method handler: takes params and returns a result (sync or async). */
export type MethodHandler = (
  params: Record<string, unknown>,
) => Promise<unknown> | unknown;

/** Registry of method handlers (name → handler). */
export type MethodRegistry = Record<string, MethodHandler>;

/** Decides whether a parsed request is allowed to be served at all — checked
 *  BEFORE method dispatch, so an unauthenticated peer reaches no handler. The
 *  broker supplies it (the policy is the broker's); when omitted, no
 *  authentication is required and every well-formed request is dispatched (the
 *  unix-socket default, where the kernel already authenticated the peer). */
export type RequestAuthorizer = (req: RequestEnvelope) => boolean;

/**
 * Create socket handlers for a door daemon.
 *
 * @example
 *   const handlers = createDoorHandlers("myservice", {
 *     greet: async (params) => ({ message: `Hello, ${params.name}` }),
 *   }, log);
 *   listen({ unix: "/run/myservice.sock", socket: handlers });
 */
export function createDoorHandlers<Cx extends { buffer: string }>(
  name: string,
  methods: MethodRegistry,
  log: (level: "INFO" | "ERR" | "ALLOW" | "DENY" | "WARN", msg: string) => void,
  authorize?: RequestAuthorizer,
): {
  open: (socket: DoorSocket<Cx>) => void;
  data: (socket: DoorSocket<Cx>, chunk: Uint8Array) => void;
  close: (socket: DoorSocket<Cx>) => void;
  error: (socket: DoorSocket<Cx>, error: Error) => void;
} {
  return {
    open(socket) {
      socket.data = { buffer: "" } as Cx;
    },

    async data(socket, chunk) {
      socket.data.buffer += Buffer.from(chunk).toString("utf-8");
      const lines = socket.data.buffer.split("\n");
      socket.data.buffer = lines.pop()!; // Keep incomplete line

      for (const line of lines) {
        if (!line.trim()) continue;
        const response = await handleLine(line, methods, log, authorize);
        socket.write(JSON.stringify(response) + "\n");
      }
    },

    close(_socket) {
      // Nothing to clean up in the generic case
    },

    error(_socket, error) {
      log("ERR", `socket error: ${error.message}`);
    },
  };
}

async function handleLine(
  line: string,
  methods: MethodRegistry,
  log: (level: "INFO" | "ERR" | "ALLOW" | "DENY" | "WARN", msg: string) => void,
  authorize?: RequestAuthorizer,
): Promise<ResponseEnvelope> {
  let req: RequestEnvelope;
  try {
    req = JSON.parse(line) as RequestEnvelope;
  } catch {
    return err("?", "PARSE_ERROR", "invalid JSON");
  }

  // Authenticate before dispatch — an unauthorized peer must reach no handler.
  // Fail-closed: if the broker required auth, a request that doesn't satisfy it
  // is denied without leaking why (no method/handler probing). When no authorizer
  // is configured, every well-formed request proceeds (unix-socket default).
  if (authorize && !authorize(req)) {
    log("DENY", `unauthenticated request: ${req.method}`);
    return err(req.id, "UNAUTHENTICATED", "request rejected");
  }

  const handler = methods[req.method];
  if (!handler) {
    log("ERR", `unknown method: ${req.method}`);
    return err(req.id, "UNKNOWN_METHOD", `unknown method: ${req.method}`);
  }

  try {
    const result = await handler(req.params ?? {});
    return ok(req.id, result);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    log("ERR", `${req.method}: ${message}`);
    return err(req.id, "HANDLER_ERROR", message);
  }
}

// ── Client helper ───────────────────────────────────────────────────────────

/**
 * Resolve a door endpoint to a Bun.connect target. A leading "/" (optionally
 * `unix://`) is a unix socket path; otherwise `host:port` (optionally `tcp://`)
 * is a TCP target — so the same client reaches a mounted unix socket (Linux/pod)
 * or a host-gateway / pod-local TCP port (e.g. macOS, where virtiofs can't share
 * a unix socket across the host↔VM boundary). A path containing ":" stays unix.
 */
function connectTarget(endpoint: string): { unix: string } | { hostname: string; port: number } {
  const stripped = endpoint.replace(/^unix:\/\//, "");
  if (!stripped.startsWith("/")) {
    const m = stripped.replace(/^tcp:\/\//, "").match(/^([^/\s]+):(\d{1,5})$/);
    if (m) return { hostname: m[1]!, port: Number(m[2]) };
  }
  return { unix: stripped };
}

/**
 * Send a request to a door daemon and wait for the response. The endpoint is a
 * unix socket path or a `host:port` TCP target (see {@link connectTarget}).
 *
 * Authenticate against a broker that fronts a tcp/vsock door: pass a fixed
 * `opts.auth` bearer token (matched by {@link tokenAuthorizer}), or — preferred —
 * `opts.sign` to compute a per-request signature over the assembled envelope
 * (use {@link hmacSigner}, matched by {@link hmacAuthorizer}). `sign` takes
 * precedence over `auth`. Both are harmless (ignored) on an unauthenticated unix
 * door.
 *
 * @example
 *   const result = await call("/run/myservice.sock", "greet", { name: "world" });
 *   const viaTcp  = await call("host.containers.internal:3002", "greet", { name: "world" }, { auth: token });
 *   const signed  = await call("host.containers.internal:3002", "greet", { name: "world" }, { sign: hmacSigner(key) });
 */
export async function call<T = unknown>(
  endpoint: string,
  method: string,
  params: Record<string, unknown> = {},
  opts: { auth?: string; sign?: (req: RequestEnvelope) => string } = {},
): Promise<T> {
  const id = crypto.randomUUID();
  const req: RequestEnvelope = { id, method, params };
  const auth = opts.sign ? opts.sign(req) : opts.auth;
  if (auth !== undefined) req.auth = auth;

  return new Promise((resolve, reject) => {
    let buffer = "";
    const socket = Bun.connect({
      ...connectTarget(endpoint),
      socket: {
        data(_socket, chunk) {
          buffer += Buffer.from(chunk).toString("utf-8");
          const idx = buffer.indexOf("\n");
          if (idx !== -1) {
            const line = buffer.slice(0, idx);
            try {
              const resp = JSON.parse(line) as ResponseEnvelope;
              if (resp.ok) {
                resolve(resp.result as T);
              } else {
                reject(new Error(resp.error?.message ?? "unknown error"));
              }
            } catch (e) {
              reject(e);
            }
            _socket.end();
          }
        },
        open(socket) {
          socket.write(JSON.stringify(req) + "\n");
        },
        error(_socket, error) {
          reject(error);
        },
        close() {},
      },
    });
    socket.catch(reject);
  });
}
