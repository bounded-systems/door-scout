/**
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

import type { Socket } from "bun";

// ── Protocol types (shared across all doors) ────────────────────────────────

export type RequestEnvelope = {
  id: string;
  method: string;
  params?: Record<string, unknown>;
};

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

// ── Connection handler ──────────────────────────────────────────────────────

export type MethodHandler = (
  params: Record<string, unknown>,
) => Promise<unknown> | unknown;

export type MethodRegistry = Record<string, MethodHandler>;

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
): {
  open: (socket: Socket<Cx>) => void;
  data: (socket: Socket<Cx>, chunk: Uint8Array) => void;
  close: (socket: Socket<Cx>) => void;
  error: (socket: Socket<Cx>, error: Error) => void;
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
        const response = await handleLine(line, methods, log);
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
): Promise<ResponseEnvelope> {
  let req: RequestEnvelope;
  try {
    req = JSON.parse(line) as RequestEnvelope;
  } catch {
    return err("?", "PARSE_ERROR", "invalid JSON");
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
 * Send a request to a door daemon and wait for the response.
 *
 * @example
 *   const result = await call("/run/myservice.sock", "greet", { name: "world" });
 */
export async function call<T = unknown>(
  socketPath: string,
  method: string,
  params: Record<string, unknown> = {},
): Promise<T> {
  const id = crypto.randomUUID();
  const req: RequestEnvelope = { id, method, params };

  return new Promise((resolve, reject) => {
    let buffer = "";
    const socket = Bun.connect({
      unix: socketPath,
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
