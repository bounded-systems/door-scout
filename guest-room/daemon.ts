/**
 * daemon.ts — shared utilities for door daemons.
 *
 * Every daemon follows the same pattern:
 *   - Listens on a unix socket (or TCP for testing)
 *   - CLI: `<name> serve [--socket PATH]`
 *   - Logs to stdout with timestamp + level
 *
 * This module extracts the common pieces so daemons stay focused on their
 * service logic (what the door DOES), not the transport boilerplate.
 *
 * The socket path is parameterized: consumers pass their own `runDir` function
 * so this module stays guest-agnostic (no product paths like ~/.foo-box).
 */

import { mkdirSync, unlinkSync } from "node:fs";

export type Env = Record<string, string | undefined>;

/** Function to determine the run directory for sockets. */
export type RunDirFn = (env: Env) => string;

/**
 * Default socket path for a daemon.
 *
 * @param name - daemon name (e.g., "keeper")
 * @param runDir - function returning the directory for sockets
 * @param env - environment variables
 */
export function defaultSocketPath(
  name: string,
  runDir: RunDirFn,
  env: Env = process.env,
): string {
  // XDG_RUNTIME_DIR takes precedence (systemd convention)
  const runtime = env.XDG_RUNTIME_DIR;
  if (runtime) return `${runtime}/${name}.sock`;

  const dir = runDir(env);
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch {
    // Already exists or no permission — serve() will fail if unusable
  }
  return `${dir}/${name}.sock`;
}

/**
 * Prepare a unix socket path for listening: unlink any stale socket file.
 * Returns the path for use in `listen({ unix: ... })`.
 */
export function prepareSocket(path: string): string {
  try {
    unlinkSync(path);
  } catch {
    // File doesn't exist — fine
  }
  return path;
}

/**
 * Structured log line: `<name> <ISO timestamp> <level> <message>`
 */
export function log(
  name: string,
  level: "INFO" | "ALLOW" | "DENY" | "ERR" | "WARN",
  message: string,
): void {
  process.stdout.write(`${name} ${new Date().toISOString()} ${level} ${message}\n`);
}

/**
 * Create a logger bound to a daemon name.
 *
 * @example
 *   const log = createLogger("myservice");
 *   log("INFO", "listening on /run/myservice.sock");
 */
export function createLogger(
  name: string,
): (level: "INFO" | "ALLOW" | "DENY" | "ERR" | "WARN", message: string) => void {
  return (level, message) => log(name, level, message);
}

/**
 * Parse common daemon CLI arguments.
 *
 * @param name - daemon name
 * @param argv - command-line arguments (typically Bun.argv.slice(2))
 * @param runDir - function returning the run directory
 * @param env - environment variables
 *
 * @returns
 *   - command: "serve" | "help" | undefined
 *   - socket: socket path (default based on daemon name)
 *   - port: TCP port for testing (undefined = use socket)
 *
 * @example
 *   const { command, socket, port } = parseArgs("myservice", args, myRunDir);
 *   if (command === "serve") { listen({ unix: socket, ... }); }
 */
export function parseArgs(
  name: string,
  argv: string[],
  runDir: RunDirFn,
  env: Env = process.env,
): { command: string | undefined; socket: string; port: number | undefined } {
  const envKey = `${name.toUpperCase()}_SOCK`;
  let socket = env[envKey] ?? defaultSocketPath(name, runDir, env);
  let port: number | undefined;
  const command = argv[0];

  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--socket" || arg === "-s" || arg === "--unix") {
      socket = argv[++i]!;
    } else if (arg === "--port") {
      port = Number(argv[++i]);
    }
  }

  return { command, socket, port };
}

/**
 * Show usage for a daemon with standard CLI structure.
 *
 * @param name - daemon name
 * @param description - one-line description
 * @param runDir - function returning the run directory (for help text)
 * @param envVars - additional environment variables to document
 */
export function showUsage(
  name: string,
  description: string,
  runDir: RunDirFn,
  envVars: Record<string, string> = {},
): void {
  const defaultDir = runDir({});
  const envLines = Object.entries(envVars)
    .map(([k, v]) => `  ${k.padEnd(16)} ${v}`)
    .join("\n");

  console.log(`${name} — ${description}

Usage:
  ${name} serve                     start daemon (foreground, unix socket)
  ${name} serve --port PORT         listen on TCP (for testing)
  ${name} serve --socket PATH       custom socket path (--unix is alias)
  ${name} help                      show this help

Environment:
  ${name.toUpperCase()}_SOCK      default unix socket path (fallback: ${defaultDir}/${name}.sock)
${envLines ? envLines + "\n" : ""}`);
}
