/**
 * runtime.ts — claude-box runtime helpers for daemons.
 *
 * Bridges the guest-agnostic guest-room/ modules with claude-box-specific
 * paths and conventions. Daemons import from here for:
 *   - Socket path resolution with ~/.claude-box/run default
 *   - Logging with consistent format
 *   - CLI parsing with claude-box conventions
 */

import {
  defaultSocketPath as genericSocketPath,
  prepareSocket,
  createLogger as genericLogger,
  parseArgs as genericParseArgs,
  showUsage as genericShowUsage,
  type Env,
  type RunDirFn,
} from "../guest-room/daemon.ts";

// Re-export protocol types for convenience
export {
  type RequestEnvelope,
  type ResponseEnvelope,
  ok,
  err,
  createDoorHandlers,
  call,
  type MethodHandler,
  type MethodRegistry,
} from "../guest-room/protocol.ts";

// Re-export daemon utilities
export { prepareSocket, type Env };

/**
 * The claude-box run directory: ~/.claude-box/run
 * This is where door sockets live on macOS (no XDG_RUNTIME_DIR).
 */
export const claudeBoxRunDir: RunDirFn = (env: Env): string => {
  const home = env.HOME ?? "/tmp";
  return `${home}/.claude-box/run`;
};

/**
 * Default socket path for a claude-box daemon.
 * Uses XDG_RUNTIME_DIR if available, otherwise ~/.claude-box/run.
 */
export function defaultSocketPath(name: string, env: Env = process.env): string {
  return genericSocketPath(name, claudeBoxRunDir, env);
}

/**
 * Create a logger for a claude-box daemon.
 */
export function createLogger(name: string) {
  return genericLogger(name);
}

/**
 * Parse CLI arguments for a claude-box daemon.
 */
export function parseArgs(
  name: string,
  argv: string[],
  env: Env = process.env,
): { command: string | undefined; socket: string; port: number | undefined } {
  return genericParseArgs(name, argv, claudeBoxRunDir, env);
}

/**
 * Show usage for a claude-box daemon.
 */
export function showUsage(
  name: string,
  description: string,
  envVars: Record<string, string> = {},
): void {
  genericShowUsage(name, description, claudeBoxRunDir, envVars);
}
