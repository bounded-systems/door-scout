/**
 * @module
 * Daemon-side wire conformance: this daemon's METHODS dispatch table must match
 * the PUBLISHED wire agreement (pinned as a flake input, read as manifest.json).
 * The agreement is the single source of truth; a method added/dropped without
 * the contract moving reds. Dependency-free (regex) so it runs sealed in Nix.
 *
 *   deno run --no-remote --allow-read tests/wire-methods.ts <daemon.ts> <manifest.json>
 */

const [daemonPath, manifestPath] = Deno.args;
if (!daemonPath || !manifestPath) {
  console.error("usage: wire-methods.ts <daemon.ts> <manifest.json>");
  Deno.exit(2);
}

const manifest = JSON.parse(Deno.readTextFileSync(manifestPath));
const label: string = manifest.type ?? "wire";
const src = Deno.readTextFileSync(daemonPath).replace(/\/\*[\s\S]*?\*\//g, "");
const block = src.match(/const\s+METHODS[^=]*=\s*\{([\s\S]*?)\}/);
if (!block) {
  console.error(`${label}: could not find the daemon's METHODS table`);
  Deno.exit(1);
}
const daemon = new Set(
  [...block[1].matchAll(/(?:^|,)\s*(?:"([^"]+)"|([A-Za-z_][\w-]*))\s*:/g)]
    .map((m) => m[1] ?? m[2]),
);
const want = new Set<string>(manifest.methods);

const missing = [...want].filter((m) => !daemon.has(m));
const extra = [...daemon].filter((m) => !want.has(m));
if (missing.length || extra.length) {
  console.error(`${label}: daemon METHODS drift from the agreement:`);
  if (missing.length) console.error(`  daemon missing: ${missing.join(", ")}`);
  if (extra.length) console.error(`  daemon extra:   ${extra.join(", ")}`);
  Deno.exit(1);
}
console.log(`${label}: daemon METHODS match the agreement. ✓`);
