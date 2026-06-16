# door-scout — the external-read capability door

`door-scout` is **scoutd** packaged as a standalone, pinned OCI image. scoutd holds external read
tokens and hands a box **content** — never the credentials. It egresses *only* through a mounted
`scout-netd` door (socat bridges loopback → that socket; `--network=none` otherwise — interposition,
not cooperation). It's the read half of the
[claude-box](https://github.com/bounded-systems/claude-box) door model (write: door-keeper; egress:
door-net; resolution: concierged).

## Build / run

```sh
nix build .#scoutd-image && podman load -i result
podman run -v doors:/run/doors scoutd
```

Tests: `tests/scoutd.test.ts` + `tests/scoutd.ocap.test.ts` (caveat/door-grant enforcement).

## Pinned dependencies (vendored mirrors)

scoutd needs the engine + the runtime helper (no provenance contract). Each is a PINNED input and a
generated mirror, kept honest by the `*-mirror` checks (`nix flake check`):

| Dir | Pinned input | Bump |
|---|---|---|
| `lib/runtime.ts` | [`door-kit`](https://github.com/bounded-systems/door-kit) `@a3ae40e` | `nix flake update door-kit` + `nix run .#sync-door-kit` |
| `guest-room/` | [`guest-room`](https://github.com/bounded-systems/guest-room) `@5bc85b6` | `nix flake update guest-room` + `nix run .#sync-guest-room` |

_Extracted from claude-box `scoutd.ts` — decomposition epic `prx-ii01`, card 2._
