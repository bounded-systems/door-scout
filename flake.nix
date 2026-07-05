{
  # door-scout — the external-read door (scoutd) as a pinned OCI image.
  #
  # Extracted from claude-box (epic prx-ii01, card 2). scoutd holds read tokens
  # and hands boxes *content*, never credentials. It egresses only through a
  # mounted scout-netd door (socat bridges loopback → that socket; --network=none
  # otherwise). claude-box (the integrator) pins the published image.
  description = "door-scout — the scoutd external-read door as a pinned OCI image";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/9f11f828c213641c2369a9f1fa31fe31557e3156";

  # scoutd needs the engine + the runtime helper (no provenance contract).
  inputs.guest-room.url = "github:bounded-systems/guest-room/79662abe154039d1bf91f46cefa03a06204e87ef";
  inputs.guest-room.flake = false;
  inputs.door-kit.url = "github:bounded-systems/door-kit/a3ae40e5075e3dbded3db9a0d345f842984a646b";
  inputs.door-kit.flake = false;
  # the PUBLISHED scout-wire agreement — scoutd's own METHODS are checked against
  # it, so the contract (not this daemon) is the source of truth.
  inputs.scout-wire.url = "github:bounded-systems/scout-wire";
  inputs.scout-wire.flake = false;

  outputs = { self, nixpkgs, guest-room, door-kit, scout-wire }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      forEach = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };
      uid = 1000;
    in
    {
      packages = forEach (system:
        let pkgs = pkgsFor system;
        in {
          # scoutd-image — the external read daemon as a container.
          #   nix build .#scoutd-image && podman load -i result
          #   podman run -v doors:/run/doors scoutd
          scoutd-image =
            let
              # bun + coreutils + cacert + socat (socat bridges loopback-TCP → the
              # scout-netd door socket so scoutd egresses through netd, no NIC).
              scoutdTools = with pkgs; [ bun cacert coreutils socat bashInteractive ];

              scoutdEnv = pkgs.buildEnv {
                name = "scoutd-image-root";
                paths = scoutdTools;
                pathsToLink = [ "/bin" "/etc" "/share" "/lib" ];
              };

              scoutdSrc = pkgs.runCommand "scoutd-src" { } ''
                mkdir -p $out/app/lib $out/app/guest-room
                cp ${./scoutd.ts} $out/app/scoutd.ts
                # the published scout-wire agreement, next to scoutd for the
                # runtime shadow-validation (log-only). Kept fresh by the pin.
                cp ${scout-wire}/manifest.json $out/app/scout-wire.manifest.json
                cp ${./lib/runtime.ts} $out/app/lib/runtime.ts
                cp ${./guest-room/mod.ts} $out/app/guest-room/mod.ts
                cp ${./guest-room/daemon.ts} $out/app/guest-room/daemon.ts
                cp ${./guest-room/protocol.ts} $out/app/guest-room/protocol.ts
              '';

              scoutdEntrypoint = pkgs.writeShellScript "scoutd-entrypoint" ''
                # If a scout-netd door is mounted, bridge loopback → its socket and
                # force scoutd's egress through it (SCOUTD_PROXY). With --network=none
                # this is the ONLY egress path: interposition, not cooperation.
                if [ -S /run/doors/scout-netd.sock ]; then
                  ${pkgs.socat}/bin/socat TCP-LISTEN:3128,fork,reuseaddr,bind=127.0.0.1 \
                    UNIX-CONNECT:/run/doors/scout-netd.sock &
                  export SCOUTD_PROXY="http://127.0.0.1:3128"
                fi
                exec bun /app/scoutd.ts serve --socket /run/doors/scoutd.sock "$@"
              '';
            in
            pkgs.dockerTools.buildLayeredImage {
              name = "scoutd";
              tag = "dev";

              contents = [ scoutdEnv scoutdSrc ];

              extraCommands = ''
                mkdir -p etc tmp run/doors creds
                chmod 1777 tmp
                cat > etc/passwd <<EOF
                root:x:0:0:root:/root:/bin/bash
                scout:x:${toString uid}:${toString uid}:scout:/app:/bin/bash
                EOF
                cat > etc/group <<EOF
                root:x:0:
                scout:x:${toString uid}:
                EOF
              '';

              fakeRootCommands = ''
                chown -R ${toString uid}:${toString uid} run/doors creds
              '';

              config = {
                Entrypoint = [ "${scoutdEntrypoint}" ];
                WorkingDir = "/app";
                User = "scout";
                Env = [
                  "HOME=/app"
                  "PATH=/bin"
                  "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                  "LANG=C.UTF-8"
                ];
                Volumes = {
                  "/run/doors" = { };
                  "/creds" = { };
                };
              };
            };

          default = self.packages.${system}.scoutd-image;
        });

      # ── sync apps (regenerate the vendored mirrors from the pinned inputs) ──
      apps.aarch64-darwin =
        let pkgs = pkgsFor "aarch64-darwin";
        in {
          sync-guest-room = {
            type = "app";
            program = "${pkgs.writeShellScriptBin "sync-guest-room" ''
              set -euo pipefail
              for f in mod.ts daemon.ts protocol.ts; do
                install -m 644 ${guest-room}/$f "$PWD/guest-room/$f"; echo "synced guest-room/$f"
              done
            ''}/bin/sync-guest-room";
            meta.description = "Sync ./guest-room/ from the pinned guest-room input";
          };
          sync-door-kit = {
            type = "app";
            program = "${pkgs.writeShellScriptBin "sync-door-kit" ''
              set -euo pipefail
              install -m 644 ${door-kit}/lib/runtime.ts "$PWD/lib/runtime.ts"; echo "synced lib/runtime.ts"
            ''}/bin/sync-door-kit";
            meta.description = "Sync ./lib/runtime.ts from the pinned door-kit input";
          };
        };

      # ── mirror checks: the vendored dirs must match the pinned inputs ──
      # ── daemon-side wire conformance (Linux, so CI actually runs it) ──
      # scoutd's METHODS table must match the published scout-wire agreement.
      checks = (forEach (system:
        let pkgs = pkgsFor system;
        in {
          scout-wire-methods = pkgs.runCommand "scout-wire-methods" {
            nativeBuildInputs = [ pkgs.deno ];
            DENO_DIR = "/tmp/deno";
          } ''
            export HOME=$TMPDIR
            deno run --no-remote --allow-read ${./tests/wire-methods.ts} \
              ${./scoutd.ts} \
              ${scout-wire}/manifest.json
            touch $out
          '';
        })) // {
        # ── mirror checks: the vendored dirs must match the pinned inputs ──
        aarch64-darwin = let pkgs = pkgsFor "aarch64-darwin";
        in {
          guest-room-mirror = pkgs.runCommand "guest-room-mirror" { } ''
            for f in mod.ts daemon.ts protocol.ts; do
              if ! diff -u ${guest-room}/$f ${./guest-room}/$f; then
                echo "guest-room/$f drifted — run: nix run .#sync-guest-room" >&2; exit 1
              fi
            done
            touch $out
          '';
          door-kit-mirror = pkgs.runCommand "door-kit-mirror" { } ''
            if ! diff -u ${door-kit}/lib/runtime.ts ${./lib}/runtime.ts; then
              echo "lib/runtime.ts drifted — run: nix run .#sync-door-kit" >&2; exit 1
            fi
            touch $out
          '';
        };
      };
    };
}
