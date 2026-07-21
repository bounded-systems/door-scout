# Release intents

This repo uses [@bounded-systems/mint](https://github.com/bounded-systems/mint) for
versioning. Each PR with a user-facing change drops an intent file here; mint
resolves the strongest bump and cuts the release deterministically.

Format — `.release/<slug>.md`:

    ---
    bump: minor   # patch | minor | major
    ---
    short summary of the change (becomes the changelog line)

The version lives in `package.json` (which `scoutd.ts` reads for its
self-reported version). `mint version` bumps it + prepends `CHANGELOG.md`;
`mint release` cuts the `v<version>` tag, which drives `publish-ghcr.yml` (the
scoutd **OCI image**, pushed to GHCR at the tag's version) and `release.yml`
(in-toto provenance). mint is the only thing that cuts a release tag.
