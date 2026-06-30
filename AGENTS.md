# AGENTS.md

## Public Repository Boundary

This repository is public and player-facing.

- Keep website files, public release notes, download manifests, and GitHub Release metadata here.
- Do not add server source, operator tooling, live database files, admin commands, private configs, tunnel endpoint caches, or unreleased gameplay authority logic.
- Do not publish private repo files from `frizas/shinobi-online-servers` here unless they have gone through an explicit public-scope review.

## Release Rules

- Large downloadable builds belong in GitHub Releases, not committed to this repository.
- Vercel should serve the website and small JSON files only.
- `public/latest.json` is the player/update manifest. Keep it valid with `scripts/Validate-LatestManifest.ps1`.
- No open-source license is granted until a license policy is chosen explicitly.
