# Distribution Model

The public repository is the distribution layer for Shinobi Online.

## Public

- Website
- Public release notes
- `public/latest.json`
- `public/server.json`
- GitHub Release assets for installers/downloads

## Private

- Server runtime and source
- Operator launchers and scripts
- Client source workspace
- Live databases and local tunnel state
- Build and release tooling

Vercel should host only the static website and small manifest files. Game server hosting needs a separate TCP-capable host.

## Player Launcher Contract

The website download button reads `public/latest.json.installer.url`. The installed launcher reads:

- `public/latest.json` for installer and runtime package versions.
- `public/server.json` for the current Leaf endpoint.

The launcher downloads full runtime packages from GitHub Releases, verifies SHA-256 hashes, writes `shinobi-launch.lua`, then starts the OTClient runtime.
