# Distribution Model

The public repository is the distribution layer for Shinobi Online.

## Public

- Website
- Public release notes
- `public/latest.json`
- GitHub Release assets for installers/downloads

## Private

- Server runtime and source
- Operator launchers and scripts
- Client source workspace
- Live databases and local tunnel state
- Build and release tooling

Vercel should host only the static website and small manifest files. Game server hosting needs a separate TCP-capable host.
