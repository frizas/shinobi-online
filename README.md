# Shinobi Online

Public distribution repository for Shinobi Online.

This repo contains the player-facing website, public release notes, and the latest-version manifest used by the launcher/update flow. Server source, operator tooling, live databases, and private authority logic live in the private `frizas/shinobi-online-servers` repository.

Live distribution site: https://shinobionline.vercel.app

## Public Artifacts

- Website entry point: `index.html`
- Vercel configuration: `vercel.json`
- Latest release manifest: `public/latest.json`
- Leaf server manifest: `public/server.json`
- Manifest schema: `public/latest.schema.json`
- Public release notes: `releases/`

## Download Channel

Player builds should be uploaded as GitHub Release assets. Do not commit installer or zip binaries directly to this repository.

The manifest should be updated after a release asset is published:

```json
{
  "schemaVersion": 2,
  "version": "0.1.0",
  "status": "available",
  "installer": {
    "url": "https://github.com/frizas/shinobi-online/releases/download/v0.1.0/ShinobiOnlineSetup-0.1.0.exe",
    "sha256": "<64 lowercase hex characters>",
    "sizeBytes": 12345678
  },
  "runtimePackage": {
    "url": "https://github.com/frizas/shinobi-online/releases/download/v0.1.0/ShinobiOnlineRuntime-0.1.0.zip",
    "sha256": "<64 lowercase hex characters>",
    "runtimeManifestSha256": "<64 lowercase hex characters>",
    "sizeBytes": 12345678
  },
  "compatibility": {
    "os": "Windows 10 or newer",
    "architecture": "x64",
    "graphics": "OpenGL-capable GPU driver",
    "prerequisiteMode": "detect-and-guide"
  }
}
```

The temporary cutoff mode uses `SITE_ACCESS_PASSWORD` and `SITE_ACCESS_SIGNING_KEY` in Vercel production. It returns `404` for unauthenticated protected paths, keeps only `public/server.json` public for endpoint discovery, encrypts the installer, and does not publish a runtime updater asset.

`public/server.json` is updated by the private operator repo when Leaf starts or stops.

## Validation

```powershell
pwsh -ExecutionPolicy Bypass -File .\scripts\Validate-LatestManifest.ps1
pwsh -ExecutionPolicy Bypass -File .\scripts\Validate-ServerManifest.ps1
```
