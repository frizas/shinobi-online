# Shinobi Online

Public distribution repository for Shinobi Online.

This repo contains the player-facing website, public release notes, and the latest-version manifest used by the launcher/update flow. Server source, operator tooling, live databases, and private authority logic live in the private `frizas/shinobi-online-servers` repository.

Live distribution site: https://shinobi-online-frizas-frizas-projects-a9f36227.vercel.app

## Public Artifacts

- Website entry point: `index.html`
- Vercel configuration: `vercel.json`
- Latest release manifest: `public/latest.json`
- Manifest schema: `public/latest.schema.json`
- Public release notes: `releases/`

## Download Channel

Player builds should be uploaded as GitHub Release assets. Do not commit installer or zip binaries directly to this repository.

The manifest should be updated after a release asset is published:

```json
{
  "version": "0.1.0",
  "installerUrl": "https://github.com/frizas/shinobi-online/releases/download/v0.1.0/ShinobiOnlineSetup-0.1.0.exe",
  "sha256": "<64 lowercase hex characters>",
  "sizeBytes": 12345678
}
```

## Validation

```powershell
pwsh -ExecutionPolicy Bypass -File .\scripts\Validate-LatestManifest.ps1
```
