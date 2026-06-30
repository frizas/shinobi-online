[CmdletBinding()]
param(
    [string] $ManifestPath = (Join-Path $PSScriptRoot '..\public\latest.json')
)

$ErrorActionPreference = 'Stop'

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json

if ($manifest.schemaVersion -ne 1) {
    throw 'schemaVersion must be 1.'
}

if ($manifest.game -ne 'Shinobi Online') {
    throw 'game must be "Shinobi Online".'
}

if ($manifest.channel -notin @('production', 'staging')) {
    throw 'channel must be production or staging.'
}

if ($manifest.version -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9.-]+)?$') {
    throw 'version must be semver-like, for example 0.1.0.'
}

if ($manifest.status -notin @('pending-release', 'available', 'withdrawn')) {
    throw 'status must be pending-release, available, or withdrawn.'
}

if ($manifest.status -eq 'available') {
    if ([string]::IsNullOrWhiteSpace($manifest.installerFileName)) {
        throw 'available manifests require installerFileName.'
    }

    if ($manifest.installerUrl -notmatch '^https://github\.com/frizas/shinobi-online/releases/download/') {
        throw 'available manifests require a GitHub Release installerUrl.'
    }

    if ($manifest.sha256 -notmatch '^[a-f0-9]{64}$') {
        throw 'available manifests require a lowercase 64-character sha256.'
    }

    if ($manifest.sizeBytes -lt 1) {
        throw 'available manifests require sizeBytes greater than 0.'
    }

    if ([string]::IsNullOrWhiteSpace($manifest.publishedAt)) {
        throw 'available manifests require publishedAt.'
    }
}

Write-Host "Manifest OK: $($manifest.game) $($manifest.version) [$($manifest.status)]"
