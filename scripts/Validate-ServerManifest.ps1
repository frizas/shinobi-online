[CmdletBinding()]
param(
    [string] $ManifestPath = (Join-Path $PSScriptRoot '..\public\server.json')
)

$ErrorActionPreference = 'Stop'

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json

if ($manifest.schemaVersion -ne 1) {
    throw 'schemaVersion must be 1.'
}

if ($manifest.serverName -ne 'Leaf') {
    throw 'serverName must be Leaf.'
}

if ($manifest.status -notin @('online', 'offline', 'maintenance')) {
    throw 'status must be online, offline, or maintenance.'
}

if ($manifest.mode -notin @('pinggy', 'stable')) {
    throw 'mode must be pinggy or stable.'
}

if ($manifest.protocol -lt 1) {
    throw 'protocol must be a positive integer.'
}

if ($manifest.endpointRevision -lt 0) {
    throw 'endpointRevision must be 0 or greater.'
}

if ([string]::IsNullOrWhiteSpace($manifest.updatedAt)) {
    throw 'updatedAt is required.'
}

if ([string]::IsNullOrWhiteSpace($manifest.message)) {
    throw 'message is required.'
}

if ($manifest.status -eq 'online') {
    if ([string]::IsNullOrWhiteSpace($manifest.loginHost) -or [int]$manifest.loginPort -lt 1) {
        throw 'online manifests require loginHost and loginPort.'
    }

    if ([string]::IsNullOrWhiteSpace($manifest.gameHost) -or [int]$manifest.gamePort -lt 1) {
        throw 'online manifests require gameHost and gamePort.'
    }
}

Write-Host "Server manifest OK: $($manifest.serverName) [$($manifest.status)] revision $($manifest.endpointRevision)"
