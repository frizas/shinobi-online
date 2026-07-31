[CmdletBinding()]
param(
    [string] $ManifestPath = (Join-Path $PSScriptRoot '..\public\server.json'),
    [string] $SignaturePath = (Join-Path $PSScriptRoot '..\public\server.sig'),
    [string] $PublicKeyPath = (Join-Path $PSScriptRoot '..\public\manifest-signing-key.json')
)

$ErrorActionPreference = 'Stop'

foreach ($requiredPath in @($ManifestPath, $SignaturePath, $PublicKeyPath)) {
    if (!(Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Server manifest signature input is missing: $requiredPath"
    }
}

$manifestBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $ManifestPath))
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$signature = Get-Content -LiteralPath $SignaturePath -Raw | ConvertFrom-Json
$publicKey = Get-Content -LiteralPath $PublicKeyPath -Raw | ConvertFrom-Json
$signatureAlgorithm = 'RSASSA-PKCS1-v1_5-SHA256'
if ($signature.schemaVersion -ne 1 -or
    $publicKey.schemaVersion -ne 1 -or
    $signature.algorithm -cne $signatureAlgorithm -or
    $publicKey.algorithm -cne $signatureAlgorithm -or
    $signature.keyId -cne $publicKey.keyId -or
    $signature.keyId -notmatch '^sha256:[a-f0-9]{64}$') {
    throw 'Server manifest signature metadata is invalid or does not match the trusted public key.'
}

$manifestHash = [Security.Cryptography.SHA256]::Create()
try {
    $manifestSha256 = ([BitConverter]::ToString($manifestHash.ComputeHash($manifestBytes)) -replace '-', '').ToLowerInvariant()
} finally {
    $manifestHash.Dispose()
}
if ($signature.manifestSha256 -cne $manifestSha256) {
    throw 'Server manifest signature metadata does not match the exact server.json bytes.'
}

$parameters = [Security.Cryptography.RSAParameters]::new()
$parameters.Modulus = [Convert]::FromBase64String([string]$publicKey.modulus)
$parameters.Exponent = [Convert]::FromBase64String([string]$publicKey.exponent)
$provider = [Security.Cryptography.RSA]::Create()
try {
    $provider.ImportParameters($parameters)
    $signatureBytes = [Convert]::FromBase64String([string]$signature.signature)
    if (!$provider.VerifyData(
        $manifestBytes,
        $signatureBytes,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)) {
        throw 'server.json signature verification failed.'
    }
} finally {
    $provider.Dispose()
}

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
