[CmdletBinding()]
param(
    [string] $ManifestPath = (Join-Path $PSScriptRoot '..\public\v0.2\latest.json'),
    [string] $SignaturePath = (Join-Path $PSScriptRoot '..\public\v0.2\latest.sig'),
    [string] $PublicKeyPath = (Join-Path $PSScriptRoot '..\public\manifest-signing-key.json')
)

$ErrorActionPreference = 'Stop'

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json

foreach ($requiredPath in @($SignaturePath, $PublicKeyPath)) {
    if (!(Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Manifest signature input is missing: $requiredPath"
    }
}

$signature = Get-Content -LiteralPath $SignaturePath -Raw | ConvertFrom-Json
$publicKey = Get-Content -LiteralPath $PublicKeyPath -Raw | ConvertFrom-Json
$signatureAlgorithm = 'RSASSA-PKCS1-v1_5-SHA256'
if ($signature.schemaVersion -ne 1 -or
    $publicKey.schemaVersion -ne 1 -or
    $signature.algorithm -cne $signatureAlgorithm -or
    $publicKey.algorithm -cne $signatureAlgorithm -or
    $signature.keyId -cne $publicKey.keyId -or
    $signature.keyId -notmatch '^sha256:[a-f0-9]{64}$') {
    throw 'Manifest signature metadata is invalid or does not match the trusted public key.'
}

$manifestBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $ManifestPath))
$manifestHash = [Security.Cryptography.SHA256]::Create()
try {
    $manifestSha256 = ([BitConverter]::ToString($manifestHash.ComputeHash($manifestBytes)) -replace '-', '').ToLowerInvariant()
} finally {
    $manifestHash.Dispose()
}
if ($signature.manifestSha256 -cne $manifestSha256) {
    throw 'Manifest signature metadata does not match the exact latest.json bytes.'
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
        throw 'latest.json signature verification failed.'
    }
} finally {
    $provider.Dispose()
}

if ($manifest.schemaVersion -notin @(3, 4)) {
    throw 'schemaVersion must be 3 or 4.'
}

if ($manifest.game -ne 'Shinobi Online') {
    throw 'game must be "Shinobi Online".'
}

if ($manifest.channel -notin @('production', 'staging')) {
    throw 'channel must be production or staging.'
}

if ($manifest.version -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9.-]+)?$') {
    throw 'version must be semver-like, for example 0.2.0.'
}

if ([Version]($manifest.version.Split('-', 2)[0]) -lt [Version]'0.2.0') {
    throw 'version must be 0.2.0 or newer.'
}
$normalizedManifestVersion = [Version]($manifest.version.Split('-', 2)[0])
$expectedTokenKind = if ($manifest.schemaVersion -eq 3) {
    'runtimeManifestSha256'
} elseif ($normalizedManifestVersion -ge [Version]'0.4.13') {
    'shinobiContentIndexSha256'
} else {
    'runtimeIdentitySha256'
}

if ($manifest.status -notin @('pending-release', 'available', 'withdrawn')) {
    throw 'status must be pending-release, available, or withdrawn.'
}

if (!$manifest.launcher) {
    throw 'launcher metadata is required.'
}

if ($manifest.launcher.currentVersion -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9.-]+)?$') {
    throw 'launcher.currentVersion must be semver-like.'
}

if ($manifest.launcher.minimumVersion -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9.-]+)?$') {
    throw 'launcher.minimumVersion must be semver-like.'
}

if (!$manifest.compatibility) {
    throw 'compatibility metadata is required.'
}

if ($manifest.compatibility.os -ne 'Windows 10 or newer') {
    throw 'compatibility.os must be "Windows 10 or newer".'
}

if ($manifest.compatibility.architecture -ne 'x64') {
    throw 'compatibility.architecture must be "x64".'
}

if ($manifest.compatibility.graphics -ne 'OpenGL-capable GPU driver') {
    throw 'compatibility.graphics must be "OpenGL-capable GPU driver".'
}

if ($manifest.compatibility.prerequisiteMode -ne 'detect-and-guide') {
    throw 'compatibility.prerequisiteMode must be "detect-and-guide".'
}

function Assert-ReleaseArtifact {
    param(
        [object] $Artifact,
        [string] $Name
    )

    if (!$Artifact) {
        throw "$Name is required when status is available."
    }

    if ([string]::IsNullOrWhiteSpace($Artifact.fileName)) {
        throw "$Name.fileName is required."
    }

    if ($Artifact.url -notmatch '^https://github\.com/frizas/shinobi-online/releases/download/') {
        throw "$Name.url must point to a frizas/shinobi-online GitHub Release asset."
    }

    if ($Artifact.sha256 -notmatch '^[a-f0-9]{64}$') {
        throw "$Name.sha256 must be a lowercase 64-character SHA-256."
    }

    if ($Artifact.sizeBytes -lt 1) {
        throw "$Name.sizeBytes must be greater than 0."
    }
}

function Assert-ClientBuildEntry {
    param(
        [object] $Entry,
        [string] $Name
    )

    if (!$Entry) {
        throw "$Name is required."
    }

    if ($Entry.version -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9.-]+)?$') {
        throw "$Name.version must be semver-like."
    }

    if ($Entry.token -notmatch '^[a-f0-9]{64}$') {
        throw "$Name.token must be a lowercase 64-character SHA-256."
    }

    if ($Entry.tokenKind -ne $expectedTokenKind) {
        throw "$Name.tokenKind must be $expectedTokenKind."
    }

    if ([string]::IsNullOrWhiteSpace($Entry.publishedAt)) {
        throw "$Name.publishedAt is required."
    }
}

function Assert-RuntimePackage {
    param(
        [object] $Package,
        [string] $Name
    )

    Assert-ReleaseArtifact -Artifact $Package -Name $Name

    if ($Package.runtimeManifestSha256 -notmatch '^[a-f0-9]{64}$') {
        throw "$Name.runtimeManifestSha256 must be a lowercase 64-character SHA-256."
    }
}

if ($manifest.status -eq 'available') {
    if ([string]::IsNullOrWhiteSpace($manifest.publishedAt)) {
        throw 'available manifests require publishedAt.'
    }

    Assert-ReleaseArtifact -Artifact $manifest.installer -Name 'installer'
    if ($manifest.schemaVersion -eq 4) {
        if (!$manifest.contentPack -or
            $manifest.contentPack.format -cne 'ShinobiContentPack/1' -or
            $manifest.contentPack.version -cne $manifest.version -or
            $manifest.contentPack.contentRevision -lt 1 -or
            $manifest.contentPack.indexSha256 -notmatch '^[a-f0-9]{64}$' -or
            $manifest.contentPack.chunkBaseUrl -notmatch '^https://github\.com/frizas/shinobi-online/releases/download/[^/]+/$') {
            throw 'contentPack metadata is invalid.'
        }
        Assert-ReleaseArtifact -Artifact $manifest.contentPack.index -Name 'contentPack.index'
        Assert-ReleaseArtifact -Artifact $manifest.contentPack.signature -Name 'contentPack.signature'
        if ($manifest.contentPack.index.sha256 -cne $manifest.contentPack.indexSha256) {
            throw 'contentPack.index must match contentPack.indexSha256.'
        }
        if ($expectedTokenKind -ceq 'shinobiContentIndexSha256') {
            Assert-ReleaseArtifact -Artifact $manifest.contentPack.activation -Name 'contentPack.activation'
            Assert-ReleaseArtifact -Artifact $manifest.contentPack.activationSignature -Name 'contentPack.activationSignature'
        }
    } elseif ($manifest.PSObject.Properties.Name -contains 'contentPack') {
        throw 'schemaVersion 3 must not publish contentPack metadata.'
    }
    if ($manifest.PSObject.Properties.Name -contains 'runtimePackage') {
        throw 'runtimePackage is forbidden; v0.2 Windows updates are installer-only.'
    }

    if (!$manifest.clientBuild) {
        throw 'available manifests require clientBuild metadata.'
    }

    if ($manifest.PSObject.Properties.Name -contains 'access') {
        throw 'access metadata must not be published.'
    }

    if (!$manifest.distribution -or
        $manifest.distribution.securityGeneration -cne 'v0.2' -or
        $manifest.distribution.runtimeUpdaterEnabled) {
        throw 'distribution must identify v0.2 with the raw runtime updater disabled.'
    }

    $expectedUpdateMode = if ($manifest.schemaVersion -eq 4) { 'content-or-installer' } else { 'installer' }
    if ($manifest.clientBuild.updateMode -ne $expectedUpdateMode -or
        ($manifest.schemaVersion -eq 4 -and !$manifest.distribution.contentUpdaterEnabled)) {
        throw "clientBuild.updateMode must be $expectedUpdateMode and match distribution content-updater policy."
    }

    if ($manifest.clientBuild.minimumAcceptedVersion -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9.-]+)?$') {
        throw 'clientBuild.minimumAcceptedVersion must be semver-like.'
    }

    Assert-ClientBuildEntry -Entry $manifest.clientBuild.current -Name 'clientBuild.current'

    $acceptedBuilds = @($manifest.clientBuild.accepted)
    if ($acceptedBuilds.Count -ne 1) {
        throw 'clientBuild.accepted must contain exactly the current v0.2 build.'
    }

    for ($i = 0; $i -lt $acceptedBuilds.Count; $i++) {
        Assert-ClientBuildEntry -Entry $acceptedBuilds[$i] -Name "clientBuild.accepted[$i]"
    }

    if ($expectedTokenKind -ceq 'shinobiContentIndexSha256' -and
        $manifest.clientBuild.current.token -cne $manifest.contentPack.indexSha256) {
        throw 'clientBuild.current.token must match contentPack.indexSha256 for native content-index releases.'
    }

    $acceptedCurrent = $acceptedBuilds[0]
    if ($acceptedCurrent.version -cne $manifest.clientBuild.current.version -or
        $acceptedCurrent.token -cne $manifest.clientBuild.current.token -or
        $acceptedCurrent.tokenKind -cne $manifest.clientBuild.current.tokenKind -or
        $acceptedCurrent.publishedAt -cne $manifest.clientBuild.current.publishedAt) {
        throw 'clientBuild.accepted must contain the exact current build.'
    }

    if ($manifest.PSObject.Properties.Name -contains 'android') {
        throw 'Android distribution is not published in the v0.2 Windows release manifest.'
    }
}

Write-Host "Manifest OK: $($manifest.game) $($manifest.version) [$($manifest.status)]"
