[CmdletBinding()]
param(
    [string] $ManifestPath = (Join-Path $PSScriptRoot '..\public\latest.json')
)

$ErrorActionPreference = 'Stop'

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json

if ($manifest.schemaVersion -ne 2) {
    throw 'schemaVersion must be 2.'
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

    if ($Entry.tokenKind -ne 'runtimeManifestSha256') {
        throw "$Name.tokenKind must be runtimeManifestSha256."
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
    Assert-RuntimePackage -Package $manifest.runtimePackage -Name 'runtimePackage'

    if (!$manifest.clientBuild) {
        throw 'available manifests require clientBuild metadata.'
    }

    if ($manifest.clientBuild.updateMode -ne 'launcher') {
        throw 'clientBuild.updateMode must be launcher.'
    }

    if ($manifest.clientBuild.minimumAcceptedVersion -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9.-]+)?$') {
        throw 'clientBuild.minimumAcceptedVersion must be semver-like.'
    }

    Assert-ClientBuildEntry -Entry $manifest.clientBuild.current -Name 'clientBuild.current'

    $acceptedBuilds = @($manifest.clientBuild.accepted)
    if ($acceptedBuilds.Count -lt 1) {
        throw 'clientBuild.accepted must contain at least one build.'
    }

    for ($i = 0; $i -lt $acceptedBuilds.Count; $i++) {
        Assert-ClientBuildEntry -Entry $acceptedBuilds[$i] -Name "clientBuild.accepted[$i]"
    }

    if ($manifest.android) {
        if ($manifest.android.versionName -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9.-]+)?$') {
            throw 'android.versionName must be semver-like.'
        }

        if ($manifest.android.versionCode -lt 1) {
            throw 'android.versionCode must be greater than 0.'
        }

        if ($manifest.android.minimumVersionCode -lt 1) {
            throw 'android.minimumVersionCode must be greater than 0.'
        }

        if ($manifest.android.minimumVersionCode -gt $manifest.android.versionCode) {
            throw 'android.minimumVersionCode cannot be greater than android.versionCode.'
        }

        if ($manifest.android.packageName -notmatch '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$') {
            throw 'android.packageName must be a Java-style package name.'
        }

        if ($manifest.android.updateMode -ne 'website') {
            throw 'android.updateMode must be website.'
        }

        if ([string]::IsNullOrWhiteSpace($manifest.android.downloadUrl)) {
            throw 'android.downloadUrl is required.'
        }

        Assert-ReleaseArtifact -Artifact $manifest.android.apk -Name 'android.apk'
        Assert-RuntimePackage -Package $manifest.android.runtimePackage -Name 'android.runtimePackage'

        if ($manifest.android.acceptedRuntimePackages) {
            foreach ($entry in @($manifest.android.acceptedRuntimePackages)) {
                Assert-ClientBuildEntry -Entry $entry -Name 'android.acceptedRuntimePackages[]'
            }
        }
    }
}

Write-Host "Manifest OK: $($manifest.game) $($manifest.version) [$($manifest.status)]"
