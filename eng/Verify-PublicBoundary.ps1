#Requires -Version 7.2
[CmdletBinding()]
param(
    [string] $ArtifactPath
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$deniedTokens = @(
    'Stratus.Snare.',
    'ApplicationDbContext',
    'PlatformWorkItem',
    'OrganizationId',
    'TenantId',
    'ManagedFindingEvidence',
    'RemediationBatch',
    'STRATUS_SCANNER_FEED',
    'UserSecretsId',
    'C:\Users\',
    '/Users/',
    '/home/'
)
$textExtensions = @(
    '.cs', '.csproj', '.json', '.md', '.props', '.ps1', '.slnx', '.targets', '.txt', '.yml', '.yaml'
)
$violations = [System.Collections.Generic.List[string]]::new()

$trackedFiles = @(& git -C $repositoryRoot ls-files --cached --others --exclude-standard | Sort-Object -Unique)
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to enumerate tracked files.'
}

foreach ($relativePath in $trackedFiles) {
    if (($relativePath.Contains('..', [System.StringComparison]::Ordinal)) -or
        ([System.IO.Path]::IsPathRooted($relativePath))) {
        $violations.Add("Unsafe tracked path: $relativePath")
        continue
    }

    $fullPath = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $relativePath))
    if (-not ($fullPath.StartsWith(
        $repositoryRoot + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase))) {
        $violations.Add("Tracked path escapes the repository: $relativePath")
        continue
    }

    if (($relativePath -match '(^|/)(bin|obj|artifacts|TestResults)(/|$)') -or
        ($relativePath -match '\.(dll|exe|pdb|nupkg|snupkg|zip)$')) {
        $violations.Add("Generated or binary file is tracked: $relativePath")
    }

    if (($relativePath -eq 'eng/Verify-PublicBoundary.ps1') -or
        ($textExtensions -notcontains [System.IO.Path]::GetExtension($relativePath))) {
        continue
    }

    $content = [System.IO.File]::ReadAllText($fullPath)
    foreach ($token in $deniedTokens) {
        if ($content.Contains($token, [System.StringComparison]::OrdinalIgnoreCase)) {
            $violations.Add("$relativePath contains denied token '$token'.")
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($ArtifactPath)) {
    $resolvedArtifact = [System.IO.Path]::GetFullPath($ArtifactPath)
    if (-not ($resolvedArtifact.StartsWith(
        $repositoryRoot + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase))) {
        throw 'ArtifactPath must remain inside the repository.'
    }
    if (-not (Test-Path -LiteralPath $resolvedArtifact -PathType Leaf)) {
        throw "Release artifact not found: $resolvedArtifact"
    }
    $artifactExtension = [System.IO.Path]::GetExtension($resolvedArtifact)
    if ($artifactExtension -notin @('', '.exe')) {
        throw 'Only an unpacked release executable may be supplied for binary boundary verification.'
    }

    $bytes = [System.IO.File]::ReadAllBytes($resolvedArtifact)
    $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
    $unicode = [System.Text.Encoding]::Unicode.GetString($bytes)
    foreach ($token in $deniedTokens) {
        if (($ascii.Contains($token, [System.StringComparison]::OrdinalIgnoreCase)) -or
            ($unicode.Contains($token, [System.StringComparison]::OrdinalIgnoreCase))) {
            $violations.Add("Release executable contains denied token '$token'.")
        }
    }
}

if ($violations.Count -gt 0) {
    throw "Public boundary verification failed:`n - $($violations -join "`n - ")"
}

Write-Host "Public boundary verified across $($trackedFiles.Count) repository files."
