#Requires -Version 7.2
[CmdletBinding()]
param(
    [string] $ArtifactPath
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$deniedIdentifierHashes = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
@(
    '89497d797bf96c6bbb8e3af01cd0ca0310b1623fff9f6d5c51997d3701864381',
    '1b74cc1fdcbe91d53627f2e0f305d242edee0affc3bf652cf5a05bc2cdc26fb4',
    'b12b9dcefa38633710308d2ac2ff0641d366e15a4937d83bc48689ae407e7b32',
    '6c55c1b146951ae5ea1b842483893237ed40a7d74921a2f713f1e533b44ab36a',
    '3c99c62343e3789bb0d43a95086f894ba0612044ae14c95b1664f8319f5e3c9f',
    '607c5f4b19efcf9def2240899864dc900b6132cf9396e289f39432f9b441d0e0',
    '0d23a5780bb98cddc07dba83c4e1a6607fa712acadcb92b836ca29bc5af7f111'
) | ForEach-Object { [void] $deniedIdentifierHashes.Add($_) }
$artifactAllowedIdentifierHashes = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
@(
    # Framework configuration metadata name; this does not contain a secrets identifier or value.
    '0d23a5780bb98cddc07dba83c4e1a6607fa712acadcb92b836ca29bc5af7f111'
) | ForEach-Object { [void] $artifactAllowedIdentifierHashes.Add($_) }
$publicNamespace = 'Stratus.Sift'
$namespacePattern = [regex]::new(
    '(?m)^\s*(?:global\s+)?(?:namespace|using)\s+(?<name>Stratus\.[A-Za-z0-9_.]+)',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
$identifierPattern = [regex]::new(
    '\b[A-Za-z_][A-Za-z0-9_]*\b',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
$identifierScannerSource = @'
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

public static class PublicBoundaryIdentifierScanner
{
    public static string FindDeniedIdentifierHash(string content, IEnumerable<string> deniedHashes)
    {
        var denied = new HashSet<string>(deniedHashes, StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < content.Length; index++)
        {
            var current = content[index];
            if (!IsIdentifierStart(current)
                || (index > 0 && IsIdentifierPart(content[index - 1])))
            {
                continue;
            }

            var end = index + 1;
            while (end < content.Length && IsIdentifierPart(content[end]))
            {
                end++;
            }

            var identifier = content.Substring(index, end - index);
            if (seen.Add(identifier))
            {
                var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identifier.ToLowerInvariant()))).ToLowerInvariant();
                if (denied.Contains(hash))
                {
                    return hash;
                }
            }

            index = end - 1;
        }

        return string.Empty;
    }

    private static bool IsIdentifierStart(char value)
        => value == '_' || (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');

    private static bool IsIdentifierPart(char value)
        => IsIdentifierStart(value) || (value >= '0' && value <= '9');
}
'@
Add-Type -TypeDefinition $identifierScannerSource -Language CSharp
$personalPathPattern = [regex]::new(
    '(?i)(?:[A-Z]:\\Users\\[^\\/\s]+|/(?:Users|home)/[^/\s]+)',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
$emailPattern = [regex]::new(
    '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
$textExtensions = @(
    '.cs', '.csproj', '.json', '.md', '.props', '.ps1', '.slnx', '.targets', '.txt', '.yml', '.yaml'
)
$violations = [System.Collections.Generic.List[string]]::new()

function Get-IdentifierHash([string] $Value) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant())
    return [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Test-PublicContent(
    [string] $Location,
    [string] $Content,
    [bool] $CheckEmail = $true) {
    foreach ($match in $namespacePattern.Matches($Content)) {
        if (-not $match.Groups['name'].Value.StartsWith(
            $publicNamespace,
            [System.StringComparison]::Ordinal)) {
            $violations.Add("$Location contains a namespace outside the public Sift boundary.")
        }
    }

    $deniedHash = [PublicBoundaryIdentifierScanner]::FindDeniedIdentifierHash($Content, $deniedIdentifierHashes)
    if (-not [string]::IsNullOrEmpty($deniedHash)) {
        $violations.Add("$Location contains a restricted identifier ($deniedHash).")
    }

    if ($personalPathPattern.IsMatch($Content)) {
        $violations.Add("$Location contains a local user path.")
    }

    if ($CheckEmail) {
        foreach ($match in $emailPattern.Matches($Content)) {
            $isProjectAddress =
                $match.Value.EndsWith('@stratussecurity.com', [System.StringComparison]::OrdinalIgnoreCase) -or
                $match.Value.EndsWith('@stratus.security', [System.StringComparison]::OrdinalIgnoreCase)
            if (-not $isProjectAddress) {
                $violations.Add("$Location contains a non-project email address.")
            }
        }
    }
}

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
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        continue
    }

    if (($relativePath -match '(^|/)(bin|obj|artifacts|TestResults)(/|$)') -or
        ($relativePath -match '\.(dll|exe|pdb|nupkg|snupkg|zip)$')) {
        $violations.Add("Generated or binary file is tracked: $relativePath")
    }

    if ($textExtensions -notcontains [System.IO.Path]::GetExtension($relativePath)) {
        continue
    }

    Test-PublicContent $relativePath ([System.IO.File]::ReadAllText($fullPath))
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
    $artifactDeniedIdentifierHashes = [System.Collections.Generic.HashSet[string]]::new(
        $deniedIdentifierHashes,
        [System.StringComparer]::Ordinal)
    $artifactDeniedIdentifierHashes.ExceptWith($artifactAllowedIdentifierHashes)
    $deniedIdentifierHashes = $artifactDeniedIdentifierHashes
    Test-PublicContent 'Release executable' $ascii $false
    Test-PublicContent 'Release executable' $unicode $false
}

if ($violations.Count -gt 0) {
    throw "Public boundary verification failed:`n - $($violations | Sort-Object -Unique | Join-String -Separator "`n - ")"
}

Write-Host "Public boundary verified across $($trackedFiles.Count) repository files."
