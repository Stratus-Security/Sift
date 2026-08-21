#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string] $Version,

    [Parameter(Mandatory = $true)]
    [ValidateSet('win-x64', 'win-arm64', 'linux-x64', 'linux-arm64', 'osx-x64', 'osx-arm64')]
    [string] $RuntimeIdentifier,

    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$artifactRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot 'artifacts'))
$runtimeParts = $RuntimeIdentifier.Split('-', 2)
$targetSystem = $runtimeParts[0]
$targetArchitecture = $runtimeParts[1]
$hostSystem = if ($IsWindows) { 'win' } elseif ($IsLinux) { 'linux' } elseif ($IsMacOS) { 'osx' } else { 'unsupported' }
$hostArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant()

if ($hostSystem -ne $targetSystem -or $hostArchitecture -ne $targetArchitecture) {
    throw "Native AOT builds must run on the target platform. This host is $hostSystem-$hostArchitecture, not $RuntimeIdentifier."
}

$resolvedOutput = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    Join-Path $artifactRoot "release\$RuntimeIdentifier"
}
elseif ([System.IO.Path]::IsPathRooted($OutputPath)) {
    [System.IO.Path]::GetFullPath($OutputPath)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputPath))
}

if (-not $resolvedOutput.StartsWith(
    $artifactRoot + [System.IO.Path]::DirectorySeparatorChar,
    [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Release output must remain under $artifactRoot."
}

if (Test-Path -LiteralPath $resolvedOutput) {
    Remove-Item -LiteralPath $resolvedOutput -Recurse -Force
}

New-Item -ItemType Directory -Path $resolvedOutput | Out-Null
$publishPath = Join-Path $artifactRoot "publish-$RuntimeIdentifier"
if (Test-Path -LiteralPath $publishPath) {
    Remove-Item -LiteralPath $publishPath -Recurse -Force
}

New-Item -ItemType Directory -Path $publishPath | Out-Null
$projectPath = Join-Path $repositoryRoot 'src/Stratus.Sift.Cli/Stratus.Sift.Cli.csproj'
$contractsPath = Join-Path $repositoryRoot 'src/Stratus.Sift.Contracts/Stratus.Sift.Contracts.csproj'
$runtimeLockPath = Join-Path $repositoryRoot "eng/locks/packages.$RuntimeIdentifier.lock.json"
if (-not (Test-Path -LiteralPath $runtimeLockPath -PathType Leaf)) {
    throw "The dependency lock file for $RuntimeIdentifier is missing."
}

try {
    & dotnet restore $contractsPath --locked-mode
    & dotnet restore $projectPath `
        --locked-mode `
        --runtime $RuntimeIdentifier `
        --no-dependencies `
        --lock-file-path $runtimeLockPath `
        -p:PublishAot=true
    & dotnet publish $projectPath `
        --configuration Release `
        --runtime $RuntimeIdentifier `
        --self-contained true `
        --no-restore `
        --output $publishPath `
        -p:Version=$Version `
        -p:AssemblyVersion="$Version.0" `
        -p:FileVersion="$Version.0" `
        -p:PublishAot=true `
        -p:PublishTrimmed=true `
        -p:ContinuousIntegrationBuild=true `
        -p:PathMap="$repositoryRoot=/_/" `
        -p:DebugType=None `
        -p:DebugSymbols=false `
        -p:StripSymbols=true

    $publishedName = if ($IsWindows) { 'stratus-sift.exe' } else { 'stratus-sift' }
    $publishedExecutable = Join-Path $publishPath $publishedName
    if (-not (Test-Path -LiteralPath $publishedExecutable -PathType Leaf)) {
        throw "The $RuntimeIdentifier publish did not produce $publishedName."
    }

    $unexpectedFiles = @(Get-ChildItem -LiteralPath $publishPath -File | Where-Object Name -ne $publishedName)
    if ($unexpectedFiles.Count -gt 0) {
        throw "Unexpected files were produced beside the native executable: $($unexpectedFiles.Name -join ', ')"
    }

    $releaseName = "stratus-sift-$RuntimeIdentifier"
    if ($IsWindows) {
        $releaseName += '.exe'
    }

    $releaseExecutable = Join-Path $resolvedOutput $releaseName
    Copy-Item -LiteralPath $publishedExecutable -Destination $releaseExecutable
    if (-not $IsWindows) {
        & chmod 755 $releaseExecutable
    }

    $checksumPath = Join-Path $resolvedOutput "SHA256SUMS-$RuntimeIdentifier.txt"
    $hash = (Get-FileHash -LiteralPath $releaseExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksums = @("$hash  $releaseName")
    [System.IO.File]::WriteAllLines($checksumPath, $checksums, [System.Text.UTF8Encoding]::new($false))
}
finally {
    if (Test-Path -LiteralPath $publishPath) {
        Remove-Item -LiteralPath $publishPath -Recurse -Force
    }
}

Write-Host "Built Stratus Sift $Version for $RuntimeIdentifier in $resolvedOutput."
