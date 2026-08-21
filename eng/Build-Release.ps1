#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string] $Version,

    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$artifactRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot 'artifacts'))
$resolvedOutput = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    Join-Path $artifactRoot 'release'
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
$publishPath = Join-Path $artifactRoot 'publish-win-x64'
if (Test-Path -LiteralPath $publishPath) {
    Remove-Item -LiteralPath $publishPath -Recurse -Force
}

New-Item -ItemType Directory -Path $publishPath | Out-Null
try {
    & dotnet restore (Join-Path $repositoryRoot 'Stratus.Sift.slnx') --locked-mode
    & dotnet publish (Join-Path $repositoryRoot 'src\Stratus.Sift.Cli\Stratus.Sift.Cli.csproj') `
        --configuration Release `
        --runtime win-x64 `
        --self-contained true `
        --no-restore `
        --output $publishPath `
        -p:Version=$Version `
        -p:AssemblyVersion="$Version.0" `
        -p:FileVersion="$Version.0" `
        -p:PublishSingleFile=true `
        -p:PublishTrimmed=false `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:ContinuousIntegrationBuild=true `
        -p:PathMap="$repositoryRoot=/_/" `
        -p:DebugType=None `
        -p:DebugSymbols=false

    $publishedExecutable = Join-Path $publishPath 'stratus-sift.exe'
    if (-not (Test-Path -LiteralPath $publishedExecutable -PathType Leaf)) {
        throw 'The Windows x64 publish did not produce stratus-sift.exe.'
    }

    $unexpectedFiles = @(Get-ChildItem -LiteralPath $publishPath -File | Where-Object Name -ne 'stratus-sift.exe')
    if ($unexpectedFiles.Count -gt 0) {
        throw "Unexpected files were produced beside the single executable: $($unexpectedFiles.Name -join ', ')"
    }

    $releaseExecutable = Join-Path $resolvedOutput 'stratus-sift-win-x64.exe'
    Copy-Item -LiteralPath $publishedExecutable -Destination $releaseExecutable
    $archivePath = Join-Path $resolvedOutput 'stratus-sift-win-x64.zip'
    Compress-Archive -LiteralPath $releaseExecutable -DestinationPath $archivePath -CompressionLevel Optimal

    $checksumPath = Join-Path $resolvedOutput 'SHA256SUMS.txt'
    $checksums = foreach ($file in @($releaseExecutable, $archivePath)) {
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $([System.IO.Path]::GetFileName($file))"
    }
    [System.IO.File]::WriteAllLines($checksumPath, $checksums, [System.Text.UTF8Encoding]::new($false))
}
finally {
    if (Test-Path -LiteralPath $publishPath) {
        Remove-Item -LiteralPath $publishPath -Recurse -Force
    }
}

Write-Host "Built Stratus Sift $Version release assets in $resolvedOutput."
