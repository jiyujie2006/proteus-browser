#Requires -Version 7.2

<#
.SYNOPSIS
Turns one completed Windows Chromium build into the complete hard-M0 bundle and
records consumed by the Sigstore builder workflow.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('A', 'B')]
    [string] $Slot,

    [Parameter(Mandatory)]
    [string] $SourceRoot,

    [Parameter(Mandatory)]
    [string] $DepotToolsRoot,

    [Parameter(Mandatory)]
    [string] $ArtifactRoot,

    [Parameter(Mandatory)]
    [string] $Git,

    [Parameter(Mandatory)]
    [string] $Python
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'finalize-m0-build.ps1 must run on Windows.'
}

function Resolve-ControlledPath {
    param([string] $Path, [string] $Label)
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path -match '[\x00-\x1f\x7f]') {
        throw "$Label must be a safe absolute path."
    }
    return [IO.Path]::GetFullPath($Path)
}

function Assert-OrdinaryFile {
    param([string] $Path, [string] $Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must be an ordinary non-reparse file: $Path"
    }
}

function Invoke-Native {
    param(
        [string] $FilePath,
        [string[]] $Arguments = @(),
        [switch] $Quiet
    )
    if ($Quiet) {
        & $FilePath @Arguments | Out-Null
    }
    else {
        & $FilePath @Arguments
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Native command failed with exit code $LASTEXITCODE`: $FilePath"
    }
}

function Invoke-NativeToFreshFile {
    param(
        [string] $FilePath,
        [string[]] $Arguments,
        [string] $Destination
    )
    if (Test-Path -LiteralPath $Destination) {
        throw "Output must be fresh: $Destination"
    }
    $lines = @(& $FilePath @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "Native command failed with exit code $LASTEXITCODE`: $FilePath"
    }
    if ($lines.Count -eq 0) {
        throw "Native command produced no output: $FilePath"
    }
    $contents = ($lines -join "`n") + "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($contents)
    $stream = [IO.File]::Open(
        $Destination,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

$sourceRootPath = Resolve-ControlledPath $SourceRoot 'SourceRoot'
$depotToolsPath = Resolve-ControlledPath $DepotToolsRoot 'DepotToolsRoot'
$artifactRootPath = Resolve-ControlledPath $ArtifactRoot 'ArtifactRoot'
$gitPath = Resolve-ControlledPath $Git 'Git'
$pythonPath = Resolve-ControlledPath $Python 'Python'
Assert-OrdinaryFile $gitPath 'Git'
Assert-OrdinaryFile $pythonPath 'Python'

$engineRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$repoRoot = [IO.Path]::GetFullPath((Join-Path $engineRoot '..'))
$source = Join-Path $sourceRootPath 'src'
$outRelative = 'out/Proteus'
$outDir = Join-Path $source 'out\Proteus'
$dependencyLock = Join-Path $sourceRootPath '.proteus-dependencies.json'
$gn = Join-Path $depotToolsPath 'gn.bat'
$buildRoot = Join-Path $artifactRootPath "builds\windows-x64\$Slot"
$records = Join-Path $buildRoot 'records'
$bundle = Join-Path $buildRoot 'bundle'

Assert-OrdinaryFile $dependencyLock 'Resolved dependency lock'
Assert-OrdinaryFile $gn 'Pinned gn.bat'
Assert-OrdinaryFile (Join-Path $outDir 'chrome.exe') 'Built Chromium executable'
if (Test-Path -LiteralPath $buildRoot) {
    throw "M0 build-record root must be fresh: $buildRoot"
}
New-Item -ItemType Directory -Path $records -ErrorAction Stop | Out-Null

$node = (Get-Command node -CommandType Application -ErrorAction Stop |
    Select-Object -First 1).Source
$effectiveRecord = Join-Path $records 'effective-gn-args.json'
$windowsToolchainSelection = Join-Path $outDir 'windows-toolchain-selection.gn'
$toolchainLock = Join-Path $records 'complete-toolchain-lock.json'
$runtimeDeps = Join-Path $records 'runtime-deps.txt'
$manifest = Join-Path $records 'bundle-manifest.json'
$liveReport = Join-Path $records 'live-report.json'
$sbom = Join-Path $records 'build-sbom.cdx.json'
$copiedDependencyLock = Join-Path $records 'resolved-dependency-lock.json'

Write-Host '==> recording expanded GN arguments'
Invoke-NativeToFreshFile -FilePath $node -Arguments @(
    (Join-Path $PSScriptRoot 'effective-gn-args.mjs'),
    'create',
    '--platform',
    'windows-x64',
    '--configuration',
    'x86_64',
    $outRelative,
    (Join-Path $outDir 'effective-args.gn')
) -Destination $effectiveRecord

$env:DEPOT_TOOLS_WIN_TOOLCHAIN = '0'
Write-Host '==> capturing Chromium Windows toolchain selection'
Invoke-NativeToFreshFile -FilePath $pythonPath -Arguments @(
    (Join-Path $source 'build\vs_toolchain.py'),
    'get_toolchain_dir'
) -Destination $windowsToolchainSelection

Write-Host '==> capturing the complete platform toolchain'
Invoke-Native -FilePath $node -Arguments @(
    (Join-Path $PSScriptRoot 'toolchain-lock.mjs'),
    'capture',
    '--platform',
    'windows-x64',
    '--configuration',
    'x86_64',
    $outDir,
    '--client-root',
    $sourceRootPath,
    '--depot-tools',
    $depotToolsPath,
    '--dependency-lock',
    $dependencyLock,
    '--effective-args-record',
    $effectiveRecord,
    '--windows-toolchain-selection',
    $windowsToolchainSelection,
    '--git',
    $gitPath,
    '--python',
    $pythonPath,
    '--lock',
    $toolchainLock
) -Quiet
Copy-Item -LiteralPath $dependencyLock -Destination $copiedDependencyLock `
    -ErrorAction Stop

Write-Host '==> resolving the GN runtime dependency closure'
Push-Location -LiteralPath $source
try {
    Invoke-NativeToFreshFile -FilePath $gn -Arguments @(
        'desc',
        $outRelative,
        'chrome',
        'runtime_deps'
    ) -Destination $runtimeDeps
}
finally {
    Pop-Location
}

Write-Host '==> packaging the complete engine runtime bundle'
Invoke-NativeToFreshFile -FilePath $node -Arguments @(
    (Join-Path $PSScriptRoot 'package-engine.mjs'),
    '--out-dir',
    $outDir,
    '--out-dir-relative',
    $outRelative,
    '--bundle-dir',
    $bundle,
    '--platform',
    'windows-x64',
    '--runtime-deps',
    $runtimeDeps,
    '--dependency-lock',
    $copiedDependencyLock,
    '--effective-gn-args',
    $effectiveRecord,
    '--toolchain-lock',
    $toolchainLock,
    '--credits-out-dir',
    $outDir
) -Destination $manifest

$entrypoint = Join-Path $bundle 'chrome.exe'
Assert-OrdinaryFile $entrypoint 'Packaged Chromium executable'

Write-Host '==> running the artifact-driven V1-V5 verification ruler'
Invoke-NativeToFreshFile -FilePath $node -Arguments @(
    (Join-Path $repoRoot 'verify-lab\tools\drive-chrome.mjs'),
    '--json',
    '--external-containment',
    '--chrome',
    $entrypoint,
    '--platform',
    'windows-x64'
) -Destination $liveReport

$createdAt = [DateTime]::UtcNow.ToString(
    'yyyy-MM-ddTHH:mm:ss.fffZ',
    [Globalization.CultureInfo]::InvariantCulture
)
Write-Host '==> generating the build-derived CycloneDX SBOM'
Invoke-NativeToFreshFile -FilePath $node -Arguments @(
    (Join-Path $PSScriptRoot 'build-sbom.mjs'),
    '--bundle-dir',
    $bundle,
    '--bundle-manifest',
    $manifest,
    '--dependency-lock',
    $copiedDependencyLock,
    '--toolchain-lock',
    $toolchainLock,
    '--effective-gn-args',
    $effectiveRecord,
    '--platform',
    'windows-x64',
    '--slot',
    $Slot,
    '--created-at',
    $createdAt
) -Destination $sbom

Write-Host "==> complete M0 build records ready under $buildRoot"
