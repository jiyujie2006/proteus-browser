#Requires -Version 7.2

<#
.SYNOPSIS
Fetches, patches, and builds the pinned Proteus Chromium target on Windows x64.

.DESCRIPTION
The checkout roots must not already exist. The script delegates provisioning to
fetch-chromium.ps1, verifies the resolved dependency lock before patching and
again before building, applies only the active M0 series, and invokes the
verified depot_tools gn/autoninja wrappers.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $Baseline = (Join-Path $PSScriptRoot '..\CHROMIUM_BASELINE'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $SourceRoot = (Join-Path $PSScriptRoot '..\src'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $DepotToolsRoot = (Join-Path $PSScriptRoot '..\depot_tools')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'build-windows.ps1 must run on Windows.'
}

function Remove-AmbientGitEnvironment {
    Get-ChildItem Env: |
        Where-Object { $_.Name.StartsWith('GIT_', [StringComparison]::Ordinal) } |
        ForEach-Object { Remove-Item -LiteralPath "Env:$($_.Name)" -ErrorAction Stop }

    $env:GIT_CONFIG_NOSYSTEM = '1'
    $env:GIT_CONFIG_GLOBAL = 'NUL'
    $env:GIT_CONFIG_COUNT = '1'
    $env:GIT_CONFIG_KEY_0 = 'core.longpaths'
    $env:GIT_CONFIG_VALUE_0 = 'true'
    $env:GIT_TERMINAL_PROMPT = '0'
}

function Resolve-NativeApplication {
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )

    $command = Get-Command -Name $Name -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    if (-not [IO.Path]::IsPathFullyQualified($command.Source)) {
        throw "$Name must resolve to an absolute executable path."
    }
    return [IO.Path]::GetFullPath($command.Source)
}

function Invoke-Native {
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [Parameter()]
        [string[]] $Arguments = @(),

        [Parameter()]
        [switch] $Quiet
    )

    if ($Quiet) {
        & $FilePath @Arguments | Out-Null
    }
    else {
        & $FilePath @Arguments
    }
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "Native command failed with exit code ${exitCode}: $FilePath"
    }
}

function Invoke-NativeOutputToNewFile {
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [Parameter(Mandatory)]
        [string[]] $Arguments,

        [Parameter(Mandatory)]
        [string] $Destination
    )

    $lines = @(& $FilePath @Arguments)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "Native command failed with exit code ${exitCode}: $FilePath"
    }
    if ($lines.Count -eq 0) {
        throw "Native command produced no effective GN args: $FilePath"
    }
    $contents = ($lines -join [Environment]::NewLine) + [Environment]::NewLine
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

function Assert-ControlledAbsolutePath {
    param(
        [Parameter(Mandatory)]
        [string] $InputPath,

        [Parameter(Mandatory)]
        [string] $Label
    )

    if ($InputPath -match '[\x00-\x1f\x7f]') {
        throw "$Label contains a control character."
    }
    if (-not [IO.Path]::IsPathFullyQualified($InputPath)) {
        throw "$Label must be an absolute path."
    }
    return [IO.Path]::GetFullPath($InputPath)
}

function Invoke-DependencyLock {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('clean', 'patched')]
        [string] $ChromiumState
    )

    $dependencyLock = Join-Path $script:EngineRoot 'scripts\dependency-lock.mjs'
    if (-not (Test-Path -LiteralPath $dependencyLock -PathType Leaf)) {
        throw (
            'Required dependency-lock.mjs is not present; cannot verify ' +
            "dependency state '$ChromiumState'."
        )
    }
    Invoke-Native -FilePath $script:NodeBin -Arguments @(
        $dependencyLock,
        'verify',
        '--client-root',
        $script:SourceRootPath,
        '--depot-tools',
        $script:DepotToolsPath,
        '--chromium-state',
        $ChromiumState
    )
}

function Assert-OrdinaryFile {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label was not produced: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must be an ordinary non-reparse file: $Path"
    }
}

Remove-AmbientGitEnvironment

$script:EngineRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$script:SourceRootPath = Assert-ControlledAbsolutePath -InputPath $SourceRoot `
    -Label 'SourceRoot'
$script:DepotToolsPath = Assert-ControlledAbsolutePath -InputPath $DepotToolsRoot `
    -Label 'DepotToolsRoot'
$baselinePath = [IO.Path]::GetFullPath($Baseline)
$script:NodeBin = Resolve-NativeApplication -Name 'node'
$script:GitBin = Resolve-NativeApplication -Name 'git'
$env:PROTEUS_GIT_BIN = $script:GitBin
$env:PROTEUS_CHROMIUM_SRC = $script:SourceRootPath
$env:PROTEUS_DEPOT_TOOLS_DIR = $script:DepotToolsPath
$env:DEPOT_TOOLS_UPDATE = '0'
$env:DEPOT_TOOLS_METRICS = '0'
$env:DEPOT_TOOLS_WIN_TOOLCHAIN = '0'

$fetchScript = Join-Path $script:EngineRoot 'scripts\fetch-chromium.ps1'
& $fetchScript -Baseline $baselinePath `
    -SourceRoot $script:SourceRootPath `
    -DepotToolsRoot $script:DepotToolsPath

$source = Join-Path $script:SourceRootPath 'src'
$env:Path = "$($script:DepotToolsPath)$([IO.Path]::PathSeparator)$env:Path"

Invoke-DependencyLock -ChromiumState 'clean'
Write-Host '==> applying the active M0 patch series'
Invoke-Native -FilePath $script:NodeBin -Arguments @(
    (Join-Path $script:EngineRoot 'scripts\apply-patches.mjs')
)
Invoke-DependencyLock -ChromiumState 'patched'

Invoke-Native -FilePath $script:NodeBin -Arguments @(
    (Join-Path $script:EngineRoot 'scripts\depot-tools-checkout.mjs'),
    '--root',
    $script:DepotToolsPath
) -Quiet
Invoke-Native -FilePath $script:NodeBin -Arguments @(
    (Join-Path $script:EngineRoot 'scripts\chromium-checkout.mjs'),
    '--source',
    $source,
    '--state',
    'patched'
) -Quiet

if ($env:PROTEUS_CC_WRAPPER) {
    throw 'PROTEUS_CC_WRAPPER is not part of the locked M0 build contract.'
}

$gn = Join-Path $script:DepotToolsPath 'gn.bat'
$autoninja = Join-Path $script:DepotToolsPath 'autoninja.bat'
Assert-OrdinaryFile -Path $gn -Label 'Pinned depot_tools gn.bat'
Assert-OrdinaryFile -Path $autoninja -Label 'Pinned depot_tools autoninja.bat'

$outDir = Join-Path $source 'out\Proteus'
if (Test-Path -LiteralPath $outDir) {
    throw "Build output directory must not already exist: $outDir"
}
$outParent = Join-Path $source 'out'
if (Test-Path -LiteralPath $outParent) {
    if (-not (Test-Path -LiteralPath $outParent -PathType Container)) {
        throw "Chromium out path is not a directory: $outParent"
    }
    $outParentItem = Get-Item -LiteralPath $outParent -Force
    if (($outParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Chromium out directory must not be a reparse point: $outParent"
    }
}
else {
    New-Item -ItemType Directory -Path $outParent -ErrorAction Stop | Out-Null
}
New-Item -ItemType Directory -Path $outDir -ErrorAction Stop | Out-Null
$lockedArgs = Join-Path $script:EngineRoot 'build\args.gn'
$targetCpuAssignments = @(
    Get-Content -LiteralPath $lockedArgs |
        Where-Object { $_ -eq 'target_cpu = "x64"' }
)
if ($targetCpuAssignments.Count -ne 1) {
    throw 'Locked args.gn must contain exactly one x64 target_cpu assignment.'
}
Copy-Item -LiteralPath $lockedArgs `
    -Destination (Join-Path $outDir 'args.gn') `
    -ErrorAction Stop

# Verify the exact dependency graph immediately before the first build tool.
Invoke-DependencyLock -ChromiumState 'patched'

Push-Location -LiteralPath $source
try {
    Write-Host '==> gn gen out\Proteus with the locked Windows x64 args'
    Invoke-Native -FilePath $gn -Arguments @(
        'gen',
        'out\Proteus',
        '--fail-on-unused-args'
    )

    $effectiveArgs = Join-Path $outDir 'effective-args.gn'
    Write-Host '==> capturing expanded GN args from the generated build'
    Invoke-NativeOutputToNewFile -FilePath $gn -Arguments @(
        'args',
        'out\Proteus',
        '--list',
        '--short'
    ) -Destination $effectiveArgs

    Write-Host '==> autoninja Windows x64 chrome + Network Time unit-test host'
    Invoke-Native -FilePath $autoninja -Arguments @(
        '-C',
        'out\Proteus',
        'chrome',
        'components_unittests'
    )
}
finally {
    Pop-Location
}

$artifact = Join-Path $outDir 'chrome.exe'
Assert-OrdinaryFile -Path $artifact -Label 'Windows Chromium executable'
$networkTimeTest = Join-Path $outDir 'components_unittests.exe'
Assert-OrdinaryFile -Path $networkTimeTest `
    -Label 'Windows components_unittests executable'
Write-Host '==> verifying the Network Time feature disable/explicit-enable paths'
Invoke-Native -FilePath $networkTimeTest -Arguments @(
    '--gtest_filter=NetworkTimeTrackerTest.NoNetworkQueryWhileFeatureDisabled',
    '--test-launcher-bot-mode'
)

Write-Host '==> Windows x64 build complete'
Write-Host "    build output directory: $outDir"
Write-Host "    executable: $artifact"
Write-Host "    effective GN args: $effectiveArgs"
