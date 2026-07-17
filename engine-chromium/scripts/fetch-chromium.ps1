#Requires -Version 7.2

<#
.SYNOPSIS
Fetches the exact Chromium and depot_tools revisions declared by
CHROMIUM_BASELINE into fresh Windows build roots.

.DESCRIPTION
This is the native Windows counterpart of fetch-chromium.sh. It accepts only
the three declared paths, clears every ambient GIT_* override before invoking
Git, pins both repositories, verifies the official Chromium tag, refuses
pre-existing checkout roots, and finishes with the shared checkout auditors.
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
    throw 'fetch-chromium.ps1 must run on Windows.'
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

function Invoke-NativeOutput {
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [Parameter()]
        [string[]] $Arguments = @()
    )

    $lines = @(& $FilePath @Arguments)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "Native command failed with exit code ${exitCode}: $FilePath"
    }
    return ($lines -join "`n").Trim()
}

function Normalize-FreshRoot {
    param(
        [Parameter(Mandatory)]
        [string] $InputPath,

        [Parameter(Mandatory)]
        [string] $Label
    )

    if ($InputPath -match '[\x00-\x1f\x7f]') {
        throw "$Label contains a control character."
    }
    if ($InputPath.StartsWith('\\?\') -or $InputPath.StartsWith('\\.\')) {
        throw "$Label must not use a Windows device path."
    }
    if (-not [IO.Path]::IsPathFullyQualified($InputPath)) {
        throw "$Label must be an absolute path."
    }
    if ($InputPath.EndsWith('\') -or $InputPath.EndsWith('/')) {
        throw "$Label must name a non-root directory without a trailing separator."
    }

    $fullPath = [IO.Path]::GetFullPath($InputPath)
    $pathRoot = [IO.Path]::GetPathRoot($fullPath)
    $trimSeparators = [char[]] @(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    if ($fullPath.TrimEnd($trimSeparators) -eq
        $pathRoot.TrimEnd($trimSeparators)) {
        throw "$Label must not be a filesystem root."
    }

    $parent = [IO.Path]::GetDirectoryName($fullPath)
    $name = [IO.Path]::GetFileName($fullPath)
    if ([string]::IsNullOrWhiteSpace($parent) -or
        [string]::IsNullOrWhiteSpace($name) -or
        $name -eq '.' -or
        $name -eq '..') {
        throw "$Label must name a non-root directory."
    }
    if ($name.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
        throw "$Label contains an invalid filename character."
    }
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "Parent of $Label does not exist: $parent"
    }

    $parentItem = Get-Item -LiteralPath $parent -Force
    $ancestor = $parentItem
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Ancestors of $Label must not contain a reparse point: $($ancestor.FullName)"
        }
        $ancestor = $ancestor.Parent
    }
    return (Join-Path $parentItem.FullName $name)
}

function Test-PathNested {
    param(
        [Parameter(Mandatory)]
        [string] $Candidate,

        [Parameter(Mandatory)]
        [string] $Parent
    )

    $separator = [IO.Path]::DirectorySeparatorChar
    $trimSeparators = [char[]] @(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $candidatePrefix = $Candidate.TrimEnd($trimSeparators) + $separator
    $parentPrefix = $Parent.TrimEnd($trimSeparators) + $separator
    return $candidatePrefix.StartsWith(
        $parentPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Get-BaselineValue {
    param(
        [Parameter(Mandatory)]
        [string] $Key
    )

    $value = Invoke-NativeOutput -FilePath $script:NodeBin -Arguments @(
        $script:BaselineParser,
        '--file',
        $script:BaselinePath,
        '--get',
        $Key
    )
    if ([string]::IsNullOrWhiteSpace($value) -or $value -match '[\r\n]') {
        throw "Baseline key $Key did not produce exactly one value."
    }
    return $value
}

function Assert-DefaultTrackedFlags {
    param(
        [Parameter(Mandatory)]
        [string] $Repository,

        [Parameter(Mandatory)]
        [string] $Label
    )

    $lines = Invoke-NativeOutput -FilePath $script:GitBin -Arguments @(
        '-C', $Repository, 'ls-files', '-v'
    )
    foreach ($line in ($lines -split "`n")) {
        if ($line.Length -gt 0 -and -not $line.StartsWith('H ')) {
            throw "$Label index contains non-default tracked-file flags."
        }
    }
}

function Assert-DepotTools {
    $origin = Invoke-NativeOutput -FilePath $script:GitBin -Arguments @(
        '-C', $script:DepotToolsPath, 'remote', 'get-url', 'origin'
    )
    $head = Invoke-NativeOutput -FilePath $script:GitBin -Arguments @(
        '-C', $script:DepotToolsPath, 'rev-parse', '--verify', 'HEAD'
    )
    $actualTree = Invoke-NativeOutput -FilePath $script:GitBin -Arguments @(
        '-C', $script:DepotToolsPath, 'write-tree'
    )
    $expectedTree = Invoke-NativeOutput -FilePath $script:GitBin -Arguments @(
        '-C', $script:DepotToolsPath, 'rev-parse', '--verify',
        "$($script:DepotToolsCommit)^{tree}"
    )
    $dirty = Invoke-NativeOutput -FilePath $script:GitBin -Arguments @(
        '-C', $script:DepotToolsPath, 'status', '--porcelain',
        '--untracked-files=all'
    )

    if ($origin -ne $script:DepotToolsRepository) {
        throw 'depot_tools origin is not the pinned canonical repository.'
    }
    if ($head -ne $script:DepotToolsCommit) {
        throw "depot_tools HEAD $head does not match $($script:DepotToolsCommit)."
    }
    if ($actualTree -ne $expectedTree) {
        throw 'depot_tools index tree differs from its pinned commit.'
    }
    if ($dirty.Length -ne 0) {
        throw 'depot_tools checkout is dirty.'
    }
    Assert-DefaultTrackedFlags -Repository $script:DepotToolsPath -Label 'depot_tools'

    foreach ($tool in @('gclient.bat')) {
        $toolPath = Join-Path $script:DepotToolsPath $tool
        if (-not (Test-Path -LiteralPath $toolPath -PathType Leaf)) {
            throw "Pinned depot_tools does not contain $tool."
        }
        Invoke-Native -FilePath $script:GitBin -Arguments @(
            '-C', $script:DepotToolsPath, 'ls-files', '--error-unmatch', $tool
        ) -Quiet
    }
}

function Assert-ChromiumOriginAndClean {
    $origin = Invoke-NativeOutput -FilePath $script:GitBin -Arguments @(
        '-C', $script:ChromiumSource, 'remote', 'get-url', 'origin'
    )
    $dirty = Invoke-NativeOutput -FilePath $script:GitBin -Arguments @(
        '-C', $script:ChromiumSource, 'status', '--porcelain',
        '--untracked-files=all'
    )
    if ($origin -ne $script:ChromiumRepository) {
        throw 'Chromium origin is not the pinned canonical repository.'
    }
    if ($dirty.Length -ne 0) {
        throw 'Chromium checkout is dirty; refusing a destructive sync.'
    }
    Assert-DefaultTrackedFlags -Repository $script:ChromiumSource -Label 'Chromium'
}

function Invoke-DependencyLockCapture {
    $dependencyLock = Join-Path $script:EngineRoot 'scripts\dependency-lock.mjs'
    if (-not (Test-Path -LiteralPath $dependencyLock -PathType Leaf)) {
        throw (
            'Required dependency-lock.mjs is not present; the fetch ' +
            'entrypoint cannot capture the resolved DEPS/CIPD lock.'
        )
    }
    Invoke-Native -FilePath $script:NodeBin -Arguments @(
        $dependencyLock,
        'capture',
        '--client-root',
        $script:SourceRootPath,
        '--depot-tools',
        $script:DepotToolsPath,
        '--chromium-state',
        'clean'
    )
}

Remove-AmbientGitEnvironment

$script:EngineRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$script:BaselineParser = Join-Path $script:EngineRoot 'scripts\baseline.mjs'
$script:BaselinePath = [IO.Path]::GetFullPath($Baseline)
$script:NodeBin = Resolve-NativeApplication -Name 'node'
$script:GitBin = Resolve-NativeApplication -Name 'git'
$env:PROTEUS_GIT_BIN = $script:GitBin

# Parse the complete baseline before any network request or checkout mutation.
Invoke-Native -FilePath $script:NodeBin -Arguments @(
    $script:BaselineParser,
    '--file',
    $script:BaselinePath,
    '--check'
) -Quiet

$script:ChromiumRepository = Get-BaselineValue -Key 'CHROMIUM_REPOSITORY'
$script:ChromiumStable = Get-BaselineValue -Key 'CHROMIUM_STABLE'
$script:ChromiumCommit = Get-BaselineValue -Key 'CHROMIUM_COMMIT'
$script:DepotToolsRepository = Get-BaselineValue -Key 'DEPOT_TOOLS_REPOSITORY'
$script:DepotToolsCommit = Get-BaselineValue -Key 'DEPOT_TOOLS_COMMIT'

$script:SourceRootPath = Normalize-FreshRoot -InputPath $SourceRoot `
    -Label 'SourceRoot'
$script:DepotToolsPath = Normalize-FreshRoot -InputPath $DepotToolsRoot `
    -Label 'DepotToolsRoot'
$script:ChromiumSource = Join-Path $script:SourceRootPath 'src'

if ((Test-PathNested -Candidate $script:SourceRootPath `
        -Parent $script:DepotToolsPath) -or
    (Test-PathNested -Candidate $script:DepotToolsPath `
        -Parent $script:SourceRootPath)) {
    throw 'SourceRoot and DepotToolsRoot must not overlap.'
}
if ((Test-Path -LiteralPath $script:SourceRootPath) -or
    (Test-Path -LiteralPath $script:DepotToolsPath)) {
    throw (
        'Fetch requires fresh, non-existent source and depot_tools roots. ' +
        'Provision a new ephemeral build directory for every invocation.'
    )
}

$env:PROTEUS_CHROMIUM_SRC = $script:SourceRootPath
$env:PROTEUS_DEPOT_TOOLS_DIR = $script:DepotToolsPath
$env:DEPOT_TOOLS_UPDATE = '0'
$env:DEPOT_TOOLS_METRICS = '0'
# Public builders do not have access to Google's internal Windows toolchain
# package. Bind gclient/gn to the runner's audited Visual Studio installation.
$env:DEPOT_TOOLS_WIN_TOOLCHAIN = '0'

Write-Host "==> cloning pinned depot_tools into $($script:DepotToolsPath)"
Invoke-Native -FilePath $script:GitBin -Arguments @(
    'clone',
    '--filter=blob:none',
    '--no-checkout',
    '--',
    $script:DepotToolsRepository,
    $script:DepotToolsPath
)
Invoke-Native -FilePath $script:GitBin -Arguments @(
    '-C', $script:DepotToolsPath, 'fetch', 'origin', $script:DepotToolsCommit
)
Invoke-Native -FilePath $script:GitBin -Arguments @(
    '-C', $script:DepotToolsPath, 'checkout', '--detach',
    $script:DepotToolsCommit
)
Assert-DepotTools

$env:Path = "$($script:DepotToolsPath)$([IO.Path]::PathSeparator)$env:Path"
$gclient = Join-Path $script:DepotToolsPath 'gclient.bat'
Assert-DepotTools

New-Item -ItemType Directory -Path $script:SourceRootPath -ErrorAction Stop |
    Out-Null
$fixtureRoot = Join-Path $script:SourceRootPath '.proteus-gclient-config'
try {
    New-Item -ItemType Directory -Path $fixtureRoot -ErrorAction Stop | Out-Null
    Push-Location -LiteralPath $fixtureRoot
    try {
        Invoke-Native -FilePath $gclient -Arguments @(
            'config',
            '--name',
            'src',
            '--unmanaged',
            $script:ChromiumRepository
        ) -Quiet
    }
    finally {
        Pop-Location
    }
    Assert-DepotTools
    Copy-Item -LiteralPath (Join-Path $fixtureRoot '.gclient') `
        -Destination (Join-Path $script:SourceRootPath '.gclient') `
        -ErrorAction Stop
}
finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction Stop
    }
}

Write-Host (
    "==> initial gclient sync of Chromium $($script:ChromiumStable) @ " +
    $script:ChromiumCommit
)
Push-Location -LiteralPath $script:SourceRootPath
try {
    Invoke-Native -FilePath $gclient -Arguments @(
        'sync',
        '-D',
        '--force',
        '--reset',
        '--with_branch_heads',
        '--revision',
        "src@$($script:ChromiumCommit)"
    )
}
finally {
    Pop-Location
}
Assert-DepotTools

if (-not (Test-Path -LiteralPath (Join-Path $script:ChromiumSource '.git') `
        -PathType Container)) {
    throw (
        'gclient did not produce a Chromium Git checkout at ' +
        $script:ChromiumSource
    )
}
Assert-ChromiumOriginAndClean

Write-Host (
    "==> verifying official tag $($script:ChromiumStable) resolves to the " +
    'pinned commit'
)
Invoke-Native -FilePath $script:GitBin -Arguments @(
    '-C',
    $script:ChromiumSource,
    'fetch',
    '--force',
    'origin',
    "refs/tags/$($script:ChromiumStable):refs/tags/$($script:ChromiumStable)"
)
$tagCommit = Invoke-NativeOutput -FilePath $script:GitBin -Arguments @(
    '-C',
    $script:ChromiumSource,
    'rev-parse',
    '--verify',
    "refs/tags/$($script:ChromiumStable)^{commit}"
)
if ($tagCommit -ne $script:ChromiumCommit) {
    throw (
        "Chromium tag resolves to $tagCommit, expected " +
        $script:ChromiumCommit
    )
}

Invoke-Native -FilePath $script:GitBin -Arguments @(
    '-C', $script:ChromiumSource, 'checkout', '--detach',
    $script:ChromiumCommit
)
$detachedHead = Invoke-NativeOutput -FilePath $script:GitBin -Arguments @(
    '-C', $script:ChromiumSource, 'rev-parse', '--verify', 'HEAD'
)
if ($detachedHead -ne $script:ChromiumCommit) {
    throw 'Failed to detach Chromium at the pinned commit.'
}

Write-Host "==> syncing DEPS exactly at $($script:ChromiumCommit)"
Push-Location -LiteralPath $script:SourceRootPath
try {
    Invoke-Native -FilePath $gclient -Arguments @(
        'sync',
        '-D',
        '--force',
        '--reset',
        '--with_branch_heads',
        '--revision',
        "src@$($script:ChromiumCommit)"
    )
}
finally {
    Pop-Location
}

Assert-DepotTools
Assert-ChromiumOriginAndClean
$finalCommit = Invoke-NativeOutput -FilePath $script:GitBin -Arguments @(
    '-C', $script:ChromiumSource, 'rev-parse', '--verify', 'HEAD'
)
if ($finalCommit -ne $script:ChromiumCommit) {
    throw "gclient moved Chromium HEAD to $finalCommit."
}

Invoke-Native -FilePath $script:NodeBin -Arguments @(
    (Join-Path $script:EngineRoot 'scripts\depot-tools-checkout.mjs'),
    '--root',
    $script:DepotToolsPath
) -Quiet
Invoke-Native -FilePath $script:NodeBin -Arguments @(
    (Join-Path $script:EngineRoot 'scripts\chromium-checkout.mjs'),
    '--source',
    $script:ChromiumSource,
    '--state',
    'clean'
) -Quiet

Invoke-DependencyLockCapture

# Capturing resolved dependencies is read-only. Re-audit both repositories so a
# future dependency-lock implementation cannot silently mutate build inputs.
Assert-DepotTools
Assert-ChromiumOriginAndClean
Invoke-Native -FilePath $script:NodeBin -Arguments @(
    (Join-Path $script:EngineRoot 'scripts\depot-tools-checkout.mjs'),
    '--root',
    $script:DepotToolsPath
) -Quiet
Invoke-Native -FilePath $script:NodeBin -Arguments @(
    (Join-Path $script:EngineRoot 'scripts\chromium-checkout.mjs'),
    '--source',
    $script:ChromiumSource,
    '--state',
    'clean'
) -Quiet

Write-Host "==> done: $($script:ChromiumSource)"
Write-Host (
    "    Chromium $($script:ChromiumStable) @ $($script:ChromiumCommit)"
)
Write-Host (
    "    depot_tools @ $($script:DepotToolsCommit) (auto-update disabled)"
)
