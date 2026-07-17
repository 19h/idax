[CmdletBinding()]
param(
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Architecture = "x64",
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertFrom-EnvironmentLines {
    param([string[]]$Lines)

    $result = [System.Collections.Generic.Dictionary[string, string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($line in $Lines) {
        $separator = $line.IndexOf("=")
        if ($separator -le 0) {
            continue
        }
        $name = $line.Substring(0, $separator)
        $value = $line.Substring($separator + 1)
        $result[$name] = $value
    }
    return ,$result
}

function Get-DeduplicatedPathList {
    param([string]$Value)

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $entries = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $Value.Split(";")) {
        if ($seen.Add($entry)) {
            $entries.Add($entry)
        }
    }
    return [string]::Join(";", $entries)
}

function Assert-SelfTest {
    $parsed = ConvertFrom-EnvironmentLines @(
        "Path=first;second;FIRST",
        "VALUE=left=right",
        "not-an-environment-line"
    )
    if ($parsed["VALUE"] -ne "left=right") {
        throw "environment parsing did not preserve equals signs"
    }
    if ((Get-DeduplicatedPathList $parsed["Path"]) -ne "first;second") {
        throw "path-list deduplication did not preserve first occurrence"
    }
    if ($parsed.ContainsKey("not-an-environment-line")) {
        throw "malformed environment line was accepted"
    }
}

if ($SelfTest) {
    Assert-SelfTest
    Write-Host "MSVC environment bridge self-test: PASS"
    exit 0
}

if (-not $IsWindows) {
    throw "the MSVC environment bridge requires Windows"
}
if ([string]::IsNullOrWhiteSpace($env:GITHUB_ENV)) {
    throw "GITHUB_ENV is not available"
}

$programFilesX86 = [System.Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
if ([string]::IsNullOrWhiteSpace($programFilesX86)) {
    throw "ProgramFiles(x86) is not available"
}
$vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio/Installer/vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
    throw "vswhere.exe was not found"
}

$installationPaths = & $vswhere `
    -latest `
    -products "*" `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
$vswhereSucceeded = $?
$installationPath = $installationPaths |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Select-Object -First 1
if (-not $vswhereSucceeded -or [string]::IsNullOrWhiteSpace($installationPath)) {
    throw "Visual Studio with the C++ toolchain was not found"
}

$vcvarsall = Join-Path $installationPath "VC/Auxiliary/Build/vcvarsall.bat"
if (-not (Test-Path -LiteralPath $vcvarsall -PathType Leaf)) {
    throw "vcvarsall.bat was not found"
}

$before = [System.Collections.Generic.Dictionary[string, string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
foreach ($entry in Get-ChildItem Env:) {
    $before[$entry.Name] = $entry.Value
}

$commandFile = Join-Path $env:RUNNER_TEMP ("idax-vcvars-{0}.cmd" -f $PID)
$command = @(
    "@echo off",
    ('call "{0}" {1} >nul' -f $vcvarsall, $Architecture),
    "if errorlevel 1 exit /b %errorlevel%",
    "set"
) -join "`r`n"

try {
    [System.IO.File]::WriteAllText(
        $commandFile,
        $command + "`r`n",
        [System.Text.ASCIIEncoding]::new()
    )
    $environmentLines = & $env:ComSpec /d /q /c $commandFile
    $vcvarsSucceeded = $?
    if (-not $vcvarsSucceeded) {
        throw "vcvarsall.bat rejected the requested architecture"
    }
}
finally {
    Remove-Item -LiteralPath $commandFile -Force -ErrorAction SilentlyContinue
}

$after = ConvertFrom-EnvironmentLines $environmentLines
if (-not $after.ContainsKey("VCINSTALLDIR") -or -not $after.ContainsKey("PATH")) {
    throw "vcvarsall.bat did not produce a complete compiler environment"
}

$compilerFound = $false
foreach ($directory in $after["PATH"].Split(";")) {
    if (-not [string]::IsNullOrWhiteSpace($directory) -and
        (Test-Path -LiteralPath (Join-Path $directory "cl.exe") -PathType Leaf)) {
        $compilerFound = $true
        break
    }
}
if (-not $compilerFound) {
    throw "cl.exe is not resolvable from the configured compiler path"
}

$pathVariables = @("PATH", "INCLUDE", "LIB", "LIBPATH")
$updates = [System.Collections.Generic.List[string]]::new()
foreach ($entry in $after.GetEnumerator() | Sort-Object Key) {
    $name = $entry.Key
    $value = $entry.Value
    if ($name.StartsWith("GITHUB_", [System.StringComparison]::OrdinalIgnoreCase) -or
        $name.StartsWith("RUNNER_", [System.StringComparison]::OrdinalIgnoreCase)) {
        continue
    }
    if ($value.Contains("`r") -or $value.Contains("`n")) {
        throw "vcvarsall.bat produced a multiline environment value"
    }
    $oldValue = $null
    $wasPresent = $before.TryGetValue($name, [ref]$oldValue)
    if ($wasPresent -and $oldValue -ceq $value) {
        continue
    }
    if ($pathVariables -contains $name.ToUpperInvariant()) {
        $value = Get-DeduplicatedPathList $value
    }
    $updates.Add("$name=$value")
    Write-Host "Exporting $name"
}

[System.IO.File]::AppendAllLines(
    $env:GITHUB_ENV,
    $updates,
    [System.Text.UTF8Encoding]::new($false)
)
Write-Host "Configured MSVC Developer Command Prompt for $Architecture ($($updates.Count) variables)"
