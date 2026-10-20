#!/usr/bin/env pwsh
# =============================================================================
# JCB AirPlay - Outside Judge Verification Script
# scripts/verify_step.ps1
#
# PURPOSE: This is the single source of truth for "done".
#          No step in this project is complete until this script exits 0.
#
# RUNS:
#   1. cargo check               - Rust compilation check (no codegen)
#   2. cargo test --no-fail-fast - All Rust unit and integration tests
#   3. cargo clippy -- -D warnings - Lints (warnings are errors)
#   4. npx tsc --noEmit          - TypeScript type checking
# =============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -- Helpers ------------------------------------------------------------------

$script:Passed = 0
$script:Failed = 0
$script:StartTime = Get-Date

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor DarkGray
}

function Write-Step {
    param([int]$Num, [string]$Label, [string]$Cmd)
    Write-Host ""
    Write-Host "  [$Num/4] $Label" -ForegroundColor Yellow
    Write-Host "          > $Cmd" -ForegroundColor DarkGray
    Write-Host ""
}

function Invoke-Check {
    param(
        [int]$Num,
        [string]$Label,
        [string]$Cmd,
        [string[]]$CheckArgs,
        [string]$WorkDir = $PSScriptRoot + '\..'
    )

    Write-Step -Num $Num -Label $Label -Cmd "$Cmd $($CheckArgs -join ' ')"

    Push-Location (Resolve-Path $WorkDir)
    try {
        & $Cmd @CheckArgs
        $exitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }

    if ($exitCode -eq 0) {
        Write-Host "  [PASS] $Label" -ForegroundColor Green
        $script:Passed++
    } else {
        Write-Host "  [FAIL] $Label (exit code $exitCode)" -ForegroundColor Red
        $script:Failed++
    }
}

# -- Main ---------------------------------------------------------------------

Write-Header "JCB AirPlay - Outside Judge"
Write-Host "  Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "  Directory : $(Resolve-Path (Join-Path $PSScriptRoot '..'))" -ForegroundColor DarkGray

$cargoManifest = Join-Path $PSScriptRoot '..\src-tauri\Cargo.toml'
$cargoArgs = @('--manifest-path', $cargoManifest)

# Check 1 - cargo check
Invoke-Check -Num 1 `
             -Label 'cargo check (Rust compilation)' `
             -Cmd 'cargo' `
             -CheckArgs (@('check') + $cargoArgs)

# Check 2 - cargo test
Invoke-Check -Num 2 `
             -Label 'cargo test --no-fail-fast (Rust tests)' `
             -Cmd 'cargo' `
             -CheckArgs (@('test', '--no-fail-fast') + $cargoArgs)

# Check 3 - cargo clippy
Invoke-Check -Num 3 `
             -Label 'cargo clippy -- -D warnings (Rust lints)' `
             -Cmd 'cargo' `
             -CheckArgs (@('clippy') + $cargoArgs + @('--', '-D', 'warnings'))

# Check 4 - TypeScript type check
$npxCmd = if (Get-Command 'npx.cmd' -ErrorAction SilentlyContinue) { 'npx.cmd' } else { 'npx' }
Invoke-Check -Num 4 `
             -Label 'npx tsc --noEmit (TypeScript type-check)' `
             -Cmd $npxCmd `
             -CheckArgs @('tsc', '--noEmit') `
             -WorkDir (Join-Path $PSScriptRoot '..')

# -- Summary -------------------------------------------------------------------

$elapsed = (Get-Date) - $script:StartTime

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor DarkGray
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor DarkGray
Write-Host "  Passed  : $script:Passed / 4" -ForegroundColor $(if ($script:Passed -eq 4) { 'Green' } else { 'Yellow' })
Write-Host "  Failed  : $script:Failed / 4" -ForegroundColor $(if ($script:Failed -eq 0) { 'Green' } else { 'Red' })
Write-Host "  Elapsed : $($elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor DarkGray
Write-Host ""

if ($script:Failed -gt 0) {
    Write-Host "  OUTSIDE JUDGE: FAIL - This step is NOT complete." -ForegroundColor Red
    Write-Host "     Fix all issues above, then re-run .\scripts\verify_step.ps1" -ForegroundColor Red
    Write-Host ""
    exit 1
} else {
    Write-Host "  OUTSIDE JUDGE: PASS - Step verified. Safe to commit." -ForegroundColor Green
    Write-Host ""
    exit 0
}
