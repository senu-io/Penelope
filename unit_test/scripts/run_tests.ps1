param(
    [ValidateSet("backend", "frontend", "full")]
    [string]$Suite = "full",
    [switch]$Private
)

$ErrorActionPreference = "Continue"
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$baseUtDir = Join-Path $repoRoot "unit_test"
$targetUtDir = if ($Private) { Join-Path $baseUtDir ".private_tests" } else { $baseUtDir }
$reportsDir = Join-Path $targetUtDir "reports"
New-Item -ItemType Directory -Force -Path $reportsDir | Out-Null
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$results = @()
$overallPass = $true

function Add-MissingStepFailure {
    param([string]$Name, [string]$Reason)
    $script:overallPass = $false
    $script:results += [PSCustomObject]@{
        Step       = $Name
        Status     = "FAIL"
        ExitCode   = 1
        DurationMs = 0
        Output     = "SUITE_NOT_FOUND_OR_EMPTY: $Reason"
    }
}

function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $output = & $Action 2>&1 | Out-String
    $exitCode = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } else { 1 }
    $sw.Stop()
    $status = if ($exitCode -eq 0) { "PASS" } else { "FAIL" }
    if ($exitCode -ne 0) { $script:overallPass = $false }
    $script:results += [PSCustomObject]@{
        Step       = $Name
        Status     = $status
        ExitCode   = $exitCode
        DurationMs = $sw.ElapsedMilliseconds
        Output     = $output.Trim()
    }
}

if ($Suite -in @("backend", "full")) {
    $cargoToml = Join-Path $repoRoot "backend\Cargo.toml"
    if (Test-Path -LiteralPath $cargoToml) {
        Invoke-Step "Rust Format Check (cargo fmt --check)" {
            Push-Location (Join-Path $repoRoot "backend")
            cargo fmt --all -- --check
            Pop-Location
        }
        Invoke-Step "Rust Lint Check (cargo clippy -- -D warnings)" {
            Push-Location (Join-Path $repoRoot "backend")
            cargo clippy --all-targets -- -D warnings
            Pop-Location
        }
        Invoke-Step "Rust Unit & Integration Tests (cargo test)" {
            Push-Location (Join-Path $repoRoot "backend")
            cargo test -- --nocapture
            Pop-Location
        }
    } else {
        Add-MissingStepFailure "Rust Backend Suite" "Missing $cargoToml. Cannot report PASS when target suite is absent."
    }
}

if ($Suite -in @("frontend", "full")) {
    $pkgJson = Join-Path $repoRoot "frontend\package.json"
    if (Test-Path -LiteralPath $pkgJson) {
        Invoke-Step "Frontend Unit Tests (vitest)" {
            Push-Location (Join-Path $repoRoot "frontend")
            npm test -- --run
            Pop-Location
        }
    } else {
        Add-MissingStepFailure "Frontend Suite" "Missing $pkgJson. Cannot report PASS when target suite is absent."
    }
}

if ($results.Count -eq 0) {
    Add-MissingStepFailure "Test Execution" "Zero test steps were executed."
}

$finalStatus = if ($overallPass) { "PASS" } else { "FAIL" }
$reportBase = "ut_report_${timestamp}_${Suite}_${finalStatus}"
$mdPath = Join-Path $reportsDir "$reportBase.md"
$jsonPath = Join-Path $reportsDir "$reportBase.json"

$reportObj = @{
    timestamp = (Get-Date -Format "o")
    suite     = $Suite
    status    = $finalStatus
    steps     = $results
}
$reportObj | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8

$md = @()
$md += "# Penelope Test Report ($reportBase)"
$md += ""
$md += "- Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$md += "- Suite: $Suite"
$md += "- Status: $finalStatus"
$md += ""
$md += "| Step | Status | Exit Code | Duration (ms) |"
$md += "| :--- | :--- | ---: | ---: |"
foreach ($r in $results) {
    $md += "| $($r.Step) | $($r.Status) | $($r.ExitCode) | $($r.DurationMs) |"
}
$md += ""
$md += "## Detailed Output"
foreach ($r in $results) {
    $md += ""
    $md += "### $($r.Step) [$($r.Status)]"
    $md += '```text'
    $md += $r.Output
    $md += '```'
}

$md -join "`r`n" | Set-Content -Path $mdPath -Encoding UTF8
Write-Output "Generated report: $mdPath"
if (-not $overallPass) { exit 1 }
