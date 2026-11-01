param(
    [ValidateSet("backend", "frontend", "full")]
    [string]$Suite = "full",
    [switch]$Private
)

$ErrorActionPreference = "Continue"

# Resolve [Penelope] repository root reliably regardless of whether this script
# lives in unit_test/scripts/ or unit_test/.private_tests/scripts/
$scriptDir = $PSScriptRoot
if ($scriptDir -match '[\\/]\.private_tests[\\/]scripts$') {
    $repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptDir "..\..\.."))
} else {
    $repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptDir "..\.."))
}

$baseUtDir = Join-Path $repoRoot "unit_test"
$targetUtDir = if ($Private) { Join-Path $baseUtDir ".private_tests" } else { $baseUtDir }
$reportsDir = Join-Path $targetUtDir "reports"
New-Item -ItemType Directory -Force -Path $reportsDir | Out-Null
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$results = @()
$overallPass = $true

function Add-StepResult {
    param(
        [string]$Name,
        [string]$Status,
        [int]$ExitCode,
        [long]$DurationMs,
        [int]$TestsExecuted,
        [string]$Output
    )
    if ($Status -ne "PASS") { $script:overallPass = $false }
    $script:results += [PSCustomObject]@{
        Step          = $Name
        Status        = $Status
        ExitCode      = $ExitCode
        DurationMs    = $DurationMs
        TestsExecuted = $TestsExecuted
        Output        = $Output.Trim()
    }
}

function Invoke-QualityStep {
    param([string]$Name, [scriptblock]$Action)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $output = & $Action 2>&1 | Out-String
    $exitCode = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } else { 1 }
    $sw.Stop()
    $status = if ($exitCode -eq 0) { "PASS" } else { "FAIL" }
    Add-StepResult -Name $Name -Status $status -ExitCode $exitCode -DurationMs $sw.ElapsedMilliseconds -TestsExecuted 0 -Output $output
}

function Invoke-TestRunnerStep {
    param([string]$Name, [scriptblock]$Action, [string]$CountPattern)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $output = & $Action 2>&1 | Out-String
    $exitCode = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } else { 1 }
    $sw.Stop()

    # Count actual executed tests from runner output; 0 executed tests is an automatic FAIL
    $totalExecuted = 0
    $regexMatches = [regex]::Matches($output, $CountPattern)
    foreach ($m in $regexMatches) {
        $totalExecuted += [int]$m.Groups[1].Value
    }

    $status = if ($exitCode -eq 0 -and $totalExecuted -gt 0) { "PASS" } else { "FAIL" }
    if ($exitCode -eq 0 -and $totalExecuted -eq 0) {
        $output = $output + "`r`n[ERROR] Command exited 0 but executed 0 tests. Vacuous PASS is forbidden."
        $exitCode = 1
    }
    Add-StepResult -Name $Name -Status $status -ExitCode $exitCode -DurationMs $sw.ElapsedMilliseconds -TestsExecuted $totalExecuted -Output $output
}

if ($Suite -in @("backend", "full")) {
    $cargoToml = Join-Path $repoRoot "backend\Cargo.toml"
    if (Test-Path -LiteralPath $cargoToml) {
        Invoke-QualityStep "Rust Format Check (cargo fmt --check)" {
            Push-Location (Join-Path $repoRoot "backend")
            cargo fmt --all -- --check
            Pop-Location
        }
        Invoke-QualityStep "Rust Lint Check (cargo clippy -- -D warnings)" {
            Push-Location (Join-Path $repoRoot "backend")
            cargo clippy --all-targets -- -D warnings
            Pop-Location
        }
        if ($Private) {
            Invoke-TestRunnerStep -Name "Rust Private & Ignored Edge-Case Tests" -CountPattern 'test result: ok\.\s+(\d+)\s+passed' -Action {
                Push-Location (Join-Path $repoRoot "backend")
                $env:PENELOPE_PRIVATE_TESTS = "1"
                cargo test -- --include-ignored --nocapture
                Pop-Location
            }
        } else {
            Invoke-TestRunnerStep -Name "Rust Unit & Integration Tests (cargo test)" -CountPattern 'test result: ok\.\s+(\d+)\s+passed' -Action {
                Push-Location (Join-Path $repoRoot "backend")
                cargo test -- --nocapture
                Pop-Location
            }
        }
    } else {
        Add-StepResult -Name "Rust Backend Suite" -Status "FAIL" -ExitCode 1 -DurationMs 0 -TestsExecuted 0 -Output "SUITE_NOT_FOUND: Missing $cargoToml."
    }
}

if ($Suite -in @("frontend", "full")) {
    $pkgJson = Join-Path $repoRoot "frontend\package.json"
    if (Test-Path -LiteralPath $pkgJson) {
        Invoke-TestRunnerStep -Name "Frontend Unit Tests (vitest)" -CountPattern '(\d+)\s+passed' -Action {
            Push-Location (Join-Path $repoRoot "frontend")
            npm test -- --run
            Pop-Location
        }
    } else {
        Add-StepResult -Name "Frontend Suite" -Status "FAIL" -ExitCode 1 -DurationMs 0 -TestsExecuted 0 -Output "SUITE_NOT_FOUND: Missing $pkgJson."
    }
}

if ($results.Count -eq 0) {
    Add-StepResult -Name "Test Execution" -Status "FAIL" -ExitCode 1 -DurationMs 0 -TestsExecuted 0 -Output "Zero test steps were executed."
}

$finalStatus = if ($overallPass) { "PASS" } else { "FAIL" }
$modeTag = if ($Private) { "private_${Suite}" } else { $Suite }
$reportBase = "ut_report_${timestamp}_${modeTag}_${finalStatus}"
$mdPath = Join-Path $reportsDir "$reportBase.md"
$jsonPath = Join-Path $reportsDir "$reportBase.json"

$reportObj = @{
    timestamp = (Get-Date -Format "o")
    repo_root = $repoRoot
    suite     = $Suite
    private   = [bool]$Private
    status    = $finalStatus
    steps     = $results
}
$reportObj | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8

$md = @()
$md += "# Penelope Test Report ($reportBase)"
$md += ""
$md += "- Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$md += "- Suite: $Suite (Private: $([bool]$Private))"
$md += "- Status: $finalStatus"
$md += ""
$md += "| Step | Status | Exit Code | Tests Executed | Duration (ms) |"
$md += "| :--- | :--- | ---: | ---: | ---: |"
foreach ($r in $results) {
    $md += "| $($r.Step) | $($r.Status) | $($r.ExitCode) | $($r.TestsExecuted) | $($r.DurationMs) |"
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
