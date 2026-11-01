param(
    [ValidateSet("backend", "frontend", "full")]
    [string]$Suite = "full",
    [switch]$Private,
    [string]$RepoRootOverride = ""
)

$ErrorActionPreference = "Continue"

# Resolve [Penelope] repository root reliably regardless of whether this script
# lives in unit_test/scripts/ or unit_test/.private_tests/scripts/
if (-not [string]::IsNullOrWhiteSpace($RepoRootOverride)) {
    $repoRoot = [System.IO.Path]::GetFullPath($RepoRootOverride)
} else {
    $scriptDir = $PSScriptRoot
    if ($scriptDir -match '[\\/]\.private_tests[\\/]scripts$') {
        $repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptDir "..\..\.."))
    } else {
        $repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptDir "..\.."))
    }
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

    # Strip ANSI escape sequences before counting executed tests; 0 executed tests is an automatic FAIL
    $cleanOutput = [regex]::Replace($output, '\x1B\[[0-9;]*[a-zA-Z]', '')
    $totalExecuted = 0
    $regexMatches = [regex]::Matches($cleanOutput, $CountPattern)
    foreach ($m in $regexMatches) {
        $totalExecuted += [int]$m.Groups[1].Value
    }

    $status = if ($exitCode -eq 0 -and $totalExecuted -gt 0) { "PASS" } else { "FAIL" }
    if ($exitCode -eq 0 -and $totalExecuted -eq 0) {
        $cleanOutput = $cleanOutput + "`r`n[ERROR] Command exited 0 but executed 0 tests. Vacuous PASS is forbidden."
        $exitCode = 1
    }
    Add-StepResult -Name $Name -Status $status -ExitCode $exitCode -DurationMs $sw.ElapsedMilliseconds -TestsExecuted $totalExecuted -Output $cleanOutput
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
            $privateTargetFile = Join-Path $repoRoot "backend\tests\private_suite.rs"
            $privateVaultFile = Join-Path $repoRoot "unit_test\.private_tests\backend\private_suite.rs"
            if ((-not (Test-Path -LiteralPath $privateTargetFile)) -and (Test-Path -LiteralPath $privateVaultFile)) {
                New-Item -ItemType Directory -Force -Path (Split-Path -Parent $privateTargetFile) | Out-Null
                Copy-Item -LiteralPath $privateVaultFile -Destination $privateTargetFile -Force
            }
            if (Test-Path -LiteralPath $privateTargetFile) {
                Invoke-TestRunnerStep -Name "Rust Isolated Private Integration Target (--test private_suite)" -CountPattern 'test result: ok\.\s+(\d+)\s+passed' -Action {
                    Push-Location (Join-Path $repoRoot "backend")
                    $env:PENELOPE_PRIVATE_TESTS = "1"
                    cargo test --test private_suite -- --nocapture
                    Pop-Location
                }
            } else {
                Add-StepResult -Name "Rust Isolated Private Integration Target (--test private_suite)" -Status "FAIL" -ExitCode 1 -DurationMs 0 -TestsExecuted 0 -Output "PRIVATE_TARGET_NOT_FOUND: Missing $privateTargetFile."
            }
        } else {
            Invoke-TestRunnerStep -Name "Rust Public Unit & DB Integration Tests (--lib --bins --test db_integrity_and_concurrency)" -CountPattern 'test result: ok\.\s+(\d+)\s+passed' -Action {
                Push-Location (Join-Path $repoRoot "backend")
                cargo test --lib --bins --test db_integrity_and_concurrency -- --nocapture
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
        if ($Private) {
            Invoke-TestRunnerStep -Name "Frontend Isolated Private Tests (vitest private.config)" -CountPattern 'Tests\s+(\d+)\s+passed' -Action {
                Push-Location (Join-Path $repoRoot "frontend")
                npm.cmd run test:private
                Pop-Location
            }
        } else {
            Invoke-TestRunnerStep -Name "Frontend Public Unit Tests (vitest public)" -CountPattern 'Tests\s+(\d+)\s+passed' -Action {
                Push-Location (Join-Path $repoRoot "frontend")
                npm.cmd test
                Pop-Location
            }
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
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$jsonText = $reportObj | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($jsonPath, $jsonText, $utf8NoBom)

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

[System.IO.File]::WriteAllText($mdPath, ($md -join "`r`n"), $utf8NoBom)
Write-Output "Generated report: $mdPath"
if (-not $overallPass) { exit 1 }
