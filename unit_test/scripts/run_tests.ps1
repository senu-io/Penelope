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

function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $output = & $Action 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
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
    if (Test-Path (Join-Path $repoRoot "backend\Cargo.toml")) {
        Invoke-Step "Rust Backend Unit Tests (cargo test)" {
            Push-Location (Join-Path $repoRoot "backend")
            cargo test -- --nocapture
            Pop-Location
        }
    }
}

if ($Suite -in @("frontend", "full")) {
    if (Test-Path (Join-Path $repoRoot "frontend\package.json")) {
        Invoke-Step "Frontend Unit Tests (vitest)" {
            Push-Location (Join-Path $repoRoot "frontend")
            npm test -- --run
            Pop-Location
        }
    }
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
$md += "# Penelope Unit Test Report ($reportBase)"
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

$md -join "`r`n" | Set-Content -Path $mdPath -Encoding UTF8
Write-Output "Generated report: $mdPath"
