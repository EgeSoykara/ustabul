$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$djangoDir = $repoRoot
$healthUrl = "http://127.0.0.1:8000"
$mobileScript = Join-Path $PSScriptRoot "run_mobile_android_local.ps1"

function Test-LocalServer {
    try {
        $response = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 3
        return $response.StatusCode -ge 200 -and $response.StatusCode -lt 400
    } catch {
        return $false
    }
}

if (-not (Test-LocalServer)) {
    Write-Host "Starting local Django server in a new PowerShell window..." -ForegroundColor Cyan
    $command = "Set-Location '$djangoDir'; python manage.py runserver"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $command | Out-Null

    $healthy = $false
    for ($attempt = 0; $attempt -lt 30 -and -not $healthy; $attempt++) {
        Start-Sleep -Seconds 2
        $healthy = Test-LocalServer
    }

    if (-not $healthy) {
        throw "Local Django server did not become ready on $healthUrl in time."
    }
} else {
    Write-Host "Local Django server already running." -ForegroundColor DarkYellow
}

Write-Host "Launching Android app against local backend..." -ForegroundColor Green
powershell -ExecutionPolicy Bypass -File $mobileScript
