$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$mobileAppDir = Join-Path $repoRoot "mobile_app"
$emulatorName = "UstaBul_API_36"
$localSiteUrl = "http://10.0.2.2:8000"
$localHealthUrl = "http://127.0.0.1:8000"

function Get-AndroidEmulatorDeviceId {
    foreach ($line in (adb devices)) {
        if ($line -match "^(emulator-\d+)\s+(device|offline)$") {
            return $Matches[1]
        }
    }
    return $null
}

function Wait-AndroidEmulatorReady([string]$deviceId) {
    & adb -s $deviceId wait-for-device | Out-Null

    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $bootCompleted = (& adb -s $deviceId shell getprop sys.boot_completed).Trim()
        if ($bootCompleted -eq "1") {
            return
        }
        Start-Sleep -Seconds 2
    }

    throw "Android emulator did not finish booting in time."
}

Push-Location $mobileAppDir
try {
    Write-Host "Checking local Django server..." -ForegroundColor Cyan
    $response = Invoke-WebRequest -Uri $localHealthUrl -UseBasicParsing
    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 400) {
        throw "Local server did not return a healthy response: $($response.StatusCode)"
    }

    $deviceId = Get-AndroidEmulatorDeviceId
    if (-not $deviceId) {
        Write-Host "Launching Android emulator..." -ForegroundColor Cyan
        flutter emulators --launch $emulatorName | Out-Null

        for ($attempt = 0; $attempt -lt 30 -and -not $deviceId; $attempt++) {
            Start-Sleep -Seconds 2
            $deviceId = Get-AndroidEmulatorDeviceId
        }
    } else {
        Write-Host "Android emulator already running." -ForegroundColor DarkYellow
    }

    if (-not $deviceId) {
        throw "Android emulator did not become available in time."
    }

    Write-Host "Using device $deviceId" -ForegroundColor Green
    Wait-AndroidEmulatorReady $deviceId
    flutter pub get
    flutter run -d $deviceId --dart-define=SITE_URL=$localSiteUrl --no-resident
}
finally {
    Pop-Location
}
