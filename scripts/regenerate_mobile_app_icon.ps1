$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$mobileAppDir = Join-Path $repoRoot "mobile_app"

Push-Location $mobileAppDir
try {
    flutter pub get
    dart run flutter_launcher_icons
}
finally {
    Pop-Location
}
