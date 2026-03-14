$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$mobileAppDir = Join-Path $repoRoot "mobile_app"
$keyPropertiesPath = Join-Path $mobileAppDir "android\key.properties"
$defaultSiteUrl = "https://ustabul.onrender.com"

function Read-KeyProperties([string]$path) {
    $map = @{}
    foreach ($line in Get-Content $path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#") -or -not $trimmed.Contains("=")) {
            continue
        }
        $parts = $trimmed.Split("=", 2)
        $map[$parts[0].Trim()] = $parts[1].Trim()
    }
    return $map
}

if (-not (Test-Path $keyPropertiesPath)) {
    throw "Release signing icin mobile_app/android/key.properties dosyasi gerekli."
}

$keyProperties = Read-KeyProperties $keyPropertiesPath
$requiredKeys = @("storeFile", "storePassword", "keyAlias", "keyPassword")
foreach ($requiredKey in $requiredKeys) {
    if (-not $keyProperties.ContainsKey($requiredKey) -or [string]::IsNullOrWhiteSpace($keyProperties[$requiredKey])) {
        throw "key.properties icinde '$requiredKey' eksik."
    }
}

$placeholders = @("change-me", "example", "todo")
foreach ($requiredKey in $requiredKeys) {
    $value = $keyProperties[$requiredKey].ToLowerInvariant()
    if ($placeholders -contains $value) {
        throw "key.properties icindeki '$requiredKey' placeholder olarak duruyor."
    }
}

$keystorePath = Join-Path $mobileAppDir "android\$($keyProperties['storeFile'])"
if (-not (Test-Path $keystorePath)) {
    throw "Release keystore bulunamadi: $keystorePath"
}

$siteUrl = if ($env:MOBILE_SITE_URL) { $env:MOBILE_SITE_URL.Trim() } else { $defaultSiteUrl }
if ([string]::IsNullOrWhiteSpace($siteUrl)) {
    throw "SITE_URL bos olamaz."
}

Push-Location $mobileAppDir
try {
    flutter pub get
    flutter build appbundle --release --dart-define=SITE_URL=$siteUrl
}
finally {
    Pop-Location
}
