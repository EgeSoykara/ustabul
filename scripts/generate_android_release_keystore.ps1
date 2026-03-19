$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$androidDir = Join-Path $repoRoot "mobile_app\android"
$keystoreDir = Join-Path $androidDir "keystore"
$keystorePath = Join-Path $keystoreDir "release-keystore.jks"
$keyPropertiesPath = Join-Path $androidDir "key.properties"

if (Test-Path $keystorePath) {
    Remove-Item $keystorePath -Force
}

if (Test-Path $keyPropertiesPath) {
    Remove-Item $keyPropertiesPath -Force
}

if (-not (Test-Path $keystoreDir)) {
    New-Item -ItemType Directory -Path $keystoreDir | Out-Null
}

function New-Secret([int]$bytesLength = 24) {
    $bytes = New-Object byte[] $bytesLength
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }

    return ([Convert]::ToBase64String($bytes)).
        Replace("+", "A").
        Replace("/", "B").
        Replace("=", "C")
}

$storePassword = New-Secret
$keyPassword = New-Secret
$keyAlias = "upload"
$keytoolPath = (Get-Command keytool).Source

& $keytoolPath `
    -genkeypair `
    -v `
    -storetype JKS `
    -keystore $keystorePath `
    -storepass $storePassword `
    -alias $keyAlias `
    -keypass $keyPassword `
    -keyalg RSA `
    -keysize 4096 `
    -validity 3650 `
    -dname "CN=UstaBul Upload, OU=Mobile, O=UstaBul, L=Nicosia, ST=Nicosia, C=CY" `
    | Out-Null

@(
    "storeFile=keystore/release-keystore.jks"
    "storePassword=$storePassword"
    "keyAlias=$keyAlias"
    "keyPassword=$keyPassword"
) | Set-Content -Path $keyPropertiesPath -Encoding ASCII

Write-Output "Android release keystore hazirlandi."
Write-Output "Keystore: $keystorePath"
Write-Output "Properties: $keyPropertiesPath"
