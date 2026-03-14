$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$svgPath = Join-Path $repoRoot "static\pwa\favicon-dark.svg"
$pngPath = Join-Path $repoRoot "mobile_app\assets\branding\app_icon.png"
$regenerateScript = Join-Path $PSScriptRoot "regenerate_mobile_app_icon.ps1"
$regenerateLaunchScript = Join-Path $PSScriptRoot "regenerate_mobile_launch_assets.ps1"
$edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

if (-not (Test-Path $svgPath)) {
    throw "Source SVG not found: $svgPath"
}

if (-not (Test-Path $edgePath)) {
    throw "Microsoft Edge executable not found: $edgePath"
}

$pngDir = Split-Path -Parent $pngPath
New-Item -ItemType Directory -Force $pngDir | Out-Null

$svgUri = [System.Uri]::new($svgPath).AbsoluteUri
$tempHtml = Join-Path $env:TEMP "ustabul-mobile-icon-preview.html"
$htmlUri = [System.Uri]::new($tempHtml).AbsoluteUri

$html = @"
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <style>
    html, body {
      margin: 0;
      width: 1024px;
      height: 1024px;
      overflow: hidden;
      background: linear-gradient(135deg, #0b1220 0%, #1e293b 100%);
    }

    img {
      display: block;
      width: 1024px;
      height: 1024px;
    }
  </style>
</head>
<body>
  <img src="$svgUri" alt="UstaBul app icon">
</body>
</html>
"@

Set-Content -Path $tempHtml -Value $html -Encoding UTF8

& $edgePath `
    --headless=new `
    --disable-gpu `
    --hide-scrollbars `
    --window-size=1024,1024 `
    "--screenshot=$pngPath" `
    $htmlUri | Out-Null

if (-not (Test-Path $pngPath)) {
    throw "Failed to generate PNG app icon."
}

@'
from pathlib import Path
from PIL import Image

png_path = Path(r"__PNG_PATH__")
img = Image.open(png_path).convert("RGBA")
width, height = img.size
last_non_white = height - 1

for y in range(height - 1, -1, -1):
    row_is_white = True
    for x in range(0, width, max(1, width // 64)):
        if img.getpixel((x, y))[:3] != (255, 255, 255):
            row_is_white = False
            break
    if not row_is_white:
        last_non_white = y
        break

cropped = img.crop((0, 0, width, last_non_white + 1))
if cropped.size[1] != width:
    cropped = cropped.resize((width, width), Image.LANCZOS)

cropped.save(png_path)
'@.Replace("__PNG_PATH__", $pngPath.Replace("\", "\\")) | python -

powershell -ExecutionPolicy Bypass -File $regenerateScript
powershell -ExecutionPolicy Bypass -File $regenerateLaunchScript
