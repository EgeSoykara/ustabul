$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourcePng = Join-Path $repoRoot "mobile_app\assets\branding\app_icon.png"

if (-not (Test-Path $sourcePng)) {
    throw "Launch asset source PNG not found: $sourcePng"
}

@'
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

source = Path(r"__SOURCE_PNG__")
img = Image.open(source).convert("RGBA")

android_targets = {
    Path(r"__ROOT__") / "mobile_app/android/app/src/main/res/mipmap-mdpi/launch_image.png": 96,
    Path(r"__ROOT__") / "mobile_app/android/app/src/main/res/mipmap-hdpi/launch_image.png": 144,
    Path(r"__ROOT__") / "mobile_app/android/app/src/main/res/mipmap-xhdpi/launch_image.png": 192,
    Path(r"__ROOT__") / "mobile_app/android/app/src/main/res/mipmap-xxhdpi/launch_image.png": 288,
    Path(r"__ROOT__") / "mobile_app/android/app/src/main/res/mipmap-xxxhdpi/launch_image.png": 384,
}

ios_targets = {
    Path(r"__ROOT__") / "mobile_app/ios/Runner/Assets.xcassets/LaunchImage.imageset/LaunchImage.png": 168,
    Path(r"__ROOT__") / "mobile_app/ios/Runner/Assets.xcassets/LaunchImage.imageset/LaunchImage@2x.png": 336,
    Path(r"__ROOT__") / "mobile_app/ios/Runner/Assets.xcassets/LaunchImage.imageset/LaunchImage@3x.png": 504,
}

font_candidates = [
    Path(r"C:\Windows\Fonts\seguisb.ttf"),
    Path(r"C:\Windows\Fonts\segoeuib.ttf"),
    Path(r"C:\Windows\Fonts\arialbd.ttf"),
]


def load_font(size):
    for candidate in font_candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size=size)
    return ImageFont.load_default()


def make_launch_asset(width):
    height = int(round(width * 1.28))
    icon_size = int(round(width * 0.76))
    top = int(round(width * 0.04))
    title_gap = int(round(width * 0.07))
    title_text = "UstaBul"

    canvas = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    icon = img.resize((icon_size, icon_size), Image.LANCZOS)

    radius = max(12, int(round(icon_size * 0.18)))
    mask = Image.new("L", (icon_size, icon_size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, icon_size, icon_size), radius=radius, fill=255)

    icon_x = (width - icon_size) // 2
    canvas.paste(icon, (icon_x, top), mask)

    draw = ImageDraw.Draw(canvas)
    title_font = load_font(max(16, int(round(width * 0.16))))
    title_bbox = draw.textbbox((0, 0), title_text, font=title_font)
    title_width = title_bbox[2] - title_bbox[0]
    title_x = (width - title_width) // 2
    title_y = top + icon_size + title_gap
    draw.text((title_x, title_y), title_text, font=title_font, fill=(248, 250, 252, 255))

    return canvas


for path, size in {**android_targets, **ios_targets}.items():
    path.parent.mkdir(parents=True, exist_ok=True)
    launch_asset = make_launch_asset(size)
    launch_asset.save(path)
    print(f"generated {path} ({launch_asset.size[0]}x{launch_asset.size[1]})")
'@.Replace("__SOURCE_PNG__", $sourcePng.Replace("\", "\\")).Replace("__ROOT__", $repoRoot.Replace("\", "\\")) | python -
