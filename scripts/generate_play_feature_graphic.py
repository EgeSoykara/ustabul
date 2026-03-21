from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageOps


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "mobile_app" / "assets" / "store" / "play_feature_graphic_v2_1024x500.jpg"
ICON_PATH = ROOT / "mobile_app" / "assets" / "branding" / "app_icon.png"
SIZE = (1024, 500)


def hex_rgb(value: str) -> tuple[int, int, int]:
    value = value.lstrip("#")
    return tuple(int(value[index : index + 2], 16) for index in (0, 2, 4))


def lerp_color(start: tuple[int, int, int], end: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return tuple(int(start[i] + (end[i] - start[i]) * t) for i in range(3))


def find_font(size: int, *candidates: str) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return ImageFont.truetype(str(path), size=size)
    return ImageFont.load_default()


def rounded_panel(
    size: tuple[int, int],
    radius: int,
    fill: tuple[int, int, int, int],
    outline: tuple[int, int, int, int],
    width: int = 2,
) -> Image.Image:
    panel = Image.new("RGBA", size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(panel)
    draw.rounded_rectangle((0, 0, size[0] - 1, size[1] - 1), radius=radius, fill=fill, outline=outline, width=width)
    return panel


def build_background(width: int, height: int) -> Image.Image:
    top = hex_rgb("050B1A")
    bottom = hex_rgb("0A1223")
    image = Image.new("RGB", (width, height), top)
    draw = ImageDraw.Draw(image)
    for y in range(height):
        draw.line((0, y, width, y), fill=lerp_color(top, bottom, y / max(1, height - 1)))

    overlay = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    glow = ImageDraw.Draw(overlay)
    glow.ellipse((-120, -40, 360, 360), fill=(14, 116, 144, 44))
    glow.ellipse((720, 230, 1090, 590), fill=(249, 115, 22, 28))
    glow.ellipse((560, -20, 940, 250), fill=(56, 189, 248, 20))
    overlay = overlay.filter(ImageFilter.GaussianBlur(66))
    return Image.alpha_composite(image.convert("RGBA"), overlay)


def draw_phone_mockup(base: Image.Image, origin: tuple[int, int], icon: Image.Image) -> None:
    x, y = origin

    shadow = Image.new("RGBA", (300, 390), (0, 0, 0, 0))
    shadow_draw = ImageDraw.Draw(shadow)
    shadow_draw.rounded_rectangle((24, 24, 278, 366), radius=44, fill=(0, 0, 0, 122))
    shadow = shadow.filter(ImageFilter.GaussianBlur(22))
    base.alpha_composite(shadow, (x - 12, y + 6))

    phone = Image.new("RGBA", (280, 370), (0, 0, 0, 0))
    draw = ImageDraw.Draw(phone)
    draw.rounded_rectangle((0, 0, 279, 369), radius=44, fill=(10, 16, 28, 248), outline=(113, 128, 150, 110), width=2)
    draw.rounded_rectangle((20, 20, 260, 350), radius=34, fill=(249, 253, 255, 252))
    draw.rounded_rectangle((103, 10, 177, 22), radius=6, fill=(28, 34, 48, 255))

    screen = Image.new("RGBA", (240, 330), (255, 255, 255, 0))
    screen_draw = ImageDraw.Draw(screen)
    top = hex_rgb("F9FDFF")
    bottom = hex_rgb("EEF6FF")
    for row in range(330):
        screen_draw.line((0, row, 240, row), fill=lerp_color(top, bottom, row / 329))

    glow = Image.new("RGBA", (240, 330), (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(glow)
    glow_draw.ellipse((-30, -20, 150, 145), fill=(14, 116, 144, 24))
    glow_draw.ellipse((150, 215, 290, 360), fill=(249, 115, 22, 18))
    glow = glow.filter(ImageFilter.GaussianBlur(28))
    screen = Image.alpha_composite(screen, glow)
    phone.alpha_composite(screen, (20, 20))

    draw.rounded_rectangle((38, 42, 242, 98), radius=18, fill=(255, 255, 255, 228), outline=(14, 116, 144, 50), width=1)
    draw.rounded_rectangle((38, 116, 136, 196), radius=20, fill=(255, 255, 255, 230), outline=(14, 116, 144, 42), width=1)
    draw.rounded_rectangle((144, 116, 242, 196), radius=20, fill=(255, 255, 255, 230), outline=(14, 116, 144, 42), width=1)
    draw.rounded_rectangle((38, 212, 242, 304), radius=22, fill=(255, 255, 255, 232), outline=(14, 116, 144, 42), width=1)
    draw.rounded_rectangle((54, 134, 118, 146), radius=6, fill=(14, 116, 144, 200))
    draw.rounded_rectangle((160, 134, 224, 146), radius=6, fill=(14, 116, 144, 200))
    draw.rounded_rectangle((54, 232, 188, 244), radius=6, fill=(14, 116, 144, 196))
    draw.rounded_rectangle((54, 256, 216, 266), radius=5, fill=(90, 104, 126, 120))
    draw.rounded_rectangle((54, 276, 194, 286), radius=5, fill=(90, 104, 126, 84))

    icon_copy = ImageOps.contain(icon.copy(), (56, 56))
    phone.alpha_composite(icon_copy, (44, 42))
    base.alpha_composite(phone, (x, y))


def main() -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    title_font = find_font(
        62,
        r"C:\Windows\Fonts\segoeuib.ttf",
        r"C:\Windows\Fonts\seguisb.ttf",
        r"C:\Windows\Fonts\arialbd.ttf",
    )
    subtitle_font = find_font(
        28,
        r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\arial.ttf",
    )
    meta_font = find_font(
        16,
        r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\arial.ttf",
    )
    footer_font = find_font(
        20,
        r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\arial.ttf",
    )

    image = build_background(*SIZE)
    panel_x, panel_y = 52, 84
    left_panel = rounded_panel(
        size=(560, 332),
        radius=34,
        fill=(255, 255, 255, 16),
        outline=(129, 175, 198, 74),
    )
    image.alpha_composite(left_panel, (panel_x, panel_y))

    badge = rounded_panel(
        size=(256, 40),
        radius=16,
        fill=(255, 255, 255, 18),
        outline=(148, 163, 184, 56),
        width=1,
    )
    image.alpha_composite(badge, (panel_x + 22, panel_y + 20))

    draw = ImageDraw.Draw(image)
    draw.text((panel_x + 40, panel_y + 30), "Kuzey Kıbrıs hizmet pazaryeri", font=meta_font, fill=(214, 223, 235))
    draw.text((panel_x + 34, panel_y + 92), "UstaBul", font=title_font, fill=(248, 250, 252))
    draw.multiline_text(
        (panel_x + 34, panel_y + 170),
        "Yakındaki ustaları bul,\ntalebini oluştur ve süreci mobilde takip et.",
        font=subtitle_font,
        fill=(224, 231, 239),
        spacing=12,
    )
    draw.line(
        (panel_x + 34, panel_y + 286, panel_x + 526, panel_y + 286),
        fill=(92, 113, 136),
        width=1,
    )
    draw.text(
        (panel_x + 34, panel_y + 296),
        "Website ile uyumlu premium mobil deneyim",
        font=footer_font,
        fill=(184, 196, 217),
    )

    icon = Image.open(ICON_PATH).convert("RGBA")
    draw_phone_mockup(image, (712, 66), icon)
    image.convert("RGB").save(OUTPUT_PATH, quality=95, subsampling=0)
    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()
