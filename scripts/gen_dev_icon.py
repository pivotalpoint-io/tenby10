from PIL import Image, ImageDraw, ImageFont
import os

def create_dev_icons():
    # 1. Full App Icon
    base_path = 'desktop/src-tauri/icons/icon.iconset/icon_512x512.png'
    output_app_path = 'desktop/src-tauri/icons/icon_dev_512.png'
    
    if os.path.exists(base_path):
        img = Image.open(base_path).convert("RGBA")
        size = img.size
        draw_banner(img, size, "DEV", 30)
        img.save(output_app_path)
        print(f"Successfully created {output_app_path}")

    # 2. Tray Icon (Circles only, no background)
    circles_path = 'desktop/src-tauri/icons/icon_backup.png'
    output_tray_path = 'desktop/src-tauri/icons/icon_dev_32.png'
    
    if os.path.exists(circles_path):
        circles = Image.open(circles_path).convert("RGBA")
        circles = circles.resize((256, 256), Image.LANCZOS) # Work at higher res for quality
        draw_banner(circles, circles.size, "DEV", 15)
        # Resize to 32x32 for the tray
        tray = circles.resize((32, 32), Image.LANCZOS)
        tray.save(output_tray_path)
        print(f"Successfully created {output_tray_path}")

def draw_banner(img, size, text, offset):
    banner_width = int(size[0] * 0.5)
    banner_height = int(size[1] * 0.15)
    banner_color = (0, 255, 0, 255)
    text_color = (255, 255, 255, 255)
    
    temp_banner = Image.new('RGBA', (banner_width, banner_height), banner_color)
    temp_draw = ImageDraw.Draw(temp_banner)
    
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", int(banner_height * 0.6))
    except:
        font = ImageFont.load_default()
        
    tw = temp_draw.textlength(text, font=font)
    temp_draw.text(((banner_width - tw)/2, (banner_height - (font.size if hasattr(font, 'size') else 40))//4), text, fill=text_color, font=font)
    
    rotated_banner = temp_banner.rotate(45, expand=True)
    img.alpha_composite(rotated_banner, dest=(size[0] - rotated_banner.width + offset, -offset))

if __name__ == "__main__":
    create_dev_icons()
