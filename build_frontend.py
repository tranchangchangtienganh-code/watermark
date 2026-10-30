"""
Kịch bản xây dựng & đóng gói Frontend tĩnh cho Netlify
(Netlify Static Frontend Build & Packager Script)
Dành riêng cho Hệ Thống Đóng Watermark - Ms. Trần Thị Thu Trang

Nhiệm vụ:
1. Tạo thư mục 'public/' làm Publish Directory cho Netlify
2. Đóng gói index.html từ templates/index.html (loại bỏ phụ thuộc Jinja2 server-side)
3. Đồng bộ toàn bộ tài nguyên tĩnh (CSS, JS, Fonts) vào public/static/
4. Sinh quy tắc chuyển tiếp / cấu hình Reverse Proxy Netlify (_redirects)
   chuyển tiếp an toàn mọi yêu cầu /api/* sang Flask Backend trên Render:
   https://watermark-nuwt.onrender.com/api/:splat
"""
import os
import sys
import shutil
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
RENDER_BACKEND_URL = os.environ.get("RENDER_BACKEND_URL", "https://watermark-nuwt.onrender.com").rstrip("/")

def build():
    print("=" * 60)
    print(" BẮT ĐẦU ĐÓNG GÓI NETLIFY FRONTEND - WATERMARK SYSTEM")
    print(f" Target Backend: {RENDER_BACKEND_URL}")
    print("=" * 60)

    # 1. Khởi tạo thư mục public
    if PUBLIC_DIR.exists():
        shutil.rmtree(PUBLIC_DIR)
    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)

    # 2. Xử lý templates/index.html thành public/index.html
    src_html = TEMPLATES_DIR / "index.html"
    if not src_html.exists():
        raise FileNotFoundError(f"Không tìm thấy {src_html}")

    html_content = src_html.read_text(encoding="utf-8")

    # Thay thế Jinja2 template tag {{ csrf_token }} bằng rỗng
    # Frontend app.js sẽ tự động đồng bộ CSRF token thực tế từ Backend qua /api/auth/status
    clean_html = html_content.replace(
        '<meta name="csrf-token" content="{{ csrf_token }}">',
        '<meta name="csrf-token" content="">'
    )

    dest_html = PUBLIC_DIR / "index.html"
    dest_html.write_text(clean_html, encoding="utf-8")
    print(f"[OK] Đã biên soạn: {dest_html.name}")

    # 3. Sao chép tài nguyên tĩnh (static/css, static/js)
    dest_static = PUBLIC_DIR / "static"
    shutil.copytree(STATIC_DIR, dest_static)
    print(f"[OK] Đã đồng bộ tài nguyên tĩnh vào: {dest_static}")

    # 4. Sinh file public/_redirects cho Netlify
    redirects_content = f"""# Netlify Same-Origin API Reverse Proxy to Flask on Render
/api/*  {RENDER_BACKEND_URL}/api/:splat  200!
/*      /index.html                      200
"""
    dest_redirects = PUBLIC_DIR / "_redirects"
    dest_redirects.write_text(redirects_content, encoding="utf-8")
    print(f"[OK] Đã tạo quy tắc proxy Netlify: {dest_redirects.name}")

    print("=" * 60)
    print(" HOÀN THÀNH XÂY DỰNG NETLIFY FRONTEND THÀNH CÔNG!")
    print(f" Thư mục xuất bản (Publish directory): {PUBLIC_DIR}")
    print("=" * 60)

if __name__ == "__main__":
    build()
