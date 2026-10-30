"""
Hệ thống Đóng Watermark & Khóa Tệp Chống Chỉnh Sửa
Cấu hình hệ thống (Configuration)
Hỗ trợ cả môi trường phát triển cục bộ và Triển khai Đám mây (Render / Production Cloud)
Dành riêng cho Ms. Trần Thị Thu Trang
"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Phát hiện môi trường sản xuất (Production / Render)
IS_PRODUCTION = (
    os.environ.get("FLASK_ENV") == "production"
    or os.environ.get("RENDER") == "true"
    or os.environ.get("ENVIRONMENT") == "production"
)

# Đường dẫn thư mục dữ liệu và phiên làm việc (Persistent Storage)
# Trên Render có thể gắn Render Persistent Disk tại ví dụ /var/data thông qua biến DATA_DIR
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

SESSIONS_DIR = DATA_DIR / "sessions"
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

# Đường dẫn font chữ hỗ trợ tiếng Việt đầy đủ (hoạt động đa nền tảng Linux & Windows)
FONTS_DIR = BASE_DIR / "core" / "fonts"
DEFAULT_FONT_PATH = FONTS_DIR / "arial.ttf"

# Cấu hình bảo mật và giới hạn tệp
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 50 * 1024 * 1024))  # 50 MB
ALLOWED_EXTENSIONS = {
    "pdf": ["application/pdf"],
    "docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    "png": ["image/png"],
    "jpg": ["image/jpeg"],
    "jpeg": ["image/jpeg"],
    "webp": ["image/webp"]
}

# Thời gian phiên làm việc hợp lý với cơ chế tự động gia hạn trượt an toàn (Sliding Session Renewal)
# Mặc định 30 ngày (2,592,000 giây) - Tự động gia hạn an toàn mỗi khi chủ sở hữu thao tác
SESSION_LIFETIME_DAYS = int(os.environ.get("SESSION_LIFETIME_DAYS", 30))
SESSION_LIFETIME_SECONDS = int(os.environ.get("SESSION_LIFETIME_SECONDS", SESSION_LIFETIME_DAYS * 86400))
PERMANENT_SESSION_LIFETIME = int(os.environ.get("PERMANENT_SESSION_LIFETIME", SESSION_LIFETIME_SECONDS))

# Chế độ Chủ sở hữu duy nhất (Single-Owner Mode - Dành riêng cho Ms. Trang)
SINGLE_OWNER_MODE = os.environ.get("SINGLE_OWNER_MODE", "true").lower() == "true"
OWNER_KEY = os.environ.get("OWNER_KEY") or os.environ.get("ADMIN_ACCESS_KEY")

# Cấu hình xác thực bảo mật cấp Website & Netlify Proxy
# Xác thực quyền chủ sở hữu từ tầng website/proxy, loại bỏ yêu cầu nhập mật khẩu cấp ứng dụng
PRIVATE_SITE_SECRET = os.environ.get("PRIVATE_SITE_SECRET") or os.environ.get("NETLIFY_PROXY_SECRET")
TRUST_NETLIFY_PROXY = os.environ.get("TRUST_NETLIFY_PROXY", "true").lower() == "true"

# Cấu hình bảo vệ trang web riêng tư qua HTTP Basic Auth (Tùy chọn cấp website)
BASIC_AUTH_USERNAME = os.environ.get("BASIC_AUTH_USERNAME")
BASIC_AUTH_PASSWORD = os.environ.get("BASIC_AUTH_PASSWORD")

# Cấu hình mặc định cho Watermark Ms. Trang
DEFAULT_WATERMARK_TEXT = os.environ.get("DEFAULT_WATERMARK_TEXT", "TRẦN THỊ THU TRANG")
DEFAULT_SUB_TEXT = os.environ.get("DEFAULT_SUB_TEXT", "BẢN QUYỀN SỞ HỮU • NGHIÊM CẤM SAO CHÉP & CHỈNH SỬA")
DEFAULT_GRAY_COLOR_HEX = os.environ.get("DEFAULT_GRAY_COLOR_HEX", "#708090")  # Slate Gray thanh lịch
DEFAULT_GRAY_COLOR_RGB = (112, 128, 144)

# Khóa bí mật máy chủ (Ưu tiên lấy từ biến môi trường SECRET_KEY trên Render)
def _get_or_create_secret_key() -> str:
    env_key = os.environ.get("SECRET_KEY")
    if env_key and len(env_key.strip()) >= 16:
        return env_key.strip()
    key_file = DATA_DIR / ".secret_key"
    if key_file.exists():
        try:
            return key_file.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    new_key = secrets.token_hex(32)
    try:
        key_file.write_text(new_key, encoding="utf-8")
    except Exception:
        pass
    return new_key

SECRET_KEY = _get_or_create_secret_key()

# Cấu hình bảo mật khởi tạo quản trị viên ban đầu (Chống First-Run Exploit trên Render)
ADMIN_INITIAL_PASSWORD = os.environ.get("ADMIN_INITIAL_PASSWORD")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")
SETUP_TOKEN = os.environ.get("ADMIN_SETUP_TOKEN") or os.environ.get("SETUP_TOKEN")

# Cấu hình Lưu trữ Đám mây (Tùy chọn cho Render Free Persistence: Cloudflare R2, AWS S3, Supabase)
S3_ENDPOINT_URL = os.environ.get("S3_ENDPOINT_URL")
S3_ACCESS_KEY_ID = os.environ.get("S3_ACCESS_KEY_ID")
S3_SECRET_ACCESS_KEY = os.environ.get("S3_SECRET_ACCESS_KEY")
S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME")
S3_REGION = os.environ.get("S3_REGION", "auto")

# Địa chỉ bind và cổng lắng nghe
HOST = os.environ.get("HOST", "0.0.0.0" if IS_PRODUCTION else "127.0.0.1")
PORT = int(os.environ.get("PORT", 5000))
