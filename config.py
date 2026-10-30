"""
Hệ thống Đóng Watermark & Khóa Tệp Chống Chỉnh Sửa
Cấu hình hệ thống (Configuration)
Dành riêng cho Ms. Trần Thị Thu Trang
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Đường dẫn thư mục dữ liệu và phiên làm việc (Session Storage)
DATA_DIR = BASE_DIR / "data"
SESSIONS_DIR = DATA_DIR / "sessions"
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

# Đường dẫn font chữ hỗ trợ tiếng Việt đầy đủ
FONTS_DIR = BASE_DIR / "core" / "fonts"
DEFAULT_FONT_PATH = FONTS_DIR / "arial.ttf"

# Cấu hình bảo mật và giới hạn tệp
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB
ALLOWED_EXTENSIONS = {
    "pdf": ["application/pdf"],
    "docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    "png": ["image/png"],
    "jpg": ["image/jpeg"],
    "jpeg": ["image/jpeg"],
    "webp": ["image/webp"]
}

# Thời gian hết hạn của phiên làm việc (giây) - Mặc định 2 giờ
SESSION_LIFETIME_SECONDS = 7200

# Cấu hình mặc định cho Watermark Ms. Trang
DEFAULT_WATERMARK_TEXT = "TRẦN THỊ THU TRANG"
DEFAULT_SUB_TEXT = "BẢN QUYỀN SỞ HỮU • NGHIÊM CẤM SAO CHÉP & CHỈNH SỬA"
DEFAULT_GRAY_COLOR_HEX = "#708090"  # Slate Gray thanh lịch
DEFAULT_GRAY_COLOR_RGB = (112, 128, 144)

# Khóa bí mật máy chủ (Tự động sinh khóa ngẫu nhiên an toàn nếu chưa có)
def _get_or_create_secret_key() -> str:
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    key_file = DATA_DIR / ".secret_key"
    if key_file.exists():
        try:
            return key_file.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    import secrets
    new_key = secrets.token_hex(32)
    try:
        key_file.write_text(new_key, encoding="utf-8")
    except Exception:
        pass
    return new_key

SECRET_KEY = _get_or_create_secret_key()
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", 5000))
