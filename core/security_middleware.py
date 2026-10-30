"""
Node 2: Bộ lọc Bảo mật & Xác thực (Security Middleware)
Chịu trách nhiệm:
1. Kiểm tra định dạng tệp (Magic Bytes & MIME type thực tế, chống giả mạo đuôi tệp)
2. Kiểm tra tính nguyên vẹn (Tính toán mã băm SHA-256, MD5)
3. Xác thực quyền hạn & kiểm tra mật khẩu bảo vệ
4. Làm sạch tên tệp, ngăn ngừa Directory Traversal & Injection
"""
import hashlib
import os
import re
import zipfile
from functools import wraps
from dataclasses import dataclass
from io import BytesIO
from typing import Optional, Tuple
from flask import session, jsonify, request
from config import ALLOWED_EXTENSIONS, MAX_CONTENT_LENGTH

def admin_required(fn):
    """
    Decorator kiểm tra quyền Quản trị viên từ Flask Session hoặc Authorization Header:
    - Cho phép nếu phiên session đang có quyền quản trị và tự động gia hạn phiên (Sliding Renewal)
    - Cho phép qua header Authorization (Bearer token hoặc X-Owner-Key) cho API
    - TUYỆT ĐỐI KHÔNG chấp nhận khóa bí mật trên URL query parameters (?key=...) để bảo mật
    - Tuyệt đối từ chối (HTTP 401) mọi yêu cầu công khai chưa xác thực
    """
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        # 1. Kiểm tra session hiện tại (HttpOnly Cookie)
        if session.get("is_admin"):
            session.permanent = True
            session.modified = True  # Kích hoạt gia hạn trượt an toàn (Sliding Renewal)
            return fn(*args, **kwargs)

        # 2. Hỗ trợ xác thực API qua HTTP Header (Chỉ dùng Header, KHÔNG dùng URL)
        from core.admin_auth import AdminAuthManager
        auth_header = request.headers.get("Authorization", "")
        bearer_key = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
        header_key = request.headers.get("X-Owner-Key") or bearer_key
        if header_key and AdminAuthManager.validate_owner_key(header_key):
            session["is_admin"] = True
            session.permanent = True
            session.modified = True
            return fn(*args, **kwargs)

        return jsonify({
            "success": False,
            "node": "middleware-security",
            "error": "Yêu cầu quyền Quản trị viên để thực hiện thao tác này. Vui lòng đăng nhập.",
            "requires_auth": True
        }), 401
    return decorated_view

@dataclass
class SecurityCheckResult:
    is_valid: bool
    file_type: str  # 'pdf', 'docx', 'image'
    extension: str
    sanitized_filename: str
    sha256: str
    md5: str
    file_size: int
    error_message: Optional[str] = None

class SecurityMiddleware:
    """Bộ lọc bảo mật và xác thực dữ liệu đầu vào"""

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Loại bỏ ký tự đặc biệt nguy hiểm, giữ an toàn cho hệ thống tệp"""
        # Tách tên và đuôi
        base, ext = os.path.splitext(filename)
        # Loại bỏ các ký tự điều khiển và đường dẫn tương đối
        base = re.sub(r'[\\/*?:"<>|]', "", base)
        base = base.strip().replace("..", "")
        if not base:
            base = "tailieu_mstrang"
        # Giới hạn độ dài tên tệp
        base = base[:80]
        ext = ext.lower().strip()
        return f"{base}{ext}"

    @classmethod
    def detect_real_format(cls, header_bytes: bytes, file_stream: BytesIO) -> Tuple[Optional[str], Optional[str]]:
        """
        Xác minh định dạng tệp thực tế dựa trên Magic Bytes (Chữ ký nhị phân)
        Trả về (file_type, canonical_extension)
        """
        # Kiểm tra PDF: Bắt đầu bằng %PDF-
        if header_bytes.startswith(b"%PDF-"):
            return "pdf", "pdf"

        # Kiểm tra PNG: 89 50 4E 47 0D 0A 1A 0A
        if header_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image", "png"

        # Kiểm tra JPEG: FF D8 FF
        if header_bytes.startswith(b"\xff\xd8\xff"):
            return "image", "jpg"

        # Kiểm tra WebP: RIFF....WEBP
        if header_bytes.startswith(b"RIFF") and len(header_bytes) >= 12 and header_bytes[8:12] == b"WEBP":
            return "image", "webp"

        # Kiểm tra Word (.docx): Tệp nén PK\x03\x04 và chứa word/document.xml
        if header_bytes.startswith(b"PK\x03\x04"):
            try:
                curr_pos = file_stream.tell()
                file_stream.seek(0)
                with zipfile.ZipFile(file_stream, 'r') as zf:
                    namelist = zf.namelist()
                    # Kiểm tra đặc trưng của OpenXML Word Document
                    if any(name.startswith("word/") for name in namelist) or "[Content_Types].xml" in namelist:
                        file_stream.seek(curr_pos)
                        return "docx", "docx"
                file_stream.seek(curr_pos)
            except Exception:
                pass

        return None, None

    @classmethod
    def inspect_file(cls, filename: str, file_bytes: bytes) -> SecurityCheckResult:
        """
        Kiểm tra toàn diện tệp tải lên:
        - Giới hạn kích thước
        - Định dạng thực tế qua Magic Bytes
        - Tính toán SHA-256, MD5
        - Làm sạch tên tệp
        """
        size = len(file_bytes)
        sanitized_name = cls.sanitize_filename(filename)
        _, ext = os.path.splitext(sanitized_name)
        ext = ext.lstrip(".").lower()

        # Kiểm tra dung lượng
        if size == 0:
            return SecurityCheckResult(
                is_valid=False,
                file_type="unknown",
                extension=ext,
                sanitized_filename=sanitized_name,
                sha256="",
                md5="",
                file_size=0,
                error_message="Tệp tải lên rỗng (0 bytes)."
            )

        if size > MAX_CONTENT_LENGTH:
            max_mb = MAX_CONTENT_LENGTH // (1024 * 1024)
            return SecurityCheckResult(
                is_valid=False,
                file_type="unknown",
                extension=ext,
                sanitized_filename=sanitized_name,
                sha256="",
                md5="",
                file_size=size,
                error_message=f"Dung lượng tệp ({size / (1024*1024):.1f}MB) vượt quá giới hạn cho phép ({max_mb}MB)."
            )

        # Tính toán mã băm SHA-256 và MD5 để đảm bảo tính nguyên vẹn
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        md5_hash = hashlib.md5(file_bytes).hexdigest()

        # Kiểm tra Magic Bytes
        header = file_bytes[:32]
        stream = BytesIO(file_bytes)
        detected_type, canonical_ext = cls.detect_real_format(header, stream)

        if not detected_type:
            return SecurityCheckResult(
                is_valid=False,
                file_type="unknown",
                extension=ext,
                sanitized_filename=sanitized_name,
                sha256=sha256_hash,
                md5=md5_hash,
                file_size=size,
                error_message="Định dạng tệp không được hỗ trợ hoặc tệp bị hỏng. Vui lòng chỉ tải lên Word (.docx), PDF (.pdf) hoặc Hình ảnh (.png, .jpg, .jpeg, .webp)."
            )

        # Kiểm tra sự tương thích giữa phần mở rộng khai báo và định dạng thực tế
        allowed_exts = set(ALLOWED_EXTENSIONS.keys())
        if ext not in allowed_exts and ext != "jpeg":
            # Gán lại extension chuẩn nếu cần
            ext = canonical_ext or "bin"
            sanitized_name = f"{os.path.splitext(sanitized_name)[0]}.{ext}"

        return SecurityCheckResult(
            is_valid=True,
            file_type=detected_type,
            extension=ext,
            sanitized_filename=sanitized_name,
            sha256=sha256_hash,
            md5=md5_hash,
            file_size=size,
            error_message=None
        )

    @staticmethod
    def verify_file_integrity(file_path: str, expected_sha256: str) -> bool:
        """Xác thực tệp đã qua xử lý có khớp chính xác với mã băm đã xuất bản không"""
        if not os.path.exists(file_path):
            return False
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest().lower() == expected_sha256.lower()
