"""
Hệ thống Xác thực Quản Trị Viên (Admin Authentication System)
Chịu trách nhiệm:
1. Quản lý thiết lập mật khẩu lần đầu (Secure Initial Setup & Anti-Exploit Protection)
2. Tự động cấp quyền quản trị từ biến môi trường ADMIN_INITIAL_PASSWORD trên Render
3. Bảo vệ quy trình thiết lập bằng SETUP_TOKEN trên môi trường sản xuất công khai
4. Mã hóa và lưu trữ mật khẩu an toàn (Scrypt / Salted Password Hash)
5. Giới hạn tần suất đăng nhập (Rate Limiting chống Brute-Force)
6. Xác thực và đổi mật khẩu quản trị viên
"""
import os
import json
import time
import secrets
from typing import Tuple, Dict, List, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
from config import DATA_DIR, ADMIN_INITIAL_PASSWORD, SETUP_TOKEN, IS_PRODUCTION

AUTH_FILE = DATA_DIR / "admin_auth.json"
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 900  # 15 phút

class AdminAuthManager:
    """Quản lý xác thực và phân quyền cho Quản trị viên (Ms. Trang)"""

    _failed_attempts: Dict[str, List[float]] = {}
    _ephemeral_setup_token: Optional[str] = None

    @classmethod
    def init_app(cls):
        """Khởi tạo và đồng bộ quyền Quản trị viên khi ứng dụng khởi động"""
        # Nếu có biến môi trường ADMIN_INITIAL_PASSWORD và chưa cấu hình -> Tự động khởi tạo ngay lập tức
        if ADMIN_INITIAL_PASSWORD and not cls.is_configured():
            cls.setup_admin(ADMIN_INITIAL_PASSWORD, bypass_token=True)
            print("[BẢO MẬT] Đã tự động khởi tạo tài khoản Quản trị viên từ biến môi trường ADMIN_INITIAL_PASSWORD.")
            return

        # Nếu chưa cấu hình và trên môi trường Production mà không có SETUP_TOKEN trong env
        # Tự động sinh One-Time Setup Token để ngăn chặn bất kỳ ai bên ngoài chiếm đoạt quyền quản trị
        if not cls.is_configured() and not SETUP_TOKEN and IS_PRODUCTION:
            token_file = DATA_DIR / ".setup_token"
            if token_file.exists():
                try:
                    cls._ephemeral_setup_token = token_file.read_text(encoding="utf-8").strip()
                except Exception:
                    cls._ephemeral_setup_token = secrets.token_hex(16)
            else:
                cls._ephemeral_setup_token = secrets.token_hex(16)
                try:
                    token_file.write_text(cls._ephemeral_setup_token, encoding="utf-8")
                except Exception:
                    pass
            print("=" * 60)
            print("[CẢNH BÁO BẢO MẬT RENDER] Hệ thống chưa có mật khẩu Quản trị viên.")
            print(f"[*] Mã kích hoạt thiết lập an toàn (One-Time Setup Token): {cls._ephemeral_setup_token}")
            print("[*] Vui lòng sử dụng mã này trên giao diện hoặc đặt biến môi trường ADMIN_INITIAL_PASSWORD.")
            print("=" * 60)

    @classmethod
    def get_required_setup_token(cls) -> Optional[str]:
        """Trả về setup token bắt buộc nếu hệ thống yêu cầu mã xác minh khi thiết lập lần đầu"""
        token = os.environ.get("SETUP_TOKEN") or SETUP_TOKEN
        if token:
            return token.strip()
        if (IS_PRODUCTION or os.environ.get("RENDER") == "true") and cls._ephemeral_setup_token:
            return cls._ephemeral_setup_token
        return None

    @classmethod
    def is_setup_token_required(cls) -> bool:
        """Kiểm tra xem hệ thống có yêu cầu mã token khi thiết lập lần đầu không"""
        return bool(cls.get_required_setup_token())

    @classmethod
    def is_configured(cls) -> bool:
        """Kiểm tra hệ thống đã được thiết lập mật khẩu quản trị viên chưa"""
        if not AUTH_FILE.exists():
            return False
        try:
            with open(AUTH_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return bool(data.get("password_hash"))
        except Exception:
            return False

    @classmethod
    def check_rate_limit(cls, ip: str) -> Tuple[bool, int, int]:
        """
        Kiểm tra số lần đăng nhập thất bại của IP:
        Trả về: (is_allowed, remaining_attempts, lockout_remaining_seconds)
        """
        now = time.time()
        attempts = cls._failed_attempts.get(ip, [])
        recent = [t for t in attempts if now - t < LOCKOUT_DURATION_SECONDS]
        cls._failed_attempts[ip] = recent

        if len(recent) >= MAX_FAILED_ATTEMPTS:
            oldest_attempt = min(recent)
            lockout_left = int(LOCKOUT_DURATION_SECONDS - (now - oldest_attempt))
            return False, 0, max(1, lockout_left)

        remaining = MAX_FAILED_ATTEMPTS - len(recent)
        return True, remaining, 0

    @classmethod
    def record_failed_attempt(cls, ip: str):
        """Ghi nhận lần đăng nhập thất bại"""
        now = time.time()
        if ip not in cls._failed_attempts:
            cls._failed_attempts[ip] = []
        cls._failed_attempts[ip].append(now)

    @classmethod
    def reset_rate_limit(cls, ip: str):
        """Xóa lịch sử thất bại khi đăng nhập thành công"""
        cls._failed_attempts.pop(ip, None)

    @classmethod
    def setup_admin(
        cls,
        password: str,
        setup_token: Optional[str] = None,
        bypass_token: bool = False
    ) -> Tuple[bool, str]:
        """
        Thiết lập mật khẩu quản trị viên lần đầu:
        - Kiểm tra mã bảo vệ setup token (chống khai thác trái phép trên Render công khai)
        - Sử dụng thuật toán băm scrypt với muối ngẫu nhiên
        """
        if cls.is_configured():
            return False, "Quản trị viên đã được thiết lập trước đó."

        # Kiểm tra mã setup token nếu hệ thống yêu cầu
        required_token = cls.get_required_setup_token()
        if required_token and not bypass_token:
            if not setup_token or not secrets.compare_digest(setup_token.strip(), required_token):
                return False, "Mã kích hoạt thiết lập (Setup Token) không chính xác hoặc chưa được cung cấp."

        if not password or len(password.strip()) < 6:
            return False, "Mật khẩu quản trị viên phải có ít nhất 6 ký tự."

        # Băm mật khẩu bằng thuật toán scrypt chuẩn Werkzeug
        hashed = generate_password_hash(password.strip())
        now = time.time()
        auth_data = {
            "password_hash": hashed,
            "created_at": now,
            "updated_at": now,
            "last_login": None
        }

        AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(auth_data, f, ensure_ascii=False, indent=2)

        # Xóa token tạm thời nếu có
        token_file = DATA_DIR / ".setup_token"
        if token_file.exists():
            try:
                token_file.unlink()
            except Exception:
                pass
        cls._ephemeral_setup_token = None

        return True, "Thiết lập mật khẩu quản trị viên thành công."

    @classmethod
    def authenticate(cls, password: str, ip: str) -> Tuple[bool, str]:
        """
        Xác thực đăng nhập quản trị viên với Rate Limiting:
        Trả về (success, message)
        """
        is_allowed, remaining, lockout_sec = cls.check_rate_limit(ip)
        if not is_allowed:
            mins = (lockout_sec + 59) // 60
            return False, f"Bạn đã nhập sai quá số lần cho phép. Vui lòng thử lại sau {mins} phút."

        if not cls.is_configured():
            return False, "Hệ thống chưa được thiết lập tài khoản quản trị viên ban đầu."

        try:
            with open(AUTH_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            stored_hash = data.get("password_hash", "")
        except Exception:
            return False, "Không thể đọc dữ liệu xác thực."

        if check_password_hash(stored_hash, password):
            cls.reset_rate_limit(ip)
            data["last_login"] = time.time()
            try:
                with open(AUTH_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
            return True, "Đăng nhập quyền Quản trị viên thành công."

        # Ghi nhận lần nhập sai
        cls.record_failed_attempt(ip)
        _, rem, _ = cls.check_rate_limit(ip)
        if rem == 0:
            return False, "Mật khẩu không chính xác. Tài khoản tạm thời bị khóa 15 phút do nhập sai 5 lần."
        return False, f"Mật khẩu không chính xác. Bạn còn {rem} lần thử trước khi bị tạm khóa."

    @classmethod
    def change_password(cls, current_password: str, new_password: str) -> Tuple[bool, str]:
        """Đổi mật khẩu quản trị viên (yêu cầu mật khẩu hiện tại)"""
        if not cls.is_configured():
            return False, "Hệ thống chưa được cấu hình quản trị viên."

        if not new_password or len(new_password.strip()) < 6:
            return False, "Mật khẩu mới phải có ít nhất 6 ký tự."

        try:
            with open(AUTH_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            stored_hash = data.get("password_hash", "")
        except Exception:
            return False, "Lỗi đọc dữ liệu xác thực."

        if not check_password_hash(stored_hash, current_password):
            return False, "Mật khẩu hiện tại không chính xác."

        if check_password_hash(stored_hash, new_password):
            return False, "Mật khẩu mới không được trùng với mật khẩu hiện tại."

        data["password_hash"] = generate_password_hash(new_password.strip())
        data["updated_at"] = time.time()

        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        return True, "Đổi mật khẩu quản trị viên thành công."
