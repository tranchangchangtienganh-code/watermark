"""
Hệ thống Xác thực Quản Trị Viên (Admin Authentication System)
Chịu trách nhiệm:
1. Quản lý thiết lập mật khẩu lần đầu (Secure Initial Setup)
2. Mã hóa và lưu trữ mật khẩu an toàn (Scrypt / Salted Password Hash)
3. Giới hạn tần suất đăng nhập (Rate Limiting chống Brute-Force)
4. Xác thực và đổi mật khẩu quản trị viên
5. Tuyệt đối không lưu mật khẩu dạng plain-text hoặc công khai
"""
import os
import json
import time
from typing import Tuple, Dict, List, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
from config import DATA_DIR

AUTH_FILE = DATA_DIR / "admin_auth.json"
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 900  # 15 phút

class AdminAuthManager:
    """Quản lý xác thực và phân quyền cho Quản trị viên (Ms. Trang)"""

    _failed_attempts: Dict[str, List[float]] = {}

    @classmethod
    def is_configured(cls) -> bool:
        """Kiểm tra hệ thống đã được thiết lập mật khẩu quản trị viên ban đầu chưa"""
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
        # Lọc các lần thử trong phạm vi LOCKOUT_DURATION_SECONDS
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
    def setup_admin(cls, password: str) -> Tuple[bool, str]:
        """
        Thiết lập mật khẩu quản trị viên lần đầu:
        - Sử dụng thuật toán băm scrypt với muối ngẫu nhiên
        - Không lưu mật khẩu gốc
        """
        if cls.is_configured():
            return False, "Quản trị viên đã được thiết lập trước đó."

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
            return False, f"Mật khẩu không chính xác. Tài khoản tạm thời bị khóa 15 phút do nhập sai 5 lần."
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
