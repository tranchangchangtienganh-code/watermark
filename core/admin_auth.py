"""
Hệ thống Xác thực Quản Trị Viên (Admin Authentication System)
Chịu trách nhiệm:
1. Quản lý thiết lập mật khẩu lần đầu (Secure Initial Setup & Anti-Hijacking Protection)
2. Tự động cấp và khôi phục quyền quản trị từ biến môi trường ADMIN_INITIAL_PASSWORD / ADMIN_PASSWORD_HASH (Persistent across Render Free restarts)
3. Bảo vệ quy trình thiết lập bằng ADMIN_SETUP_TOKEN hoặc SETUP_TOKEN trên môi trường sản xuất công khai
4. Khóa chống chiếm đoạt (Anti-Hijacking Gate): Từ chối thiết lập khi chưa cấu hình token trên đám mây
5. Tuyệt đối không in (Zero-Leak) token, mật khẩu hay mã băm ra log máy chủ
6. Xử lý chuẩn hóa an toàn khoảng trắng, dấu ngoặc kép/đơn ("..." hoặc '...') và Windows CRLF
7. Hỗ trợ xác thực đa biến token (không bị xung đột giữa ADMIN_SETUP_TOKEN và SETUP_TOKEN)
8. Mã hóa và lưu trữ mật khẩu an toàn (Scrypt / Salted Password Hash)
9. Giới hạn tần suất đăng nhập và thử mã thiết lập (Rate Limiting chống Brute-Force)
10. Xác thực và đổi mật khẩu quản trị viên
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

    @staticmethod
    def _sanitize_token(val: Optional[str]) -> str:
        """
        Chuẩn hóa và làm sạch token/mật khẩu an toàn:
        - Xóa khoảng trắng đầu/cuối, tab, xuống dòng (\\r, \\n)
        - Xóa dấu ngoặc kép hoặc ngoặc đơn bao quanh (\"...\" hoặc '...') do người dùng hoặc Render vô tình thêm vào
        """
        if not val:
            return ""
        val = str(val).strip()
        if len(val) >= 2:
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1].strip()
        return val

    @classmethod
    def get_valid_setup_tokens(cls) -> List[str]:
        """
        Lấy danh sách tất cả các setup token hợp lệ được cấu hình qua biến môi trường.
        Hỗ trợ cả ADMIN_SETUP_TOKEN lẫn SETUP_TOKEN, tự động chuẩn hóa quotes và whitespace.
        Đọc trực tiếp từ os.environ trong từng request để luôn phản ánh biến môi trường mới nhất.
        """
        candidates: List[str] = []
        for key in ["ADMIN_SETUP_TOKEN", "SETUP_TOKEN"]:
            raw = os.environ.get(key)
            if raw:
                cleaned = cls._sanitize_token(raw)
                if cleaned and cleaned not in candidates:
                    candidates.append(cleaned)

        if SETUP_TOKEN:
            cleaned = cls._sanitize_token(SETUP_TOKEN)
            if cleaned and cleaned not in candidates:
                candidates.append(cleaned)

        return candidates

    @classmethod
    def init_app(cls):
        """
        Khởi tạo và đồng bộ quyền Quản trị viên khi ứng dụng khởi động.
        Đảm bảo tính bền vững (Persistence) qua các lần khởi động lại của Render Free:
        - Khôi phục từ ADMIN_PASSWORD_HASH nếu có
        - Hoặc tự động khởi tạo từ ADMIN_INITIAL_PASSWORD nếu có
        - Hủy bỏ và vô hiệu hóa vĩnh viễn các token cũ bị lộ
        - Tuyệt đối không in bất kỳ token hay mật khẩu nào ra log console
        """
        # Hủy bỏ và xóa triệt để mọi tệp token tạm thời cũ nếu còn tồn tại
        old_token_file = DATA_DIR / ".setup_token"
        if old_token_file.exists():
            try:
                old_token_file.unlink()
            except Exception:
                pass

        # 1. Khôi phục trực tiếp từ mã băm môi trường ADMIN_PASSWORD_HASH (Duy trì bền vững trên Render Free)
        env_hash = cls._sanitize_token(os.environ.get("ADMIN_PASSWORD_HASH"))
        if env_hash and not cls.is_configured():
            now = time.time()
            auth_data = {
                "password_hash": env_hash,
                "created_at": now,
                "updated_at": now,
                "last_login": None
            }
            AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(AUTH_FILE, "w", encoding="utf-8") as f:
                json.dump(auth_data, f, ensure_ascii=False, indent=2)
            print("[BẢO MẬT] Đã đồng bộ tài khoản Quản trị viên từ cấu hình môi trường bảo mật (ADMIN_PASSWORD_HASH).")
            return

        # 2. Khôi phục hoặc khởi tạo từ ADMIN_INITIAL_PASSWORD nếu có
        env_pass = cls._sanitize_token(os.environ.get("ADMIN_INITIAL_PASSWORD") or ADMIN_INITIAL_PASSWORD)
        if env_pass and not cls.is_configured():
            cls.setup_admin(env_pass, bypass_token=True)
            print("[BẢO MẬT] Đã tự động khởi tạo tài khoản Quản trị viên từ cấu hình môi trường bảo mật (ADMIN_INITIAL_PASSWORD).")
            return

        # 3. Ghi nhận trạng thái bảo mật (Tuyệt đối không in giá trị token ra log)
        if not cls.is_configured():
            if cls.get_valid_setup_tokens():
                print("[BẢO MẬT] Hệ thống sẵn sàng cho quy trình thiết lập Quản trị viên lần đầu qua Web UI (đã kích hoạt Setup Token bảo vệ).")
            elif IS_PRODUCTION or os.environ.get("RENDER") == "true":
                print("[CẢNH BÁO BẢO MẬT] Chưa thiết lập Quản trị viên. Để kích hoạt an toàn trên Render, vui lòng đặt biến môi trường ADMIN_SETUP_TOKEN hoặc ADMIN_INITIAL_PASSWORD trong Render Dashboard (Environment tab). Chức năng thiết lập công khai tạm thời bị khóa để chống chiếm đoạt quyền.")

    @classmethod
    def get_required_setup_token(cls) -> Optional[str]:
        """
        Trả về setup token ưu tiên hàng đầu từ biến môi trường bí mật.
        Hỗ trợ cả ADMIN_SETUP_TOKEN lẫn SETUP_TOKEN.
        """
        tokens = cls.get_valid_setup_tokens()
        return tokens[0] if tokens else None

    @classmethod
    def is_setup_locked(cls) -> bool:
        """
        Kiểm tra xem quy trình thiết lập công khai có đang bị khóa chống chiếm đoạt hay không:
        Trên môi trường Production / Render, nếu chưa cấu hình quản trị viên và không có
        ADMIN_INITIAL_PASSWORD, ADMIN_PASSWORD_HASH, ADMIN_SETUP_TOKEN hoặc SETUP_TOKEN trong biến môi trường,
        hệ thống sẽ KHÓA chức năng setup để người ngoài không thể chiếm đoạt.
        """
        if cls.is_configured():
            return False

        is_prod = IS_PRODUCTION or os.environ.get("RENDER") == "true"
        has_credentials = bool(
            cls._sanitize_token(os.environ.get("ADMIN_INITIAL_PASSWORD"))
            or cls._sanitize_token(os.environ.get("ADMIN_PASSWORD_HASH"))
            or cls.get_valid_setup_tokens()
        )
        if is_prod and not has_credentials:
            return True

        return False

    @classmethod
    def is_setup_token_required(cls) -> bool:
        """Kiểm tra xem hệ thống có yêu cầu mã token khi thiết lập lần đầu không"""
        return bool(cls.get_valid_setup_tokens())

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
        Kiểm tra số lần đăng nhập / thiết lập thất bại của IP:
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
        """Ghi nhận lần thử xác thực / thiết lập thất bại"""
        now = time.time()
        if ip not in cls._failed_attempts:
            cls._failed_attempts[ip] = []
        cls._failed_attempts[ip].append(now)

    @classmethod
    def reset_rate_limit(cls, ip: str):
        """Xóa lịch sử thất bại khi xác thực thành công"""
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
        - Kiểm tra khóa chống chiếm đoạt quyền (Anti-Hijacking Gate)
        - So sánh thời gian bất biến (Constant-Time Compare) với TẤT CẢ các token hợp lệ được cấu hình
        - Tự động chuẩn hóa loại bỏ khoảng trắng và dấu ngoặc kép bao quanh
        - Sử dụng thuật toán băm scrypt với muối ngẫu nhiên (Salted Password Hash)
        """
        if cls.is_configured():
            return False, "Quản trị viên đã được thiết lập trước đó. Vui lòng đăng nhập bằng mật khẩu hiện tại."

        # Kiểm tra khóa chống chiếm đoạt trên môi trường công khai
        if cls.is_setup_locked():
            return False, "Hệ thống đang ở chế độ bảo vệ chống chiếm đoạt quyền. Vui lòng cấu hình biến môi trường ADMIN_SETUP_TOKEN hoặc ADMIN_INITIAL_PASSWORD trong Render Dashboard để kích hoạt."

        # Kiểm tra mã setup token nếu hệ thống yêu cầu
        valid_tokens = cls.get_valid_setup_tokens()
        if valid_tokens and not bypass_token:
            cleaned_input = cls._sanitize_token(setup_token)
            if not cleaned_input:
                return False, "Vui lòng nhập mã kích hoạt thiết lập (Setup Token)."

            # So sánh an toàn thời gian bất biến (constant-time) với tất cả token hợp lệ
            matched = any(secrets.compare_digest(cleaned_input, t) for t in valid_tokens)
            if not matched:
                return False, "Mã kích hoạt thiết lập (Setup Token) không chính xác hoặc chưa được cung cấp."

        cleaned_password = password.strip() if password else ""
        if not cleaned_password or len(cleaned_password) < 6:
            return False, "Mật khẩu quản trị viên phải có ít nhất 6 ký tự."

        # Băm mật khẩu bằng thuật toán scrypt chuẩn Werkzeug
        hashed = generate_password_hash(cleaned_password)
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

        # Xóa triệt để tệp token tạm thời cũ nếu còn sót lại
        old_token = DATA_DIR / ".setup_token"
        if old_token.exists():
            try:
                old_token.unlink()
            except Exception:
                pass

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
