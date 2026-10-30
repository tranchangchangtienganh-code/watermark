"""
Hệ thống Xác thực Quản Trị Viên (Admin Authentication System)
Tối ưu hóa cho Người Dùng Duy Nhất (Single-Owner Mode - Ms. Trần Thị Thu Trang):
1. Loại bỏ hoàn toàn màn hình/popup Setup Token gây phiền toái cho chủ sở hữu
2. Hỗ trợ xác thực một chạm qua Owner Key / Private Access Link (?key=...)
3. Duy trì phiên đăng nhập vĩnh viễn (365 ngày), loại bỏ yêu cầu đăng nhập lặp đi lặp lại
4. Bảo vệ an toàn tuyệt đối các API quản trị (chặn mọi truy cập công khai chưa xác thực)
5. Hỗ trợ xác thực đa nguồn: Session Cookie dài hạn, Header X-Owner-Key, Bearer Token
6. Mã hóa và lưu trữ mật khẩu an toàn (Scrypt / Salted Password Hash)
7. Tự động cấp và duy trì quyền qua các lần Render Free ngủ đông / khởi động lại
"""
import os
import json
import time
import secrets
from typing import Tuple, Dict, List, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
from config import DATA_DIR, ADMIN_INITIAL_PASSWORD, SETUP_TOKEN, IS_PRODUCTION, OWNER_KEY, SINGLE_OWNER_MODE

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
    def _get_or_create_owner_key(cls) -> str:
        """
        Lấy hoặc sinh mã khóa truy cập chủ sở hữu cố định cho hệ thống:
        - Ưu tiên đọc từ biến môi trường OWNER_KEY, ADMIN_SETUP_TOKEN hoặc ADMIN_INITIAL_PASSWORD
        - Nếu chưa có, duy trì khóa cố định trong tệp .owner_key
        """
        for env_var in ["OWNER_KEY", "ADMIN_ACCESS_KEY", "ADMIN_SETUP_TOKEN", "SETUP_TOKEN", "ADMIN_INITIAL_PASSWORD"]:
            val = os.environ.get(env_var)
            if val:
                s = cls._sanitize_token(val)
                if s:
                    return s

        key_file = DATA_DIR / ".owner_key"
        if key_file.exists():
            try:
                k = cls._sanitize_token(key_file.read_text(encoding="utf-8"))
                if k:
                    return k
            except Exception:
                pass

        # Sinh mã ngẫu nhiên 32 hex chars an toàn
        new_key = secrets.token_hex(16)
        try:
            key_file.write_text(new_key, encoding="utf-8")
        except Exception:
            pass
        return new_key

    @classmethod
    def get_valid_setup_tokens(cls) -> List[str]:
        """
        Lấy danh sách tất cả các setup token / owner key hợp lệ từ biến môi trường.
        Hỗ trợ cả OWNER_KEY, ADMIN_SETUP_TOKEN, SETUP_TOKEN và ADMIN_INITIAL_PASSWORD.
        """
        candidates: List[str] = []
        for key in ["OWNER_KEY", "ADMIN_ACCESS_KEY", "ADMIN_SETUP_TOKEN", "SETUP_TOKEN", "ADMIN_INITIAL_PASSWORD"]:
            raw = os.environ.get(key)
            if raw:
                cleaned = cls._sanitize_token(raw)
                if cleaned and cleaned not in candidates:
                    candidates.append(cleaned)

        return candidates

    @classmethod
    def validate_owner_key(cls, candidate: str) -> bool:
        """
        Xác thực mã truy cập chủ sở hữu (Owner Key / Setup Token / Password).
        Sử dụng so sánh thời gian bất biến (constant-time) chống timing attacks.
        """
        if not candidate:
            return False

        cleaned = cls._sanitize_token(candidate)
        if not cleaned:
            return False

        # 1. So khớp với các biến môi trường được cấu hình
        valid_keys = cls.get_valid_setup_tokens()
        for vk in valid_keys:
            if secrets.compare_digest(cleaned, vk):
                return True

        # 2. So khớp với khóa chủ sở hữu lưu cục bộ (.owner_key)
        key_file = DATA_DIR / ".owner_key"
        if key_file.exists():
            try:
                k = cls._sanitize_token(key_file.read_text(encoding="utf-8"))
                if k and secrets.compare_digest(cleaned, k):
                    return True
            except Exception:
                pass

        # 3. So khớp với mật khẩu băm đã lưu trong AUTH_FILE
        if AUTH_FILE.exists():
            try:
                with open(AUTH_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                stored_hash = data.get("password_hash")
                if stored_hash and check_password_hash(stored_hash, cleaned):
                    return True
            except Exception:
                pass

        return False

    @classmethod
    def init_app(cls):
        """
        Khởi tạo và đồng bộ quyền Quản trị viên khi ứng dụng khởi động.
        Đảm bảo tính bền vững (Persistence) qua các lần khởi động lại của Render Free:
        - Khôi phục từ ADMIN_PASSWORD_HASH nếu có
        - Hoặc tự động khởi tạo từ ADMIN_INITIAL_PASSWORD / OWNER_KEY
        - Tự động kích hoạt chế độ Single-Owner để loại bỏ hoàn toàn popup Setup Token
        """
        # Hủy bỏ tệp token tạm thời cũ nếu còn tồn tại
        old_token_file = DATA_DIR / ".setup_token"
        if old_token_file.exists():
            try:
                old_token_file.unlink()
            except Exception:
                pass

        # 1. Khôi phục trực tiếp từ mã băm môi trường ADMIN_PASSWORD_HASH
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

        # 2. Khôi phục hoặc khởi tạo từ ADMIN_INITIAL_PASSWORD hoặc OWNER_KEY hoặc ADMIN_SETUP_TOKEN
        env_pass = (
            cls._sanitize_token(os.environ.get("ADMIN_INITIAL_PASSWORD"))
            or cls._sanitize_token(os.environ.get("OWNER_KEY"))
            or cls._sanitize_token(os.environ.get("ADMIN_ACCESS_KEY"))
            or cls._sanitize_token(os.environ.get("ADMIN_SETUP_TOKEN"))
            or cls._sanitize_token(os.environ.get("SETUP_TOKEN"))
            or ADMIN_INITIAL_PASSWORD
        )
        if env_pass and not cls.is_configured():
            cls.setup_admin(env_pass, bypass_token=True)
            print("[BẢO MẬT] Đã tự động cấu hình quyền chủ sở hữu từ biến môi trường.")
            return

        # 3. Chế độ Single-Owner tự động kích hoạt tài khoản ban đầu
        # Loại bỏ hoàn toàn màn hình Setup Token popup gây phiền toái cho Ms. Trang
        if not cls.is_configured() and SINGLE_OWNER_MODE:
            default_key = cls._get_or_create_owner_key()
            cls.setup_admin(default_key, bypass_token=True)
            print("[BẢO MẬT] Chế độ Single-Owner: Đã tự động kích hoạt tài khoản chủ sở hữu an toàn (Zero-Popup Setup).")

    @classmethod
    def get_required_setup_token(cls) -> Optional[str]:
        """Trả về setup token ưu tiên hàng đầu nếu có"""
        tokens = cls.get_valid_setup_tokens()
        return tokens[0] if tokens else None

    @classmethod
    def is_setup_locked(cls) -> bool:
        """
        Kiểm tra xem quy trình thiết lập có bị khóa hay không:
        Nếu trên môi trường sản xuất công khai mà chưa có mật khẩu hoặc token bí mật,
        hệ thống kích hoạt khóa chống chiếm đoạt quyền (Anti-Hijacking).
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
        """Trong Single-Owner Mode, không bắt buộc người dùng nhập token popup"""
        if SINGLE_OWNER_MODE:
            return False
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
        """Ghi nhận lần thử xác thực thất bại"""
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
        - Sử dụng thuật toán băm scrypt với muối ngẫu nhiên (Salted Password Hash)
        """
        if cls.is_configured():
            return False, "Quản trị viên đã được thiết lập trước đó. Vui lòng đăng nhập bằng mật khẩu hiện tại."

        # Kiểm tra khóa chống chiếm đoạt trên môi trường công khai nếu không bypass
        if not bypass_token and cls.is_setup_locked():
            return False, "Hệ thống đang ở chế độ bảo vệ chống chiếm đoạt quyền. Vui lòng cấu hình biến môi trường ADMIN_SETUP_TOKEN hoặc ADMIN_INITIAL_PASSWORD trong Render Dashboard để kích hoạt."

        valid_tokens = cls.get_valid_setup_tokens()
        if valid_tokens and not bypass_token:
            cleaned_input = cls._sanitize_token(setup_token)
            if not cleaned_input:
                return False, "Vui lòng nhập mã kích hoạt thiết lập (Setup Token)."

            matched = any(secrets.compare_digest(cleaned_input, t) for t in valid_tokens)
            if not matched:
                return False, "Mã kích hoạt thiết lập (Setup Token) không chính xác hoặc chưa được cung cấp."

        cleaned_password = password.strip() if password else ""
        if not cleaned_password or len(cleaned_password) < 6:
            return False, "Mật khẩu quản trị viên phải có ít nhất 6 ký tự."

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

        return True, "Thiết lập mật khẩu quản trị viên thành công."

    @classmethod
    def authenticate(cls, password: str, ip: str) -> Tuple[bool, str]:
        """
        Xác thực đăng nhập quản trị viên / chủ sở hữu với Rate Limiting:
        Chấp nhận cả Mật khẩu Quản trị hoặc Mã khóa Chủ sở hữu (Owner Key)
        Trả về (success, message)
        """
        is_allowed, remaining, lockout_sec = cls.check_rate_limit(ip)
        if not is_allowed:
            mins = (lockout_sec + 59) // 60
            return False, f"Bạn đã nhập sai quá số lần cho phép. Vui lòng thử lại sau {mins} phút."

        # 1. Kiểm tra khớp Owner Key / Token trước
        if cls.validate_owner_key(password):
            cls.reset_rate_limit(ip)
            return True, "Xác thực quyền Chủ sở hữu (Ms. Trang) thành công."

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
            return False, "Mã khóa hoặc mật khẩu không chính xác. Tài khoản tạm thời bị khóa 15 phút do nhập sai 5 lần."
        return False, f"Mã khóa hoặc mật khẩu không chính xác. Bạn còn {rem} lần thử trước khi bị tạm khóa."

    @classmethod
    def change_password(cls, current_password: str, new_password: str) -> Tuple[bool, str]:
        """Đổi mật khẩu quản trị viên (yêu cầu mật khẩu hoặc Owner Key hiện tại)"""
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

        # Cho phép đổi mật khẩu nếu nhập đúng mật khẩu cũ HOẶC đúng Owner Key
        is_owner_key_valid = cls.validate_owner_key(current_password)
        is_password_valid = check_password_hash(stored_hash, current_password) if stored_hash else False

        if not is_owner_key_valid and not is_password_valid:
            return False, "Mật khẩu hiện tại không chính xác."

        if is_password_valid and check_password_hash(stored_hash, new_password):
            return False, "Mật khẩu mới không được trùng với mật khẩu hiện tại."

        data["password_hash"] = generate_password_hash(new_password.strip())
        data["updated_at"] = time.time()

        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        return True, "Đổi mật khẩu quản trị viên thành công."
