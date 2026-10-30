"""
Node 4: Kho Lưu trữ Tạm thời (Session Storage)
Chịu trách nhiệm:
1. Lưu trữ tệp gốc và tệp đã xuất bản trong từng phiên làm việc (Session ID độc lập)
2. Cung cấp API phục vụ tải xuống trực tiếp tệp đã đóng watermark và khóa
3. Lưu trữ tệp ảnh xem trước (Preview) cho giao diện người dùng
4. Tự động thu hồi và dọn dẹp các phiên làm việc hết hạn (TTL 2 giờ)
"""
import os
import json
import time
import shutil
import uuid
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from config import SESSIONS_DIR, SESSION_LIFETIME_SECONDS

class SessionStorage:
    """Quản lý kho lưu trữ phiên làm việc tạm thời"""

    _sessions_cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def create_session(
        cls,
        original_filename: str,
        file_bytes: bytes,
        file_type: str,
        extension: str,
        sha256: str
    ) -> Dict[str, Any]:
        """Tạo một phiên làm việc mới, phân bổ thư mục lưu trữ độc lập"""
        session_id = str(uuid.uuid4())
        session_dir = SESSIONS_DIR / session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        original_path = session_dir / f"original.{extension}"
        with open(original_path, "wb") as f:
            f.write(file_bytes)

        protected_filename = f"[DA_BAO_VE]_{original_filename}"
        protected_path = session_dir / f"protected.{extension}"
        preview_path = session_dir / "preview.png"
        meta_path = session_dir / "meta.json"

        created_at = time.time()
        session_data = {
            "session_id": session_id,
            "created_at": created_at,
            "expires_at": created_at + SESSION_LIFETIME_SECONDS,
            "original_filename": original_filename,
            "protected_filename": protected_filename,
            "file_type": file_type,
            "extension": extension,
            "original_path": str(original_path),
            "protected_path": str(protected_path),
            "preview_path": str(preview_path),
            "original_sha256": sha256,
            "original_size": len(file_bytes),
            "is_processed": False,
            "protected_sha256": None,
            "protected_size": None,
            "protection_details": None
        }

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(session_data, f, ensure_ascii=False, indent=2)

        cls._sessions_cache[session_id] = session_data
        return session_data

    @classmethod
    def get_session(cls, session_id: str) -> Optional[Dict[str, Any]]:
        """Lấy thông tin phiên làm việc từ bộ nhớ cache hoặc tệp meta.json"""
        if session_id in cls._sessions_cache:
            session = cls._sessions_cache[session_id]
            if time.time() > session.get("expires_at", 0):
                cls.delete_session(session_id)
                return None
            return session

        meta_path = SESSIONS_DIR / session_id / "meta.json"
        if meta_path.exists():
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if time.time() > data.get("expires_at", 0):
                    cls.delete_session(session_id)
                    return None
                cls._sessions_cache[session_id] = data
                return data
            except Exception:
                return None
        return None

    @classmethod
    def update_session(cls, session_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Cập nhật trạng thái sau khi đã đóng watermark và áp dụng chính sách bảo vệ"""
        session = cls.get_session(session_id)
        if not session:
            return None

        session.update(updates)
        cls._sessions_cache[session_id] = session

        meta_path = SESSIONS_DIR / session_id / "meta.json"
        try:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(session, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        return session

    @classmethod
    def get_download_target(cls, session_id: str) -> Optional[Tuple[str, str]]:
        """
        Lấy đường dẫn tệp ĐÃ BẢO VỆ (chứa watermark vĩnh viễn) để tải xuống công khai.
        Tuyệt đối không phục vụ tệp gốc chưa đóng watermark cho người dùng công cộng.
        """
        session = cls.get_session(session_id)
        if not session or not session.get("is_processed"):
            return None
        protected_path = session.get("protected_path")
        if not protected_path or not os.path.exists(protected_path):
            return None
        return protected_path, session.get("protected_filename", "tailieu_dabao_ve.pdf")

    @classmethod
    def get_original_target(cls, session_id: str) -> Optional[Tuple[str, str]]:
        """
        Lấy đường dẫn tệp gốc (chưa đóng watermark) - DÀNH RIÊNG CHO QUẢN TRỊ VIÊN ĐÃ XÁC THỰC
        """
        session = cls.get_session(session_id)
        if not session:
            return None
        original_path = session.get("original_path")
        if not original_path or not os.path.exists(original_path):
            return None
        return original_path, session.get("original_filename", "original_file")

    @classmethod
    def get_public_gallery(cls) -> list:
        """
        Lấy danh sách các tệp đã hoàn thành watermark phục vụ người dùng xem & tải về.
        Quét trực tiếp từ ổ lưu trữ để đảm bảo đồng bộ hoàn hảo giữa nhiều Gunicorn worker.
        """
        items = []
        now = time.time()
        
        # Đồng bộ từ ổ đĩa để hỗ trợ đa tiến trình Gunicorn (multi-worker support)
        if SESSIONS_DIR.exists():
            for folder in SESSIONS_DIR.iterdir():
                if folder.is_dir():
                    meta = folder / "meta.json"
                    if meta.exists():
                        try:
                            with open(meta, "r", encoding="utf-8") as f:
                                d = json.load(f)
                            if d.get("is_processed") and now <= d.get("expires_at", 0):
                                cls._sessions_cache[d["session_id"]] = d
                                items.append({
                                    "session_id": d["session_id"],
                                    "protected_filename": d.get("protected_filename"),
                                    "file_type": d.get("file_type"),
                                    "preview_url": f"/api/preview/{d['session_id']}",
                                    "download_url": f"/api/download/{d['session_id']}",
                                    "created_at": d.get("created_at"),
                                    "protected_sha256": d.get("protected_sha256"),
                                    "protected_size": d.get("protected_size")
                                })
                            elif now > d.get("expires_at", 0):
                                shutil.rmtree(folder, ignore_errors=True)
                        except Exception:
                            pass
        items.sort(key=lambda x: x.get("created_at", 0), reverse=True)
        return items

    @classmethod
    def delete_session(cls, session_id: str):
        """Xóa phiên làm việc khỏi cache và ổ đĩa"""
        cls._sessions_cache.pop(session_id, None)
        session_dir = SESSIONS_DIR / session_id
        if session_dir.exists():
            try:
                shutil.rmtree(session_dir, ignore_errors=True)
            except Exception:
                pass

    @classmethod
    def cleanup_expired_sessions(cls):
        """Dọn dẹp tất cả các phiên làm việc đã vượt quá thời gian TTL"""
        now = time.time()
        # Dọn dẹp cache
        expired_ids = [sid for sid, s in cls._sessions_cache.items() if now > s.get("expires_at", 0)]
        for sid in expired_ids:
            cls.delete_session(sid)

        # Quét thư mục vật lý
        if SESSIONS_DIR.exists():
            for folder in SESSIONS_DIR.iterdir():
                if folder.is_dir():
                    meta = folder / "meta.json"
                    if meta.exists():
                        try:
                            with open(meta, "r", encoding="utf-8") as f:
                                d = json.load(f)
                            if now > d.get("expires_at", 0):
                                shutil.rmtree(folder, ignore_errors=True)
                        except Exception:
                            pass
