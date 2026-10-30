"""
Node 4: Kho Lưu trữ Tạm thời (Session Storage)
Chịu trách nhiệm:
1. Lưu trữ tệp gốc và tệp đã xuất bản trong từng phiên làm việc (Session ID độc lập)
2. Cung cấp API phục vụ tải xuống trực tiếp tệp đã đóng watermark và khóa
3. Lưu trữ tệp ảnh xem trước (Preview) cho giao diện người dùng
4. Tự động thu hồi và dọn dẹp các phiên làm việc hết hạn (TTL 2 giờ)
5. Hỗ trợ tính bền vững (Persistence) qua Render Free restarts bằng:
   - Render Persistent Disk (mặc định tại DATA_DIR / SESSIONS_DIR)
   - Hoặc Đồng bộ Lưu trữ Đám mây Object Storage (Cloudflare R2, AWS S3, Supabase)
"""
import os
import json
import time
import shutil
import uuid
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
from config import (
    SESSIONS_DIR, SESSION_LIFETIME_SECONDS,
    S3_ENDPOINT_URL, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY,
    S3_BUCKET_NAME, S3_REGION
)

# Khởi tạo tùy chọn Boto3 S3 Client (nếu cấu hình biến môi trường đám mây)
_s3_client = None
if S3_BUCKET_NAME and S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY:
    try:
        import boto3
        from botocore.config import Config
        _s3_client = boto3.client(
            "s3",
            endpoint_url=S3_ENDPOINT_URL if S3_ENDPOINT_URL else None,
            aws_access_key_id=S3_ACCESS_KEY_ID,
            aws_secret_access_key=S3_SECRET_ACCESS_KEY,
            region_name=S3_REGION or "auto",
            config=Config(signature_version="s3v4", retries={"max_attempts": 3, "mode": "standard"})
        )
    except Exception as e:
        _s3_client = None

class SessionStorage:
    """Quản lý kho lưu trữ phiên làm việc tạm thời và đồng bộ persistent storage"""

    _sessions_cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def _upload_to_s3(cls, local_path: Path, s3_key: str):
        """Tải tệp lên Cloud Object Storage nếu được cấu hình"""
        if not _s3_client or not S3_BUCKET_NAME or not local_path.exists():
            return
        try:
            _s3_client.upload_file(str(local_path), S3_BUCKET_NAME, s3_key)
        except Exception:
            pass

    @classmethod
    def _download_from_s3(cls, s3_key: str, local_path: Path) -> bool:
        """Tải tệp từ Cloud Object Storage về bộ nhớ cục bộ nếu bị thiếu sau restart"""
        if not _s3_client or not S3_BUCKET_NAME:
            return False
        try:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            _s3_client.download_file(S3_BUCKET_NAME, s3_key, str(local_path))
            return local_path.exists()
        except Exception:
            return False

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

        # Đồng bộ tệp gốc và meta lên cloud storage (nếu có cấu hình)
        cls._upload_to_s3(original_path, f"sessions/{session_id}/original.{extension}")
        cls._upload_to_s3(meta_path, f"sessions/{session_id}/meta.json")

        return session_data

    @classmethod
    def get_session(cls, session_id: str) -> Optional[Dict[str, Any]]:
        """Lấy thông tin phiên làm việc từ bộ nhớ cache, ổ đĩa hoặc phục hồi từ S3/R2"""
        if session_id in cls._sessions_cache:
            session = cls._sessions_cache[session_id]
            if time.time() > session.get("expires_at", 0):
                cls.delete_session(session_id)
                return None
            return session

        meta_path = SESSIONS_DIR / session_id / "meta.json"
        if not meta_path.exists() and _s3_client:
            # Phục hồi từ Cloud Storage sau khi container Render Free khởi động lại
            cls._download_from_s3(f"sessions/{session_id}/meta.json", meta_path)

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

        session_dir = SESSIONS_DIR / session_id
        meta_path = session_dir / "meta.json"
        try:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(session, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        # Đồng bộ tệp thành phẩm, preview và meta lên cloud storage
        ext = session.get("extension", "pdf")
        prot_path = session_dir / f"protected.{ext}"
        prev_path = session_dir / "preview.png"

        if prot_path.exists():
            cls._upload_to_s3(prot_path, f"sessions/{session_id}/protected.{ext}")
        if prev_path.exists():
            cls._upload_to_s3(prev_path, f"sessions/{session_id}/preview.png")
        if meta_path.exists():
            cls._upload_to_s3(meta_path, f"sessions/{session_id}/meta.json")

        return session

    @classmethod
    def get_download_target(cls, session_id: str) -> Optional[Tuple[str, str]]:
        """
        Lấy đường dẫn tệp ĐÃ BẢO VỆ (chứa watermark vĩnh viễn) để tải xuống công khai.
        Tự động phục hồi tệp từ Cloud Storage nếu container vừa được đánh thức trên Render Free.
        """
        session = cls.get_session(session_id)
        if not session or not session.get("is_processed"):
            return None

        ext = session.get("extension", "pdf")
        protected_path = Path(session.get("protected_path", SESSIONS_DIR / session_id / f"protected.{ext}"))

        if not protected_path.exists() and _s3_client:
            cls._download_from_s3(f"sessions/{session_id}/protected.{ext}", protected_path)

        if not protected_path.exists():
            return None

        return str(protected_path), session.get("protected_filename", "tailieu_dabao_ve.pdf")

    @classmethod
    def get_original_target(cls, session_id: str) -> Optional[Tuple[str, str]]:
        """
        Lấy đường dẫn tệp gốc (chưa đóng watermark) - DÀNH RIÊNG CHO QUẢN TRỊ VIÊN ĐÃ XÁC THỰC
        Tự động phục hồi từ Cloud Storage nếu cần thiết.
        """
        session = cls.get_session(session_id)
        if not session:
            return None

        ext = session.get("extension", "pdf")
        original_path = Path(session.get("original_path", SESSIONS_DIR / session_id / f"original.{ext}"))

        if not original_path.exists() and _s3_client:
            cls._download_from_s3(f"sessions/{session_id}/original.{ext}", original_path)

        if not original_path.exists():
            return None

        return str(original_path), session.get("original_filename", "original_file")

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
        """Xóa phiên làm việc khỏi cache, ổ đĩa và cloud storage"""
        cls._sessions_cache.pop(session_id, None)
        session_dir = SESSIONS_DIR / session_id
        if session_dir.exists():
            try:
                shutil.rmtree(session_dir, ignore_errors=True)
            except Exception:
                pass

        if _s3_client and S3_BUCKET_NAME:
            try:
                # Xóa các object thuộc session trên S3
                prefix = f"sessions/{session_id}/"
                res = _s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME, Prefix=prefix)
                for obj in res.get("Contents", []):
                    _s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=obj["Key"])
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
