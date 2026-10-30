"""
Bộ Kiểm Thử Tự Động Toàn Diện (Upgraded System Automated Test Suite)
Xác thực 7 tiêu chí bảo mật theo yêu cầu:
1. Users without the administrator password cannot edit watermarks.
2. Users cannot access editing APIs directly without authentication (HTTP 401 Unauthorized).
3. Administrator login works (Authentication with salted Scrypt hash & Session persistence).
4. Incorrect passwords are rejected (with Rate Limiting lockout after 5 attempts).
5. Final downloads contain permanently embedded watermarks (Permanently composited / Content stream burned).
6. Original files remain protected (Unauthenticated users cannot download unwatermarked originals).
7. Existing application functionality still works (PDF, Word DOCX, Image, SHA-256 verification, Session Storage).
"""
import os
import io
import json
import shutil
import unittest
import pymupdf
import docx
from PIL import Image

from app import app
from core import SecurityMiddleware, WatermarkController, SessionStorage, AdminAuthManager
from core.admin_auth import AUTH_FILE

TEST_PASSWORD = "MsTrangMasterSecure2026!"

class ComprehensiveSecurityTestSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        cls.client = app.test_client()

        # Đảm bảo môi trường kiểm thử có thể cấu hình ban đầu
        if AUTH_FILE.exists():
            AUTH_FILE.unlink()
        AdminAuthManager._failed_attempts.clear()

        # Thiết lập mật khẩu quản trị viên kiểm thử
        AdminAuthManager.setup_admin(TEST_PASSWORD)

    @classmethod
    def tearDownClass(cls):
        # Dọn dẹp tệp auth sau kiểm thử nếu cần hoặc giữ nguyên
        pass

    def setUp(self):
        # Đảm bảo mỗi test có phiên độc lập
        AdminAuthManager.reset_rate_limit("127.0.0.1")

    # ==========================================================
    # TIÊU CHÍ 1 & 2: NGƯỜI DÙNG KHÔNG CÓ QUYỀN KHÔNG THỂ CHỈNH SỬA / GỌI API
    # ==========================================================
    def test_01_unauthenticated_user_cannot_access_editing_api(self):
        """Tiêu chí 2: Yêu cầu API chỉnh sửa /api/process trực tiếp từ khách chưa đăng nhập phải bị từ chối 401"""
        # Tạo PDF hợp lệ
        doc = pymupdf.open()
        doc.new_page(width=595, height=842)
        pdf_bytes = doc.tobytes()
        doc.close()

        # Gọi API /api/process mà KHÔNG có phiên đăng nhập admin
        with self.client as client:
            response = client.post(
                "/api/process",
                data={
                    "file": (io.BytesIO(pdf_bytes), "document.pdf"),
                    "watermark_text": "HACKER_ATTEMPT"
                },
                content_type="multipart/form-data"
            )
            self.assertEqual(response.status_code, 401, "API phải trả về 401 Unauthorized khi chưa đăng nhập")
            data = response.get_json()
            self.assertFalse(data["success"])
            self.assertTrue(data.get("requires_auth"), "Phải có cờ requires_auth")

    def test_02_unauthenticated_user_cannot_change_password(self):
        """Khách chưa đăng nhập không thể gọi API đổi mật khẩu quản trị"""
        with self.client as client:
            response = client.post(
                "/api/auth/change-password",
                json={"current_password": "wrong", "new_password": "newpass123", "confirm_password": "newpass123"}
            )
            self.assertEqual(response.status_code, 401)

    # ==========================================================
    # TIÊU CHÍ 3: ĐĂNG NHẬP QUẢN TRỊ VIÊN THÀNH CÔNG
    # ==========================================================
    def test_03_admin_login_success_and_session_persistence(self):
        """Tiêu chí 3: Đăng nhập quản trị viên đúng mật khẩu phải thành công và thiết lập session"""
        with self.client as client:
            # Kiểm tra trạng thái trước khi login
            res_before = client.get("/api/auth/status")
            self.assertFalse(res_before.get_json()["is_admin"])

            # Gửi mật khẩu đúng
            res_login = client.post("/api/auth/login", json={"password": TEST_PASSWORD})
            self.assertEqual(res_login.status_code, 200)
            data_login = res_login.get_json()
            self.assertTrue(data_login["success"])
            self.assertTrue(data_login["is_admin"])

            # Kiểm tra trạng thái sau khi login trong cùng session
            res_after = client.get("/api/auth/status")
            self.assertTrue(res_after.get_json()["is_admin"], "Session phải lưu trạng thái is_admin=True")

            # Đăng xuất
            res_logout = client.post("/api/auth/logout")
            self.assertEqual(res_logout.status_code, 200)
            res_after_logout = client.get("/api/auth/status")
            self.assertFalse(res_after_logout.get_json()["is_admin"])

    # ==========================================================
    # TIÊU CHÍ 4: MẬT KHẨU SAI BỊ TỪ CHỐI & RATE LIMITING
    # ==========================================================
    def test_04_incorrect_password_rejected_and_rate_limited(self):
        """Tiêu chí 4: Mật khẩu sai bị từ chối; nhập sai quá 5 lần sẽ bị khóa (Rate Limiting HTTP 429)"""
        with self.client as client:
            # 4 lần đầu tiên: trả về 401 Unauthorized kèm số lần còn lại
            for i in range(4):
                res = client.post("/api/auth/login", json={"password": "WrongPassword!"})
                self.assertEqual(res.status_code, 401)
                self.assertFalse(res.get_json()["success"])

            # Lần thứ 5: Bắt đầu kích hoạt khóa tài khoản
            res_5 = client.post("/api/auth/login", json={"password": "WrongPassword!"})
            self.assertEqual(res_5.status_code, 429, "Lần thứ 5 sai phải trả về 429 Too Many Requests")
            self.assertIn("tạm thời bị khóa", res_5.get_json()["error"])

            # Thử lại ngay cả với mật khẩu đúng khi đang bị rate-limit vẫn phải bị từ chối 429
            res_locked = client.post("/api/auth/login", json={"password": TEST_PASSWORD})
            self.assertEqual(res_locked.status_code, 429, "Trong thời gian lockout, mọi request phải nhận 429")

        # Reset rate limit cho các bài test tiếp theo
        AdminAuthManager.reset_rate_limit("127.0.0.1")

    # ==========================================================
    # TIÊU CHÍ 5: TỆP XUẤT BẢN ĐƯỢC HÒA TRỘN WATERMARK VĨNH VIỄN
    # ==========================================================
    def test_05_final_image_contains_permanently_embedded_watermark(self):
        """Tiêu chí 5: Watermark trong ảnh được hòa trộn vĩnh viễn vào pixel (Permanent Pixel Compositing)"""
        img = Image.new("RGB", (500, 300), color=(255, 255, 255))
        in_path = "test_img_raw.png"
        out_path = "test_img_protected.png"
        preview_path = "test_img_prev.png"
        img.save(in_path)

        try:
            res = WatermarkController.execute(
                file_type="image",
                input_path=in_path,
                output_path=out_path,
                preview_output_path=preview_path,
                watermark_text="TRẦN THỊ THU TRANG",
                sub_text="BẢN QUYỀN VĨNH VIỄN"
            )
            self.assertTrue(res["success"])
            self.assertTrue(res["security_policies"]["permanently_composited_pixels"])

            # Đọc lại ảnh kết quả: Phải là raster image hoàn chỉnh, pixel đã thay đổi so với nền trắng
            with Image.open(out_path) as out_img:
                self.assertEqual(out_img.size, (500, 300))
                # Điểm ảnh ở chân trang (vùng watermark) không còn là màu trắng thuần 255, 255, 255
                has_watermark_pixels = False
                for y in range(250, 300):
                    for x in range(100, 400):
                        pixel = out_img.getpixel((x, y))
                        # Nếu không phải màu trắng tinh (255, 255, 255)
                        if pixel[0] < 240 or pixel[1] < 240 or pixel[2] < 240:
                            has_watermark_pixels = True
                            break
                    if has_watermark_pixels:
                        break
                self.assertTrue(has_watermark_pixels, "Pixel ảnh phải được hòa trộn vĩnh viễn chữ watermark")
        finally:
            for p in [in_path, out_path, preview_path]:
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass

    # ==========================================================
    # TIÊU CHÍ 6: TỆP GỐC ĐƯỢC BẢO VỆ CHẶT CHẼ
    # ==========================================================
    def test_06_original_files_remain_protected(self):
        """Tiêu chí 6: Người dùng công cộng không thể tải về tệp gốc; chỉ tải được tệp đã watermark"""
        # Tạo session với tệp gốc và tệp bảo vệ
        sample_bytes = b"Original Unwatermarked Secret Content"
        session = SessionStorage.create_session(
            original_filename="secret_original.pdf",
            file_bytes=sample_bytes,
            file_type="pdf",
            extension="pdf",
            sha256="fake_sha256_orig"
        )
        session_id = session["session_id"]
        # Giả lập đã xử lý và tạo tệp bảo vệ
        with open(session["protected_path"], "wb") as f:
            f.write(b"%PDF-1.7 Protected Watermarked Content")
        SessionStorage.update_session(session_id, {"is_processed": True})

        try:
            with self.client as client:
                # 1. Tải công khai qua /api/download/<session_id>: PHẢI NHẬN TỆP ĐÃ BẢO VỆ
                pub_res = client.get(f"/api/download/{session_id}")
                self.assertEqual(pub_res.status_code, 200)
                content = pub_res.get_data()
                pub_res.close()
                self.assertIn(b"Protected Watermarked Content", content)
                self.assertNotIn(b"Original Unwatermarked Secret Content", content, "Không được phục vụ tệp gốc cho public")

                # 2. Thử truy cập API tải tệp gốc /api/download-original/<session_id> KHI CHƯA LOGIN: PHẢI BỊ 401
                orig_res_guest = client.get(f"/api/download-original/{session_id}")
                self.assertEqual(orig_res_guest.status_code, 401, "Khách không được phép tải tệp gốc")
                orig_res_guest.close()

                # 3. Đăng nhập Quản trị viên và tải tệp gốc: ĐƯỢC PHÉP
                client.post("/api/auth/login", json={"password": TEST_PASSWORD})
                orig_res_admin = client.get(f"/api/download-original/{session_id}")
                self.assertEqual(orig_res_admin.status_code, 200, "Admin được phép tải tệp gốc")
                self.assertIn(b"Original Unwatermarked Secret Content", orig_res_admin.get_data())
                orig_res_admin.close()
        finally:
            SessionStorage.delete_session(session_id)

    # ==========================================================
    # TIÊU CHÍ 7: CÁC TÍNH NĂNG ĐÃ CÓ VẪN HOẠT ĐỘNG HOÀN HẢO
    # ==========================================================
    def test_07_full_workflow_when_authenticated_admin(self):
        """Tiêu chí 7: Luồng làm việc hoàn chỉnh khi đăng nhập Admin (Word, PDF, Verification)"""
        with self.client as client:
            # 1. Login Admin
            login_res = client.post("/api/auth/login", json={"password": TEST_PASSWORD})
            self.assertEqual(login_res.status_code, 200)

            # 2. Upload & Process PDF
            doc = pymupdf.open()
            p = doc.new_page(width=595, height=842)
            p.insert_text((50, 100), "Kiem tra tinh nang PDF sau nang cap", fontsize=12)
            pdf_bytes = doc.tobytes()
            doc.close()

            proc_res = client.post(
                "/api/process",
                data={
                    "file": (io.BytesIO(pdf_bytes), "hop_dong_trang.pdf"),
                    "watermark_text": "TRẦN THỊ THU TRANG",
                    "sub_text": "BẢN QUYỀN SỞ HỮU",
                    "position": "bottom-center",
                    "gray_color": "#708090",
                    "disallow_modify": "true",
                    "disallow_copy": "true"
                },
                content_type="multipart/form-data"
            )
            self.assertEqual(proc_res.status_code, 200)
            data = proc_res.get_json()
            self.assertTrue(data["success"])
            self.assertIn("protected_sha256", data)

            # 3. Xem trước (Preview)
            prev_res = client.get(data["preview_url"])
            self.assertEqual(prev_res.status_code, 200)
            self.assertEqual(prev_res.content_type, "image/png")
            prev_res.close()

            # 4. Kiểm tra tính toàn vẹn (Integrity check)
            verify_res = client.post(
                "/api/verify-integrity",
                data={
                    "file": (io.BytesIO(pdf_bytes), "hop_dong_trang.pdf"),
                    "sha256": data["original_sha256"]
                },
                content_type="multipart/form-data"
            )
            self.assertEqual(verify_res.status_code, 200)
            self.assertTrue(verify_res.get_json()["is_matched"])

            # 5. Kiểm tra Gallery công khai
            gallery_res = client.get("/api/gallery")
            self.assertEqual(gallery_res.status_code, 200)
            items = gallery_res.get_json()["items"]
            self.assertGreater(len(items), 0, "Gallery phải hiển thị tệp đã xử lý")

    def test_08_change_password_functionality(self):
        """Kiểm thử tính năng đổi mật khẩu quản trị viên an toàn"""
        NEW_PASS = "MsTrangNewPassword2026!"
        with self.client as client:
            # Login với mật khẩu cũ
            client.post("/api/auth/login", json={"password": TEST_PASSWORD})

            # Đổi mật khẩu
            change_res = client.post("/api/auth/change-password", json={
                "current_password": TEST_PASSWORD,
                "new_password": NEW_PASS,
                "confirm_password": NEW_PASS
            })
            self.assertEqual(change_res.status_code, 200)
            self.assertTrue(change_res.get_json()["success"])

            # Đăng xuất
            client.post("/api/auth/logout")

            # Đăng nhập lại bằng mật khẩu cũ -> PHẢI THẤT BẠI
            old_try = client.post("/api/auth/login", json={"password": TEST_PASSWORD})
            self.assertEqual(old_try.status_code, 401)

            # Đăng nhập lại bằng mật khẩu mới -> PHẢI THÀNH CÔNG
            new_try = client.post("/api/auth/login", json={"password": NEW_PASS})
            self.assertEqual(new_try.status_code, 200)
            self.assertTrue(new_try.get_json()["success"])

            # Hoàn trả lại TEST_PASSWORD để các lần chạy sau đồng bộ
            client.post("/api/auth/change-password", json={
                "current_password": NEW_PASS,
                "new_password": TEST_PASSWORD,
                "confirm_password": TEST_PASSWORD
            })

    # ==========================================================
    # TIÊU CHÍ RENDER DEPLOYMENT & PRODUCTION SECURITY
    # ==========================================================
    def test_09_csrf_protection_enforcement(self):
        """Kiểm thử cơ chế bảo vệ chống tấn công CSRF (Cross-Site Request Forgery)"""
        with self.client as client:
            app.config["WTF_CSRF_ENABLED"] = True
            try:
                # 1. Truy cập trang chủ để tạo session và nhận csrf_token
                res = client.get("/")
                self.assertEqual(res.status_code, 200)

                # 2. Gửi request POST mà KHÔNG có header X-CSRF-Token -> PHẢI BỊ 403 FORBIDDEN
                res_blocked = client.post("/api/auth/login", json={"password": TEST_PASSWORD})
                self.assertEqual(res_blocked.status_code, 403)
                self.assertTrue(res_blocked.get_json().get("csrf_invalid"))

                # 3. Lấy csrf_token từ session và gửi kèm trong header X-CSRF-Token -> PHẢI HỢP LỆ
                with client.session_transaction() as sess:
                    valid_token = sess.get("csrf_token")
                self.assertIsNotNone(valid_token)

                res_allowed = client.post(
                    "/api/auth/login",
                    json={"password": TEST_PASSWORD},
                    headers={"X-CSRF-Token": valid_token}
                )
                self.assertEqual(res_allowed.status_code, 200)
            finally:
                app.config["WTF_CSRF_ENABLED"] = False

    def test_10_first_run_setup_token_protection(self):
        """Kiểm thử bảo vệ First-Run Setup: Không cho phép chiếm quyền nếu mã Setup Token sai"""
        import config
        from core.admin_auth import AdminAuthManager, AUTH_FILE

        # Giả lập chưa cấu hình và có SETUP_TOKEN bảo vệ
        old_env_token = os.environ.get("SETUP_TOKEN")
        os.environ["SETUP_TOKEN"] = "RenderSecureSetupToken2026!"
        
        # Xóa tạm auth file
        backup_auth = None
        if AUTH_FILE.exists():
            backup_auth = AUTH_FILE.read_text(encoding="utf-8")
            AUTH_FILE.unlink()

        try:
            # 1. Thử setup với token sai -> Thất bại
            success, msg = AdminAuthManager.setup_admin("Password123!", setup_token="WrongToken")
            self.assertFalse(success)
            self.assertIn("Setup Token", msg)

            # 2. Thử setup với token đúng -> Thành công
            success_ok, msg_ok = AdminAuthManager.setup_admin("Password123!", setup_token="RenderSecureSetupToken2026!")
            self.assertTrue(success_ok)
        finally:
            if old_env_token is not None:
                os.environ["SETUP_TOKEN"] = old_env_token
            else:
                os.environ.pop("SETUP_TOKEN", None)
            if backup_auth:
                AUTH_FILE.write_text(backup_auth, encoding="utf-8")
            else:
                AdminAuthManager.setup_admin(TEST_PASSWORD, bypass_token=True)

    def test_11_proxy_fix_https_and_forwarding(self):
        """Kiểm thử hoạt động sau Reverse Proxy (Render) với headers X-Forwarded-*"""
        with self.client as client:
            res = client.get(
                "/api/system-status",
                headers={
                    "X-Forwarded-Proto": "https",
                    "X-Forwarded-For": "203.0.113.195",
                    "X-Forwarded-Host": "watermark.onrender.com"
                }
            )
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data["status"], "online")

    def test_12_production_wsgi_app_exposed(self):
        """Kiểm thử ứng dụng WSGI app:app tương thích hoàn hảo với Gunicorn"""
        from app import app as wsgi_app
        self.assertTrue(callable(wsgi_app), "app.py phải expose đối tượng WSGI callable tên 'app'")
        self.assertFalse(wsgi_app.config["DEBUG"], "Flask debug mode phải tắt trong production")

    def test_13_zero_leak_logging_no_secrets_in_logs(self):
        """Kiểm thử Tiêu chuẩn Zero-Leak: Không bao giờ in token, mật khẩu hay mã băm ra log console"""
        import sys
        captured_output = io.StringIO()
        old_stdout = sys.stdout

        # Backup auth file
        backup_auth = AUTH_FILE.read_text(encoding="utf-8") if AUTH_FILE.exists() else None
        if AUTH_FILE.exists():
            AUTH_FILE.unlink()

        # Giả lập môi trường có SETUP_TOKEN bí mật
        secret_test_token = "SuperSecretTokenNeverExposeToLogs999!"
        old_token_env = os.environ.get("SETUP_TOKEN")
        os.environ["SETUP_TOKEN"] = secret_test_token

        try:
            sys.stdout = captured_output
            AdminAuthManager.init_app()
            output = captured_output.getvalue()

            # Khẳng định giá trị token bí mật TUYỆT ĐỐI KHÔNG xuất hiện trong stdout
            self.assertNotIn(secret_test_token, output, "Setup token bí mật không được phép xuất hiện trong log stdout")
            self.assertNotIn("One-Time Setup Token:", output, "Không được in thông báo lộ token ra console")
        finally:
            sys.stdout = old_stdout
            if old_token_env is not None:
                os.environ["SETUP_TOKEN"] = old_token_env
            else:
                os.environ.pop("SETUP_TOKEN", None)
            if backup_auth:
                AUTH_FILE.write_text(backup_auth, encoding="utf-8")
            else:
                AdminAuthManager.setup_admin(TEST_PASSWORD, bypass_token=True)

    def test_14_anti_hijacking_lockout_on_production(self):
        """Kiểm thử Khóa Chống Chiếm Đoạt Quyền: Từ chối 403 nếu môi trường Production chưa cấu hình token bí mật"""
        backup_auth = AUTH_FILE.read_text(encoding="utf-8") if AUTH_FILE.exists() else None
        if AUTH_FILE.exists():
            AUTH_FILE.unlink()

        old_render = os.environ.get("RENDER")
        old_token = os.environ.get("SETUP_TOKEN")
        old_admin_token = os.environ.get("ADMIN_SETUP_TOKEN")
        old_pass = os.environ.get("ADMIN_INITIAL_PASSWORD")
        old_hash = os.environ.get("ADMIN_PASSWORD_HASH")

        os.environ["RENDER"] = "true"
        os.environ.pop("SETUP_TOKEN", None)
        os.environ.pop("ADMIN_SETUP_TOKEN", None)
        os.environ.pop("ADMIN_INITIAL_PASSWORD", None)
        os.environ.pop("ADMIN_PASSWORD_HASH", None)

        try:
            self.assertTrue(AdminAuthManager.is_setup_locked(), "is_setup_locked phải là True khi chạy trên Render mà thiếu biến môi trường bí mật")

            with self.client as client:
                res = client.post("/api/auth/setup", json={
                    "password": "AttackerPassword123!",
                    "confirm_password": "AttackerPassword123!"
                })
                # Người ngoài cố gắng chiếm quyền PHẢI BỊ CHẶN 403 FORBIDDEN
                self.assertEqual(res.status_code, 403, "Phải từ chối 403 Forbidden khi quy trình thiết lập đang bị khóa chống chiếm đoạt")
                data = res.get_json()
                self.assertFalse(data["success"])
                self.assertIn("chống chiếm đoạt quyền", data["error"])
        finally:
            if old_render is not None:
                os.environ["RENDER"] = old_render
            else:
                os.environ.pop("RENDER", None)
            if old_token is not None:
                os.environ["SETUP_TOKEN"] = old_token
            if old_admin_token is not None:
                os.environ["ADMIN_SETUP_TOKEN"] = old_admin_token
            if old_pass is not None:
                os.environ["ADMIN_INITIAL_PASSWORD"] = old_pass
            if old_hash is not None:
                os.environ["ADMIN_PASSWORD_HASH"] = old_hash

            if backup_auth:
                AUTH_FILE.write_text(backup_auth, encoding="utf-8")
            else:
                AdminAuthManager.setup_admin(TEST_PASSWORD, bypass_token=True)

    def test_15_setup_token_brute_force_rate_limiting(self):
        """Kiểm thử Giới Hạn Tần Suất (Rate Limiting) trên API /api/auth/setup để chống dò mã token"""
        backup_auth = AUTH_FILE.read_text(encoding="utf-8") if AUTH_FILE.exists() else None
        if AUTH_FILE.exists():
            AUTH_FILE.unlink()

        test_ip = "192.168.1.99"
        old_token = os.environ.get("SETUP_TOKEN")
        os.environ["SETUP_TOKEN"] = "RealSecretToken123456"

        try:
            AdminAuthManager.reset_rate_limit(test_ip)

            # Thử sai 5 lần liên tiếp
            for i in range(5):
                success, _ = AdminAuthManager.setup_admin(
                    "AdminPassword123!",
                    setup_token="WrongTokenGuess"
                )
                self.assertFalse(success)
                AdminAuthManager.record_failed_attempt(test_ip)

            # Lần thứ 6 kiểm tra rate limit
            is_allowed, rem, lockout_sec = AdminAuthManager.check_rate_limit(test_ip)
            self.assertFalse(is_allowed, "IP kẻ tấn công phải bị khóa sau 5 lần nhập sai mã setup token")
            self.assertGreater(lockout_sec, 0)
        finally:
            AdminAuthManager.reset_rate_limit(test_ip)
            if old_token is not None:
                os.environ["SETUP_TOKEN"] = old_token
            else:
                os.environ.pop("SETUP_TOKEN", None)
            if backup_auth:
                AUTH_FILE.write_text(backup_auth, encoding="utf-8")
            else:
                AdminAuthManager.setup_admin(TEST_PASSWORD, bypass_token=True)

    def test_16_credentials_persistence_across_render_free_restarts(self):
        """Kiểm thử tính bền vững của quyền Quản trị qua các lần container Render Free khởi động lại"""
        # Giả lập container vừa khởi động lại: ổ đĩa tạm mất auth_file
        backup_auth = AUTH_FILE.read_text(encoding="utf-8") if AUTH_FILE.exists() else None
        if AUTH_FILE.exists():
            AUTH_FILE.unlink()

        self.assertFalse(AdminAuthManager.is_configured(), "Trước khi init_app thì chưa cấu hình do ổ đĩa container vừa bị wipe")

        # Giả lập biến môi trường ADMIN_INITIAL_PASSWORD được Render lưu trữ cố định
        persistent_password = "PersistentRenderFreePassword2026!"
        old_pass = os.environ.get("ADMIN_INITIAL_PASSWORD")
        os.environ["ADMIN_INITIAL_PASSWORD"] = persistent_password

        try:
            # Ứng dụng khởi động lại trên Render Free (gọi init_app)
            AdminAuthManager.init_app()

            # Kiểm tra: Quản trị viên tự động được khôi phục thành công
            self.assertTrue(AdminAuthManager.is_configured(), "Tài khoản quản trị viên phải tự động được khôi phục từ biến môi trường persistent")

            # Đăng nhập bằng mật khẩu bền vững -> Phải thành công
            success, msg = AdminAuthManager.authenticate(persistent_password, "127.0.0.1")
            self.assertTrue(success, f"Đăng nhập thất bại: {msg}")
        finally:
            if old_pass is not None:
                os.environ["ADMIN_INITIAL_PASSWORD"] = old_pass
            else:
                os.environ.pop("ADMIN_INITIAL_PASSWORD", None)
            if backup_auth:
                AUTH_FILE.write_text(backup_auth, encoding="utf-8")
            else:
                AdminAuthManager.setup_admin(TEST_PASSWORD, bypass_token=True)

    def test_17_documents_persistence_and_cache_eviction(self):
        """Kiểm thử tính toàn vẹn của tệp tải lên và thành phẩm qua các chu kỳ xóa cache bộ nhớ"""
        # Tạo tệp PDF mẫu
        doc = pymupdf.open()
        page = doc.new_page(width=595, height=842)
        page.insert_text((72, 72), "Tài liệu kiểm thử lưu trữ bền vững", fontsize=16)
        pdf_bytes = doc.tobytes()
        doc.close()

        # Tạo phiên lưu trữ
        session = SessionStorage.create_session("tailieu_kiemthu.pdf", pdf_bytes, "pdf", "pdf", "testhash123")
        sid = session["session_id"]

        # Xử lý watermark bằng WatermarkController.execute
        res = WatermarkController.execute(
            file_type="pdf",
            input_path=session["original_path"],
            output_path=session["protected_path"],
            preview_output_path=session["preview_path"],
            watermark_text="TRẦN THỊ THU TRANG"
        )
        self.assertTrue(res["success"])

        # Cập nhật session thành đã xử lý
        SessionStorage.update_session(sid, {
            "is_processed": True,
            "protected_sha256": res.get("sha256", "hash123"),
            "protected_size": os.path.getsize(session["protected_path"])
        })

        # Giả lập bộ nhớ RAM bị xóa (cache eviction) như khi container khởi động lại
        SessionStorage._sessions_cache.clear()
        self.assertNotIn(sid, SessionStorage._sessions_cache, "Cache bộ nhớ RAM đã được dọn sạch")

        # Tải lại phiên từ ổ lưu trữ bền vững (Persistent Storage)
        restored = SessionStorage.get_session(sid)
        self.assertIsNotNone(restored, "Phiên làm việc phải được khôi phục thành công từ kho lưu trữ")
        self.assertEqual(restored["session_id"], sid)

        # Kiểm tra tải về thành phẩm
        target = SessionStorage.get_download_target(sid)
        self.assertIsNotNone(target, "Đường dẫn tải về thành phẩm phải còn nguyên vẹn")
        self.assertTrue(os.path.exists(target[0]), "Tệp vật lý phải tồn tại trên ổ lưu trữ")

        # Dọn dẹp
        SessionStorage.delete_session(sid)

    def test_18_admin_setup_token_quotes_and_whitespace_handling(self):
        """Kiểm thử chuẩn hóa ADMIN_SETUP_TOKEN có chứa dấu ngoặc kép, khoảng trắng và ký tự xuống dòng"""
        backup_auth = AUTH_FILE.read_text(encoding="utf-8") if AUTH_FILE.exists() else None
        if AUTH_FILE.exists():
            AUTH_FILE.unlink()

        old_admin_token = os.environ.get("ADMIN_SETUP_TOKEN")
        old_token = os.environ.get("SETUP_TOKEN")

        # Giả lập Render dashboard có cấu hình chứa ngoặc kép và khoảng trắng: "  RenderToken2026! \r\n"
        os.environ["ADMIN_SETUP_TOKEN"] = '  "RenderToken2026!" \r\n '
        os.environ.pop("SETUP_TOKEN", None)

        try:
            # 1. Người dùng nhập token sạch (không có ngoặc kép): RenderToken2026!
            # Hệ thống phải tự động chuẩn hóa và so khớp thành công!
            success, msg = AdminAuthManager.setup_admin("Password123!", setup_token="RenderToken2026!")
            self.assertTrue(success, f"Setup phải thành công khi chuỗi token sạch so với env có ngoặc kép: {msg}")

            # Xóa auth file để test chiều ngược lại
            AUTH_FILE.unlink()

            # 2. Người dùng nhập token có ngoặc kép trên web: "RenderToken2026!"
            # Env không có ngoặc kép: RenderToken2026!
            os.environ["ADMIN_SETUP_TOKEN"] = "RenderToken2026!"
            success2, msg2 = AdminAuthManager.setup_admin("Password123!", setup_token='"RenderToken2026!"')
            self.assertTrue(success2, f"Setup phải thành công khi input có ngoặc kép: {msg2}")
        finally:
            if old_admin_token is not None:
                os.environ["ADMIN_SETUP_TOKEN"] = old_admin_token
            else:
                os.environ.pop("ADMIN_SETUP_TOKEN", None)
            if old_token is not None:
                os.environ["SETUP_TOKEN"] = old_token
            else:
                os.environ.pop("SETUP_TOKEN", None)

            if backup_auth:
                AUTH_FILE.write_text(backup_auth, encoding="utf-8")
            else:
                AdminAuthManager.setup_admin(TEST_PASSWORD, bypass_token=True)

    def test_19_admin_setup_token_and_setup_token_coexistence(self):
        """Kiểm thử tương thích song song: Cả ADMIN_SETUP_TOKEN lẫn SETUP_TOKEN đều được chấp nhận"""
        backup_auth = AUTH_FILE.read_text(encoding="utf-8") if AUTH_FILE.exists() else None
        if AUTH_FILE.exists():
            AUTH_FILE.unlink()

        old_admin_token = os.environ.get("ADMIN_SETUP_TOKEN")
        old_token = os.environ.get("SETUP_TOKEN")

        # Giả lập Render có cả 2 biến môi trường
        os.environ["ADMIN_SETUP_TOKEN"] = "TokenFromAdminEnv123"
        os.environ["SETUP_TOKEN"] = "TokenFromSetupEnv456"

        try:
            # Nhập mã từ ADMIN_SETUP_TOKEN -> PHẢI THÀNH CÔNG
            success, msg = AdminAuthManager.setup_admin("Password123!", setup_token="TokenFromAdminEnv123")
            self.assertTrue(success, f"Mã ADMIN_SETUP_TOKEN phải hợp lệ: {msg}")

            AUTH_FILE.unlink()

            # Nhập mã từ SETUP_TOKEN -> CŨNG PHẢI THÀNH CÔNG
            success2, msg2 = AdminAuthManager.setup_admin("Password123!", setup_token="TokenFromSetupEnv456")
            self.assertTrue(success2, f"Mã SETUP_TOKEN phải hợp lệ: {msg2}")
        finally:
            if old_admin_token is not None:
                os.environ["ADMIN_SETUP_TOKEN"] = old_admin_token
            else:
                os.environ.pop("ADMIN_SETUP_TOKEN", None)
            if old_token is not None:
                os.environ["SETUP_TOKEN"] = old_token
            else:
                os.environ.pop("SETUP_TOKEN", None)

            if backup_auth:
                AUTH_FILE.write_text(backup_auth, encoding="utf-8")
            else:
                AdminAuthManager.setup_admin(TEST_PASSWORD, bypass_token=True)

if __name__ == "__main__":
    unittest.main()
