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

if __name__ == "__main__":
    unittest.main()
