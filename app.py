"""
Ứng dụng Máy chủ Flask - Hệ thống Đóng Watermark & Khóa Tệp Chống Chỉnh Sửa
Nâng cấp: Hệ thống Xác thực Quản trị viên & Phân quyền Truy cập Chỉ Đọc
Dành riêng cho Ms. Trần Thị Thu Trang

Kiến trúc 4 khối liên kết:
1. client-upload       (Giao diện Tải lên & Xem trước, Chế độ Read-Only cho khách / Edit cho Admin)
2. middleware-security (Bộ lọc Bảo mật, Xác thực Quản trị viên, Rate Limiting & Kiểm tra Magic Bytes)
3. controller-watermark(Trình xử lý Watermark permanently composited & Khóa File)
4. database-storage    (Kho Lưu trữ Tạm thời / Session Storage)
"""
import os
import sys
import time
import secrets
from werkzeug.middleware.proxy_fix import ProxyFix

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from flask import Flask, request, jsonify, render_template, send_file, abort, session
from config import (
    SECRET_KEY, HOST, PORT, MAX_CONTENT_LENGTH,
    DEFAULT_WATERMARK_TEXT, DEFAULT_SUB_TEXT, DEFAULT_GRAY_COLOR_HEX,
    IS_PRODUCTION
)
from core import SecurityMiddleware, WatermarkController, SessionStorage, AdminAuthManager, admin_required

app = Flask(__name__)

# Hỗ trợ HTTPS và Reverse Proxy chuẩn công nghiệp (Render, Nginx, Cloudflare)
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

app.config["DEBUG"] = False
app.config["SECRET_KEY"] = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 7200  # 2 giờ

# Kích hoạt Secure Cookie khi chạy trên môi trường đám mây có HTTPS
if IS_PRODUCTION:
    app.config["SESSION_COOKIE_SECURE"] = (
        os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"
    )
else:
    app.config["SESSION_COOKIE_SECURE"] = False

# Khởi tạo quyền quản trị và cơ chế bảo vệ First-Run
AdminAuthManager.init_app()

def get_client_ip() -> str:
    """Lấy địa chỉ IP thực tế của máy khách (đã qua ProxyFix an toàn)"""
    return request.remote_addr or "127.0.0.1"

# ==========================================================
# CƠ CHẾ BẢO VỆ CSRF (Cross-Site Request Forgery Protection)
# ==========================================================
@app.before_request
def csrf_protect():
    """Bảo vệ chống tấn công CSRF cho tất cả các yêu cầu thay đổi trạng thái"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
        # Bỏ qua kiểm tra CSRF trong bộ test suite tự động nếu tắt
        if app.config.get("TESTING") and not app.config.get("WTF_CSRF_ENABLED", True):
            return

        header_token = request.headers.get("X-CSRF-Token")
        form_token = request.form.get("csrf_token") if request.form else None
        expected_token = session.get("csrf_token")

        if not expected_token or (header_token != expected_token and form_token != expected_token):
            return jsonify({
                "success": False,
                "error": "Yêu cầu bảo mật thất bại (CSRF token không hợp lệ hoặc đã hết hạn). Vui lòng làm mới trang.",
                "csrf_invalid": True
            }), 403

@app.context_processor
def inject_csrf_token():
    """Tự động cung cấp csrf_token cho giao diện HTML"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return dict(csrf_token=session["csrf_token"])

@app.errorhandler(413)
def request_entity_too_large(error):
    """Xử lý lỗi vượt quá dung lượng cho phép"""
    return jsonify({
        "success": False,
        "node": "middleware-security",
        "error": f"Dung lượng tệp tải lên vượt quá giới hạn an toàn ({MAX_CONTENT_LENGTH // (1024*1024)}MB)."
    }), 413

# ==========================================================
# 1. GIAO DIỆN CHÍNH (client-upload)
# ==========================================================
@app.route("/")
def index():
    """Giao diện chính: Tự động thích ứng chế độ Khách (Read-Only) hoặc Quản trị viên (Full Edit)"""
    is_admin = session.get("is_admin", False)
    is_configured = AdminAuthManager.is_configured()
    return render_template("index.html", is_admin=is_admin, is_configured=is_configured)

# ==========================================================
# 2. XÁC THỰC QUẢN TRỊ VIÊN (Admin Authentication API)
# ==========================================================
@app.route("/api/auth/status")
def auth_status():
    """Trả về trạng thái cấu hình và phiên đăng nhập hiện tại"""
    return jsonify({
        "success": True,
        "is_configured": AdminAuthManager.is_configured(),
        "is_admin": session.get("is_admin", False),
        "setup_token_required": AdminAuthManager.is_setup_token_required()
    })

@app.route("/api/auth/setup", methods=["POST"])
def auth_setup():
    """Thiết lập mật khẩu quản trị viên ban đầu qua quy trình an toàn có bảo vệ token"""
    if AdminAuthManager.is_configured():
        return jsonify({
            "success": False,
            "error": "Quản trị viên đã được thiết lập. Vui lòng đăng nhập bằng mật khẩu hiện tại."
        }), 400

    data = request.get_json(silent=True) or request.form
    password = data.get("password", "").strip()
    confirm = data.get("confirm_password", "").strip()
    setup_token = data.get("setup_token", "").strip() or None

    if not password or len(password) < 6:
        return jsonify({"success": False, "error": "Mật khẩu quản trị viên phải có ít nhất 6 ký tự."}), 400

    if password != confirm:
        return jsonify({"success": False, "error": "Mật khẩu xác nhận không khớp."}), 400

    success, message = AdminAuthManager.setup_admin(password, setup_token=setup_token)
    if success:
        session["is_admin"] = True
        session["admin_logged_in_at"] = time.time()
        session.permanent = True
        return jsonify({"success": True, "message": message, "is_admin": True})

    return jsonify({"success": False, "error": message}), 400

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """Đăng nhập quản trị viên với Rate Limiting chống Brute-force"""
    ip = get_client_ip()
    data = request.get_json(silent=True) or request.form
    password = data.get("password", "")

    if not password:
        return jsonify({"success": False, "error": "Vui lòng nhập mật khẩu quản trị viên."}), 400

    is_allowed, rem, lockout_sec = AdminAuthManager.check_rate_limit(ip)
    if not is_allowed:
        mins = (lockout_sec + 59) // 60
        return jsonify({
            "success": False,
            "error": f"Tài khoản bị tạm khóa do nhập sai quá nhiều lần. Vui lòng thử lại sau {mins} phút.",
            "rate_limited": True
        }), 429

    success, message = AdminAuthManager.authenticate(password, ip)
    if success:
        session["is_admin"] = True
        session["admin_ip"] = ip
        session["admin_logged_in_at"] = time.time()
        session.permanent = True
        return jsonify({"success": True, "message": message, "is_admin": True})

    status_code = 429 if "tạm thời bị khóa" in message else 401
    return jsonify({"success": False, "error": message}), status_code

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    """Đăng xuất khỏi phiên quản trị viên"""
    session.pop("is_admin", None)
    session.pop("admin_ip", None)
    session.pop("admin_logged_in_at", None)
    return jsonify({"success": True, "message": "Đã đăng xuất thành công."})

@app.route("/api/auth/change-password", methods=["POST"])
@admin_required
def auth_change_password():
    """Đổi mật khẩu quản trị viên (yêu cầu quyền quản trị và xác thực mật khẩu cũ)"""
    data = request.get_json(silent=True) or request.form
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")

    if not current_password or not new_password:
        return jsonify({"success": False, "error": "Vui lòng điền đầy đủ thông tin mật khẩu."}), 400

    if new_password != confirm_password:
        return jsonify({"success": False, "error": "Mật khẩu xác nhận không khớp."}), 400

    success, message = AdminAuthManager.change_password(current_password, new_password)
    if success:
        return jsonify({"success": True, "message": message})
    return jsonify({"success": False, "error": message}), 400

# ==========================================================
# 3. TIẾP NHẬN XỬ LÝ WATERMARK (Chỉ dành cho Quản trị viên)
# ==========================================================
@app.route("/api/process", methods=["POST"])
@admin_required
def process_file():
    """
    Điểm tiếp nhận luồng chỉnh sửa & đóng watermark:
    YÊU CẦU QUYỀN QUẢN TRỊ VIÊN ĐÃ XÁC THỰC!
    Người dùng không đăng nhập không thể gọi API này.
    """
    try:
        # Dọn dẹp các phiên làm việc hết hạn trước khi xử lý phiên mới
        SessionStorage.cleanup_expired_sessions()

        if "file" not in request.files:
            return jsonify({
                "success": False,
                "node": "middleware-security",
                "error": "Không tìm thấy tệp đính kèm trong yêu cầu."
            }), 400

        uploaded_file = request.files["file"]
        if not uploaded_file.filename:
            return jsonify({
                "success": False,
                "node": "middleware-security",
                "error": "Chưa chọn tệp để xử lý."
            }), 400

        # Lấy thông số cấu hình từ giao diện người dùng
        watermark_text = request.form.get("watermark_text", DEFAULT_WATERMARK_TEXT).strip()
        if not watermark_text:
            watermark_text = DEFAULT_WATERMARK_TEXT

        sub_text = request.form.get("sub_text", DEFAULT_SUB_TEXT).strip()
        position = request.form.get("position", "bottom-center")
        gray_color = request.form.get("gray_color", DEFAULT_GRAY_COLOR_HEX)
        password = request.form.get("password", "").strip() or None

        # Tùy chọn kích thước chữ
        font_size_str = request.form.get("font_size", "")
        font_size = float(font_size_str) if font_size_str and font_size_str.replace(".", "", 1).isdigit() else None

        # Tùy chọn chính sách bảo mật
        disallow_copy = request.form.get("disallow_copy", "true").lower() == "true"
        disallow_modify = request.form.get("disallow_modify", "true").lower() == "true"
        disallow_print = request.form.get("disallow_print", "false").lower() == "true"
        require_password_to_open = request.form.get("require_password_to_open", "false").lower() == "true"

        # Đọc dữ liệu nhị phân của tệp
        file_bytes = uploaded_file.read()

        # [NODE 2: middleware-security] Kiểm tra định dạng Magic Bytes & tính nguyên vẹn
        sec_result = SecurityMiddleware.inspect_file(uploaded_file.filename, file_bytes)
        if not sec_result.is_valid:
            return jsonify({
                "success": False,
                "node": "middleware-security",
                "error": sec_result.error_message
            }), 400

        # [NODE 4: database-storage] Khởi tạo phiên làm việc tạm thời
        session_data = SessionStorage.create_session(
            original_filename=sec_result.sanitized_filename,
            file_bytes=file_bytes,
            file_type=sec_result.file_type,
            extension=sec_result.extension,
            sha256=sec_result.sha256
        )
        session_id = session_data["session_id"]

        # [NODE 3: controller-watermark] Đóng Watermark & Áp dụng Khóa
        process_result = WatermarkController.execute(
            file_type=sec_result.file_type,
            input_path=session_data["original_path"],
            output_path=session_data["protected_path"],
            preview_output_path=session_data["preview_path"],
            watermark_text=watermark_text,
            sub_text=sub_text,
            position=position,
            gray_color_hex=gray_color,
            font_size=font_size,
            password=password,
            disallow_copy=disallow_copy,
            disallow_modify=disallow_modify,
            disallow_print=disallow_print,
            require_password_to_open=require_password_to_open
        )

        # Cập nhật kết quả vào phiên làm việc
        SessionStorage.update_session(session_id, {
            "is_processed": True,
            "protected_sha256": process_result.get("protected_sha256"),
            "protected_size": process_result.get("file_size"),
            "protection_details": process_result.get("security_policies")
        })

        # [NODE 1: client-upload] Phản hồi kết quả để xem trước và tải xuống
        return jsonify({
            "success": True,
            "session_id": session_id,
            "original_filename": sec_result.sanitized_filename,
            "protected_filename": session_data["protected_filename"],
            "file_type": sec_result.file_type,
            "original_sha256": sec_result.sha256,
            "original_size": sec_result.file_size,
            "protected_sha256": process_result.get("protected_sha256"),
            "protected_size": process_result.get("file_size"),
            "security_policies": process_result.get("security_policies"),
            "owner_protected": process_result.get("owner_protected", False),
            "preview_url": f"/api/preview/{session_id}",
            "download_url": f"/api/download/{session_id}"
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "node": "controller-watermark",
            "error": f"Lỗi trong quá trình xử lý: {str(e)}"
        }), 500

# ==========================================================
# 4. TRUY XUẤT XEM TRƯỚC & TẢI VỀ CÔNG KHAI (Read-Only)
# ==========================================================
@app.route("/api/preview/<session_id>")
def get_preview(session_id: str):
    """Cung cấp ảnh xem trước tệp ĐÃ ĐÓNG WATERMARK cho mọi người dùng (kể cả khách)"""
    session_data = SessionStorage.get_session(session_id)
    if not session_data or not session_data.get("is_processed"):
        abort(404, description="Không tìm thấy phiên làm việc hoặc chưa hoàn tất xử lý.")

    preview_path = session_data.get("preview_path")
    if not preview_path or not os.path.exists(preview_path):
        abort(404, description="Ảnh xem trước chưa sẵn sàng.")

    return send_file(preview_path, mimetype="image/png")

@app.route("/api/download/<session_id>")
def download_protected_file(session_id: str):
    """
    Cung cấp tải xuống tệp ĐÃ ĐƯỢC ĐÓNG WATERMARK VĨNH VIỄN.
    Cho phép người dùng công cộng tải về bản thành phẩm có watermark.
    """
    target = SessionStorage.get_download_target(session_id)
    if not target:
        abort(404, description="Tệp bảo vệ không tồn tại hoặc phiên làm việc đã hết hạn.")

    file_path, download_name = target
    return send_file(
        file_path,
        as_attachment=True,
        download_name=download_name
    )

@app.route("/api/download-original/<session_id>")
@admin_required
def download_original_file(session_id: str):
    """
    Tải về tệp gốc CHƯA ĐÓNG WATERMARK.
    NGHIÊM CẤM NGƯỜI DÙNG CÔNG CỘNG: CHỈ DÀNH RIÊNG CHO QUẢN TRỊ VIÊN ĐÃ XÁC THỰC!
    """
    target = SessionStorage.get_original_target(session_id)
    if not target:
        abort(404, description="Tệp gốc không tồn tại hoặc đã hết hạn.")

    file_path, download_name = target
    return send_file(
        file_path,
        as_attachment=True,
        download_name=f"[ORIGINAL]_{download_name}"
    )

@app.route("/api/gallery")
def get_gallery():
    """Cung cấp danh sách các tệp đã hoàn tất đóng watermark cho người dùng xem và tải về"""
    items = SessionStorage.get_public_gallery()
    return jsonify({"success": True, "items": items})

@app.route("/api/verify-integrity", methods=["POST"])
def verify_integrity():
    """Kiểm tra và đối chiếu tính nguyên vẹn của một tệp bất kỳ qua mã băm SHA-256"""
    if "file" not in request.files:
        return jsonify({"success": False, "error": "Chưa chọn tệp kiểm tra."}), 400

    uploaded = request.files["file"]
    expected_hash = request.form.get("sha256", "").strip().lower()

    file_bytes = uploaded.read()
    import hashlib
    actual_hash = hashlib.sha256(file_bytes).hexdigest().lower()

    is_matched = (actual_hash == expected_hash) if expected_hash else None

    return jsonify({
        "success": True,
        "filename": uploaded.filename,
        "file_size": len(file_bytes),
        "actual_sha256": actual_hash,
        "expected_sha256": expected_hash if expected_hash else None,
        "is_matched": is_matched
    })

@app.route("/api/system-status")
def system_status():
    """Trả về trạng thái hoạt động của 4 khối trong kiến trúc hệ thống"""
    return jsonify({
        "status": "online",
        "is_admin_configured": AdminAuthManager.is_configured(),
        "is_current_user_admin": session.get("is_admin", False),
        "nodes": [
            {
                "id": "client-upload",
                "label": "🖥️ Giao diện Tải lên & Xem trước",
                "status": "active",
                "mode": "Admin (Full Control)" if session.get("is_admin") else "Read-Only (Public Guest)",
                "supported_formats": ["Word (.docx)", "PDF (.pdf)", "Hình ảnh (.png, .jpg, .jpeg, .webp)"]
            },
            {
                "id": "middleware-security",
                "label": "🛡️ Bộ lọc Bảo mật & Xác thực",
                "status": "active",
                "features": ["Admin Authentication", "Rate Limiting (5 attempts)", "Magic Bytes Check", "SHA-256 Integrity"]
            },
            {
                "id": "controller-watermark",
                "label": "⚙️ Trình xử lý Watermark & Khóa File",
                "status": "active",
                "engines": ["PyMuPDF (AES-256 Content Burn)", "OpenXML SHA-512 Protect", "Pillow Pixel Composite"]
            },
            {
                "id": "database-storage",
                "label": "💾 Kho Lưu trữ Tạm thời (Session Storage)",
                "status": "active",
                "ttl_seconds": 7200
            }
        ]
    })

def _launch_browser_when_ready(target_url: str, check_url: str):
    """
    Tiến trình ngầm kiểm tra trạng thái máy chủ và chỉ mở Chrome
    khi máy chủ đã thực sự sẵn sàng phản hồi HTTP 200 (tránh lỗi ERR_CONNECTION_REFUSED).
    """
    import time
    import urllib.request
    import subprocess
    import webbrowser

    for _ in range(60):
        time.sleep(0.5)
        try:
            req = urllib.request.Request(check_url, headers={"User-Agent": "HealthCheck/1.0"})
            with urllib.request.urlopen(req, timeout=1) as resp:
                if resp.status == 200:
                    print(f"\n[OK] Máy chủ đã sẵn sàng phản hồi (HTTP 200)!")
                    print(f"[*] Đang tự động mở ứng dụng trên Google Chrome: {target_url}\n")
                    
                    # Tìm Chrome theo các đường dẫn chuẩn trên Windows
                    chrome_candidates = [
                        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
                        os.path.expandvars(r"%PROGRAMFILES%\Google\Chrome\Application\chrome.exe")
                    ]
                    chrome_bin = next((p for p in chrome_candidates if os.path.exists(p)), None)
                    
                    if chrome_bin:
                        subprocess.Popen([chrome_bin, target_url])
                    else:
                        # Thử mở chrome qua Windows App Paths, nếu không thì mở trình duyệt mặc định
                        try:
                            subprocess.Popen(["cmd", "/c", "start", "chrome", target_url], shell=True)
                        except Exception:
                            webbrowser.open(target_url)
                    return
        except Exception:
            pass

if __name__ == "__main__":
    print("=" * 60)
    print(" HỆ THỐNG ĐÓNG WATERMARK & BẢO VỆ TỆP - MS. TRẦN THỊ THU TRANG")
    print(" Chế độ bảo mật: Phân quyền Quản trị viên & Khách Chỉ Đọc")
    print(f" Máy chủ đang hoạt động tại: http://{HOST}:{PORT}")
    print("=" * 60)

    # Tự động mở trình duyệt sau khi máy chủ thực sự sẵn sàng
    if os.environ.get("AUTO_OPEN_BROWSER", "1") != "0":
        import threading
        target = f"http://{HOST}:{PORT}" if HOST != "0.0.0.0" else f"http://127.0.0.1:{PORT}"
        health = f"http://127.0.0.1:{PORT}/api/system-status"
        threading.Thread(target=_launch_browser_when_ready, args=(target, health), daemon=True).start()

    app.run(host=HOST, port=PORT, debug=False)
