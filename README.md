# HỆ THỐNG ĐÓNG WATERMARK & BẢO VỆ BẢN QUYỀN
### Sẵn Sàng Triển Khai An Toàn Trên Nền Tảng Đám Mây Render (Render Cloud Ready)
**Bản Quyền Độc Quyền: Ms. Trần Thị Thu Trang**

---

## 🔒 Tổng Quan Các Tính Năng Bảo Mật Doanh Nghiệp

1. **Phân Quyền Quản Trị Viên (Password-Protected Editing)**:
   * Chỉ Quản trị viên (Ms. Trang) mới có quyền thêm, sửa, di chuyển, xóa watermark, thay thế ảnh gốc hoặc thay đổi thiết lập bảo mật.
   * Mật khẩu được mã hóa an toàn bằng thuật toán **Scrypt** (`scrypt:32768:8:1`) với muối ngẫu nhiên (salt), hoàn toàn không lưu trữ dạng plain-text.
   * Chống chiếm đoạt quyền quản trị khi triển khai đám mây (Anti-Exploit First-Run) bằng **One-Time Setup Token** hoặc **`ADMIN_INITIAL_PASSWORD`**.

2. **Chế Độ Khách Chỉ Đọc (Read-Only Access for Public Users)**:
   * Khách công cộng chỉ được xem trước bản thành phẩm và tải về tệp đã đóng watermark vĩnh viễn (`/api/download/<session_id>`).
   * Không thể can thiệp vào cấu hình watermark (Giao diện bị khóa và Backend API chặn với `HTTP 401 Unauthorized`).
   * **Nghiêm cấm tải về tệp gốc chưa đóng watermark** (Endpoint `/api/download-original/<session_id>` bảo vệ nghiêm ngặt).

3. **Hòa Trộn Watermark Vĩnh Viễn (Permanently Composited Pixels)**:
   * **Hình ảnh (.png, .jpg, .webp)**: Watermark được hòa trộn trực tiếp vào từng pixel (Permanent Pixel Compositing) và làm phẳng hoàn toàn (Flattened Raster), không lưu dưới dạng layer tách biệt.
   * **Tài liệu PDF (.pdf)**: Watermark được vẽ trực tiếp vào dòng lệnh nội dung trang (Page Content Stream), kết hợp mã hóa phân quyền **AES-256 Bit**.

4. **An Toàn Hệ Thống Phía Sau Reverse Proxy & HTTPS**:
   * **ProxyFix (Werkzeug)**: Hỗ trợ chuyển tiếp an toàn tiêu đề `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`.
   * **Bảo vệ CSRF**: Mọi yêu cầu thay đổi dữ liệu (POST/PUT/DELETE) đều được xác thực bằng mã token `X-CSRF-Token`.
   * **Secure Cookies**: Tự động kích hoạt `SESSION_COOKIE_SECURE=True` trên HTTPS và `HTTPOnly=True`, `SameSite=Lax`.
   * **Giới hạn dung lượng**: Tự động chặn tệp vượt quá 50MB (`HTTP 413 Payload Too Large`).
   * **Rate Limiting**: Khóa tài khoản 15 phút nếu nhập sai mật khẩu quá 5 lần liên tiếp.

---

## ☁️ HƯỚNG DẪN TRIỂN KHAI LÊN RENDER (RENDER CLUSTER DEPLOYMENT)

### 1. Thông Số Cấu Hình Trên Render Dashboard (Web Service)

* **Repository**: `https://github.com/tranchangchangtienganh-code/watermark`
* **Environment / Runtime**: `Python 3`
* **Region**: `Singapore` (hoặc khu vực gần bạn nhất)
* **Branch**: `main`
* **Build Command**:
  ```bash
  pip install -r requirements.txt
  ```
* **Start Command**:
  ```bash
  gunicorn --bind 0.0.0.0:$PORT app:app
  ```

---

### 2. Danh Mục Các Biến Môi Trường (Environment Variables)

Vào mục **Environment** trên Render và thiết lập các biến sau:

| Tên Biến (Key) | Giá Trị Mẫu / Khuyến Nghị | Mục Đích |
| :--- | :--- | :--- |
| `FLASK_ENV` | `production` | Bật chế độ sản xuất, vô hiệu hóa Flask Debug |
| `RENDER` | `true` | Bật cờ bảo mật tự động của Render (ProxyFix & Secure Cookies) |
| `PYTHON_VERSION` | `3.12.10` | Đảm bảo Render sử dụng đúng phiên bản Python 3.12 |
| `SECRET_KEY` | *(Bấm nút "Generate" trên Render)* | Khóa bí mật mã hóa phiên làm việc |
| `ADMIN_INITIAL_PASSWORD` | `Trang@SecureWatermark2026!` *(tự đặt)* | Mật khẩu quản trị viên ban đầu được khởi tạo tự động an toàn |
| `SETUP_TOKEN` | *(Tùy chọn, vd: 32 ký tự ngẫu nhiên)* | Mã kích hoạt thiết lập một lần nếu không dùng `ADMIN_INITIAL_PASSWORD` |
| `DATA_DIR` | `/var/data` *(Chỉ khi dùng Persistent Disk)* | Thư mục gắn ổ đĩa lưu trữ vĩnh viễn |

---

### 3. Giải Thích Cơ Chế Lưu Trữ Trên Render (Persistent Storage vs Free Tier)

#### Lựa Chọn A: Gói Miễn Phí 100% (Render Free Web Service - $0/tháng)
* **Đặc điểm**: Ổ đĩa cục bộ của container Render Free là *ephemeral* (sẽ được làm mới lại khi container khởi động lại hoặc sau 15 phút không có lượt truy cập).
* **Cơ chế bảo vệ thông minh**: Bằng việc cấu hình biến `ADMIN_INITIAL_PASSWORD` trên Render Dashboard, mỗi khi container khởi động lại, hệ thống sẽ tự động khôi phục tài khoản Quản trị viên của Ms. Trang mà không bao giờ bị mất quyền truy cập. Các phiên tệp làm việc tạm thời sẽ hết hạn sau 2 giờ theo đúng chu kỳ bảo mật.

#### Lựa Chọn B: Gói Ổ Đĩa Vĩnh Viễn (Render Persistent Disk - Paid)
* **Chi phí**: Gói Render Starter Web Service ($7/tháng) + Persistent Disk ($0.25/GB/tháng).
* **Cấu hình**:
  1. Trong Render Web Service, chọn mục **Disks** ➔ **Add Disk**.
  2. Đặt tên: `watermark-data`, kích thước: `1 GB`, Mount Path: `/var/data`.
  3. Thêm biến môi trường: `DATA_DIR=/var/data`.
* **Kết quả**: Tất cả tệp gốc, tệp bảo vệ và mật khẩu quản trị viên được lưu cố định trên ổ đĩa SSD độc lập, không bao giờ bị xóa khi deploy lại mã nguồn.

---

## 🧪 Kết Quả Kiểm Thử Toàn Diện (12/12 Tests Passed)

Chạy bộ kiểm thử tự động tại máy cục bộ hoặc CI/CD:
```powershell
python test_suite.py
```
**Kết quả: 12/12 bài test đạt 100% (OK)**:
1. `test_01_unauthenticated_user_cannot_access_editing_api`: Chặn khách gọi API chỉnh sửa (HTTP 401).
2. `test_02_unauthenticated_user_cannot_change_password`: Chặn khách đổi mật khẩu (HTTP 401).
3. `test_03_admin_login_success_and_session_persistence`: Đăng nhập quản trị và lưu session thành công.
4. `test_04_incorrect_password_rejected_and_rate_limited`: Mật khẩu sai bị từ chối; nhập sai 5 lần kích hoạt lockout (HTTP 429).
5. `test_05_final_image_contains_permanently_embedded_watermark`: Watermark được hòa trộn vĩnh viễn vào pixel ảnh.
6. `test_06_original_files_remain_protected`: Khách chỉ tải được tệp có watermark; tệp gốc được bảo vệ nghiêm ngặt.
7. `test_07_full_workflow_when_authenticated_admin`: Luồng chỉnh sửa, preview và kiểm tra tính toàn vẹn hoạt động hoàn hảo.
8. `test_08_change_password_functionality`: Tính năng đổi mật khẩu an toàn hoạt động chính xác.
9. `test_09_csrf_protection_enforcement`: Bắt buộc token CSRF, chặn đứng các yêu cầu giả mạo từ bên ngoài (HTTP 403).
10. `test_10_first_run_setup_token_protection`: Chống chiếm đoạt quyền quản trị khi triển khai public bằng Setup Token.
11. `test_11_proxy_fix_https_and_forwarding`: Hoạt động chuẩn xác sau Render Reverse Proxy với tiêu đề X-Forwarded-*.
12. `test_12_production_wsgi_app_exposed`: Ứng dụng `app:app` tương thích 100% với Gunicorn và tắt debug mode trong production.

---

## 💻 Khởi Chạy Cục Bộ (Local Development)

Nhấp đúp chuột vào tệp [**`run.bat`**](file:///d:/WATERMARKKGCHINHSUA/run.bat) trên Windows hoặc thực thi:
```powershell
python app.py
```
Sau đó truy cập **http://127.0.0.1:5000**.
