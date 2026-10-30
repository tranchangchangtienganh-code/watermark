@echo off
cd /d "%~dp0"
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
set HOST=127.0.0.1
set PORT=5000
set AUTO_OPEN_BROWSER=1
title HỆ THỐNG ĐÓNG WATERMARK & BẢO VỆ TỆP - MS. TRẦN THỊ THU TRANG

echo =====================================================================
echo  HỆ THỐNG ĐÓNG WATERMARK & BẢO VỆ TỆP CHỐNG CHỈNH SỬA
echo  Bản quyền độc quyền: Ms. Trần Thị Thu Trang
echo  Địa chỉ cục bộ: http://127.0.0.1:5000
echo =====================================================================
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo [LỖI KHỞI ĐỘNG] Không tìm thấy Python trong hệ thống PATH!
    echo Vui lòng cài đặt Python từ python.org và tích chọn "Add Python to PATH".
    echo.
    pause
    exit /b 1
)

echo [1/3] Kiểm tra phiên bản Python...
python --version
if errorlevel 1 (
    echo [LỖI] Lệnh python gặp sự cố khi thực thi!
    echo.
    pause
    exit /b 1
)

echo [2/3] Kiểm tra các thư viện phụ thuộc (requirements.txt)...
python -m pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [CẢNH BÁO] pip install gặp sự cố hoặc cảnh báo, đang tiếp tục khởi chạy...
)

echo.
echo [3/3] Đang khởi động máy chủ Flask tại http://127.0.0.1:5000 ...
echo (*) Cửa sổ console này sẽ GIỮ NGUYÊN để duy trì máy chủ hoạt động.
echo (*) Google Chrome sẽ TỰ ĐỘNG MỞ ngay khi máy chủ phản hồi sẵn sàng.
echo (*) Để dừng máy chủ khi sử dụng xong, nhấn tổ hợp phím Ctrl + C.
echo ---------------------------------------------------------------------
echo.

python app.py

if errorlevel 1 (
    echo.
    echo =====================================================================
    echo [LỖI DỪNG MÁY CHỦ] Flask server đã thoát với mã lỗi: %errorlevel%
    echo Vui lòng kiểm tra thông báo lỗi chi tiết ở trên để khắc phục.
    echo =====================================================================
)

echo.
echo Máy chủ đã dừng hoạt động. Nhấn một phím bất kỳ để đóng cửa sổ.
pause
