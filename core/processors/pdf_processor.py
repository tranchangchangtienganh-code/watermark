"""
Bộ xử lý Watermark & Khóa File PDF
Chèn chữ 'TRẦN THỊ THU TRANG' màu xám ở cuối trang/tệp mà giữ nguyên 100% định dạng gốc,
đồng thời áp dụng chính sách chống chỉnh sửa/chuyển đổi (Anti-tamper / AES-256 Permissions Lock).
"""
import os
import hashlib
from typing import Dict, Any, Optional, Tuple
import pymupdf
from config import DEFAULT_FONT_PATH, DEFAULT_WATERMARK_TEXT, DEFAULT_SUB_TEXT

class PDFProcessor:
    """Xử lý đóng watermark và khóa chỉnh sửa đối với tệp PDF"""

    @staticmethod
    def hex_to_rgb_float(hex_color: str) -> Tuple[float, float, float]:
        """Chuyển mã màu HEX (ví dụ #708090) sang tuple RGB dạng float (0.0 - 1.0)"""
        hex_clean = hex_color.lstrip("#")
        if len(hex_clean) == 3:
            hex_clean = "".join([c*2 for c in hex_clean])
        if len(hex_clean) != 6:
            return 0.45, 0.45, 0.45
        r = int(hex_clean[0:2], 16) / 255.0
        g = int(hex_clean[2:4], 16) / 255.0
        b = int(hex_clean[4:6], 16) / 255.0
        return r, g, b

    @classmethod
    def process(
        cls,
        input_path: str,
        output_path: str,
        preview_output_path: str,
        watermark_text: str = DEFAULT_WATERMARK_TEXT,
        sub_text: str = DEFAULT_SUB_TEXT,
        position: str = "bottom-center",
        gray_color_hex: str = "#666666",
        font_size: float = 9.5,
        password: Optional[str] = None,
        disallow_copy: bool = True,
        disallow_modify: bool = True,
        disallow_print: bool = False,
        require_password_to_open: bool = False
    ) -> Dict[str, Any]:
        """
        Thực hiện chèn watermark cuối trang và khóa tệp PDF:
        - Giữ nguyên 100% vector, font chữ, bố cục gốc
        - Chèn thông tin bản quyền ở lề dưới trang
        - Áp dụng mã hóa AES-256 và chính sách phân quyền nghiêm ngặt
        """
        doc = pymupdf.open(input_path)
        total_pages = len(doc)
        font_file = str(DEFAULT_FONT_PATH) if os.path.exists(DEFAULT_FONT_PATH) else None

        color_rgb = cls.hex_to_rgb_float(gray_color_hex)
        full_watermark_text = watermark_text.strip()
        if sub_text and sub_text.strip():
            full_watermark_text = f"{full_watermark_text}  •  {sub_text.strip()}"

        # Chèn watermark ở cuối từng trang
        for page_index in range(total_pages):
            page = doc[page_index]
            rect = page.rect
            margin_x = 24.0
            margin_bottom = 12.0
            box_height = 28.0

            fontname = "ArialVN"
            if font_file:
                try:
                    page.insert_font(fontname=fontname, fontfile=font_file)
                except Exception:
                    fontname = "helv"
            else:
                fontname = "helv"

            # Xác định vị trí canh lề ở cuối trang
            align_mode = pymupdf.TEXT_ALIGN_CENTER
            if position == "bottom-right":
                align_mode = pymupdf.TEXT_ALIGN_RIGHT
                target_rect = pymupdf.Rect(
                    margin_x,
                    rect.height - margin_bottom - box_height,
                    rect.width - margin_x,
                    rect.height - margin_bottom
                )
            elif position == "bottom-left":
                align_mode = pymupdf.TEXT_ALIGN_LEFT
                target_rect = pymupdf.Rect(
                    margin_x,
                    rect.height - margin_bottom - box_height,
                    rect.width - margin_x,
                    rect.height - margin_bottom
                )
            else:  # bottom-center
                align_mode = pymupdf.TEXT_ALIGN_CENTER
                target_rect = pymupdf.Rect(
                    margin_x,
                    rect.height - margin_bottom - box_height,
                    rect.width - margin_x,
                    rect.height - margin_bottom
                )

            # Vẽ đường chỉ phân cách siêu mỏng thanh lịch phía trên watermark
            line_y = target_rect.y0 + 2
            page.draw_line(
                pymupdf.Point(target_rect.x0 + 40, line_y),
                pymupdf.Point(target_rect.x1 - 40, line_y),
                color=(color_rgb[0] * 1.2 if color_rgb[0] * 1.2 <= 1.0 else 0.8,
                       color_rgb[1] * 1.2 if color_rgb[1] * 1.2 <= 1.0 else 0.8,
                       color_rgb[2] * 1.2 if color_rgb[2] * 1.2 <= 1.0 else 0.8),
                width=0.4
            )

            # Chèn chữ watermark
            page.insert_textbox(
                target_rect,
                full_watermark_text,
                fontname=fontname,
                fontsize=font_size,
                color=color_rgb,
                align=align_mode
            )

        # Cập nhật siêu dữ liệu tệp PDF (Metadata)
        meta = doc.metadata or {}
        meta["author"] = watermark_text
        meta["creator"] = "Ms. Tran Thi Thu Trang - Watermark Protection System"
        meta["producer"] = "Secure Document Engine v2.0"
        meta["subject"] = "Protected Document - Anti Modification & Unauthorized Copying"
        doc.set_metadata(meta)

        # Tính toán phân quyền (Permissions Mask)
        permissions = 0
        if not disallow_print:
            permissions |= pymupdf.PDF_PERM_PRINT

        # Luôn cấm chỉnh sửa và sửa đổi cấu trúc
        if not disallow_modify:
            permissions |= pymupdf.PDF_PERM_MODIFY

        # Cấm sao chép nội dung/trích xuất text
        if not disallow_copy:
            permissions |= pymupdf.PDF_PERM_COPY

        # Cấm chú thích, điền form
        # Không bật PDF_PERM_ANNOTATE hay PDF_PERM_FORM

        # Thiết lập mật khẩu bảo vệ
        # Owner password dùng để khóa quyền chỉnh sửa
        # User password: để trống để người nhận có thể đọc bình thường nhưng không thể sửa
        owner_password = password if (password and password.strip()) else "Trang@SecuredLock2026"
        user_password = password if (require_password_to_open and password and password.strip()) else ""

        # Xuất bản tệp với chuẩn mã hóa cấp doanh nghiệp AES-256
        doc.save(
            output_path,
            encryption=pymupdf.PDF_ENCRYPT_AES_256,
            owner_pw=owner_password,
            user_pw=user_password,
            permissions=permissions,
            deflate=True
        )

        # Tạo ảnh xem trước trang đầu tiên (Preview Pixmap)
        preview_doc = pymupdf.open(output_path)
        first_page = preview_doc[0]
        pix = first_page.get_pixmap(dpi=130)
        pix.save(preview_output_path)
        preview_doc.close()
        doc.close()

        # Tính toán mã băm SHA-256 của tệp xuất bản
        with open(output_path, "rb") as f:
            protected_bytes = f.read()
            protected_sha256 = hashlib.sha256(protected_bytes).hexdigest()
            protected_size = len(protected_bytes)

        return {
            "success": True,
            "format": "pdf",
            "page_count": total_pages,
            "output_path": output_path,
            "preview_path": preview_output_path,
            "protected_sha256": protected_sha256,
            "file_size": protected_size,
            "owner_protected": bool(password and password.strip()),
            "security_policies": {
                "encryption": "AES-256 Bit Enterprise",
                "modify_locked": disallow_modify,
                "copy_locked": disallow_copy,
                "print_allowed": not disallow_print,
                "require_open_password": require_password_to_open
            }
        }
