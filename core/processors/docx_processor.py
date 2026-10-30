"""
Bộ xử lý Watermark & Khóa File Word (.docx)
Chèn chữ 'TRẦN THỊ THU TRANG' màu xám ở cuối trang/tệp (Footer) mà giữ nguyên 100% định dạng gốc,
đồng thời áp dụng chính sách chống chỉnh sửa/chuyển đổi (OOXML Read-Only Protection với chuẩn SHA-512).
"""
import os
import hashlib
import base64
from typing import Dict, Any, Optional, Tuple
import docx
from docx.shared import Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls
from PIL import Image, ImageDraw, ImageFont
from config import DEFAULT_FONT_PATH, DEFAULT_WATERMARK_TEXT, DEFAULT_SUB_TEXT

class DocxProcessor:
    """Xử lý đóng watermark và khóa chỉnh sửa đối với tệp Word (.docx)"""

    @staticmethod
    def hex_to_rgb(hex_color: str) -> Tuple[int, int, int]:
        """Chuyển mã màu HEX (ví dụ #708090) sang tuple RGB số nguyên (0-255)"""
        hex_clean = hex_color.lstrip("#")
        if len(hex_clean) == 3:
            hex_clean = "".join([c*2 for c in hex_clean])
        if len(hex_clean) != 6:
            return 120, 120, 120
        r = int(hex_clean[0:2], 16)
        g = int(hex_clean[2:4], 16)
        b = int(hex_clean[4:6], 16)
        return r, g, b

    @staticmethod
    def hash_word_password(password: str, spin_count: int = 100000) -> Tuple[str, str]:
        """
        Tạo mã băm bảo mật theo chuẩn ISO/IEC 29500-1:2016 cho Microsoft Word:
        Sử dụng SHA-512 lặp lại spin_count lần với Salt ngẫu nhiên 128-bit
        """
        salt = os.urandom(16)
        pw_bytes = password.encode("utf-16le")
        h = hashlib.sha512(salt + pw_bytes).digest()
        for i in range(spin_count):
            h = hashlib.sha512(h + i.to_bytes(4, byteorder="little")).digest()
        salt_b64 = base64.b64encode(salt).decode("ascii")
        hash_b64 = base64.b64encode(h).decode("ascii")
        return salt_b64, hash_b64

    @classmethod
    def generate_docx_preview(
        cls,
        doc: docx.Document,
        preview_path: str,
        watermark_text: str,
        gray_rgb: Tuple[int, int, int]
    ):
        """
        Tạo ảnh xem trước (Preview Thumbnail) trực quan mô phỏng trang Word:
        Bao gồm tiêu đề, đoạn văn bản trích đoạn và chân trang Watermark Ms. Trang
        """
        w, h = 800, 1050
        img = Image.new("RGB", (w, h), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)

        # Viền trang giấy thanh lịch
        draw.rectangle([(20, 20), (w - 20, h - 20)], outline=(225, 229, 235), width=2)
        # Bóng đổ nhẹ bên trong
        draw.rectangle([(24, 24), (w - 24, h - 24)], outline=(243, 244, 246), width=1)

        font_path = str(DEFAULT_FONT_PATH) if os.path.exists(DEFAULT_FONT_PATH) else None
        title_font = ImageFont.truetype(font_path, 22) if font_path else ImageFont.load_default()
        body_font = ImageFont.truetype(font_path, 13) if font_path else ImageFont.load_default()
        footer_font = ImageFont.truetype(font_path, 11) if font_path else ImageFont.load_default()

        # Thu thập nội dung trích xuất từ tài liệu
        paragraphs = [p.text.strip() for p in doc.paragraphs if p.text.strip()]
        title_text = paragraphs[0] if paragraphs else "Tài Liệu Word Của Ms. Trang"
        if len(title_text) > 45:
            title_text = title_text[:42] + "..."

        # Vẽ tiêu đề tài liệu
        draw.text((60, 60), title_text, font=title_font, fill=(30, 41, 59))
        draw.line([(60, 100), (w - 60, 100)], fill=(226, 232, 240), width=1)

        # Vẽ các đoạn trích đoạn mô phỏng văn bản
        curr_y = 120
        body_snippets = paragraphs[1:8] if len(paragraphs) > 1 else [
            "Nội dung văn bản được bảo vệ toàn vẹn 100% định dạng gốc.",
            "Tất cả các định dạng bảng biểu, hình ảnh, liên kết và kiểu dáng được giữ nguyên.",
            "Chính sách bảo vệ nghiêm ngặt chống chỉnh sửa trái phép đã được kích hoạt thành công."
        ]
        for snippet in body_snippets:
            if curr_y > h - 180:
                break
            line = snippet if len(snippet) < 70 else snippet[:67] + "..."
            draw.text((60, curr_y), line, font=body_font, fill=(71, 85, 105))
            curr_y += 32

        # Vẽ dải chân trang (Footer Area) với Watermark xám
        footer_line_y = h - 70
        draw.line([(50, footer_line_y), (w - 50, footer_line_y)], fill=(203, 213, 225), width=1)

        # Chữ Watermark bản quyền
        full_footer = f"🔒 {watermark_text}  •  CHỐNG CHỈNH SỬA / SAO CHÉP"
        bbox = draw.textbbox((0, 0), full_footer, font=footer_font)
        text_w = bbox[2] - bbox[0]
        text_x = (w - text_w) / 2
        draw.text((text_x, footer_line_y + 15), full_footer, font=footer_font, fill=gray_rgb)

        img.save(preview_path, format="PNG")

    @classmethod
    def process(
        cls,
        input_path: str,
        output_path: str,
        preview_output_path: str,
        watermark_text: str = DEFAULT_WATERMARK_TEXT,
        sub_text: str = DEFAULT_SUB_TEXT,
        position: str = "bottom-center",
        gray_color_hex: str = "#708090",
        font_size: float = 9.0,
        password: Optional[str] = None,
        disallow_modify: bool = True
    ) -> Dict[str, Any]:
        """
        Thực hiện chèn watermark chân trang và khóa tệp Word:
        - Giữ nguyên 100% nội dung, kiểu dáng, bảng biểu, ảnh
        - Chèn thông tin bản quyền vào tất cả footer sections
        - Áp dụng OpenXML Document Protection (w:documentProtection) với SHA-512
        """
        doc = docx.Document(input_path)
        color_rgb = cls.hex_to_rgb(gray_color_hex)
        full_watermark = watermark_text.strip()
        if sub_text and sub_text.strip():
            full_watermark = f"{full_watermark}  •  {sub_text.strip()}"

        # Lặp qua tất cả các section để chèn watermark vào chân trang (Footer)
        for section in doc.sections:
            footer = section.footer
            # Lấy hoặc tạo đoạn văn chân trang
            if footer.paragraphs:
                p = footer.paragraphs[0]
            else:
                p = footer.add_paragraph()

            # Thiết lập căn lề chân trang
            if position == "bottom-right":
                p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            elif position == "bottom-left":
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            else:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER

            # Xóa các run cũ nếu chỉ có khoảng trắng rỗng
            if not p.text.strip():
                p.text = ""

            # Thêm run chứa nội dung watermark màu xám
            run = p.add_run(f"\n{full_watermark}")
            run.font.name = "Arial"
            run.font.size = Pt(font_size)
            run.font.color.rgb = RGBColor(color_rgb[0], color_rgb[1], color_rgb[2])

        # Áp dụng chính sách chống chỉnh sửa (Document Protection)
        if disallow_modify:
            settings_elm = doc.settings.element
            # Xóa thẻ documentProtection cũ nếu có
            for old_prot in settings_elm.findall(docx.oxml.ns.qn("w:documentProtection")):
                settings_elm.remove(old_prot)

            if password and password.strip():
                salt, hash_val = cls.hash_word_password(password.strip())
                prot_xml = (
                    f'<w:documentProtection {nsdecls("w")} '
                    f'w:edit="readOnly" '
                    f'w:enforcement="1" '
                    f'w:cryptProviderType="rsaAES" '
                    f'w:cryptAlgorithmClass="hash" '
                    f'w:cryptAlgorithmType="typeAny" '
                    f'w:cryptAlgorithmSid="14" '
                    f'w:cryptSpinCount="100000" '
                    f'w:hash="{hash_val}" '
                    f'w:salt="{salt}"/>'
                )
            else:
                # Khóa chỉ đọc cơ bản nếu không nhập mật khẩu
                prot_xml = (
                    f'<w:documentProtection {nsdecls("w")} '
                    f'w:edit="readOnly" '
                    f'w:enforcement="1"/>'
                )

            protection_element = parse_xml(prot_xml)
            settings_elm.append(protection_element)

        # Lưu tài liệu Word đã khóa
        doc.save(output_path)

        # Tạo ảnh xem trước tài liệu trực quan
        cls.generate_docx_preview(doc, preview_output_path, full_watermark, color_rgb)

        # Tính toán SHA-256 tệp đã khóa
        with open(output_path, "rb") as f:
            protected_bytes = f.read()
            protected_sha256 = hashlib.sha256(protected_bytes).hexdigest()
            protected_size = len(protected_bytes)

        return {
            "success": True,
            "format": "docx",
            "section_count": len(doc.sections),
            "output_path": output_path,
            "preview_path": preview_output_path,
            "protected_sha256": protected_sha256,
            "file_size": protected_size,
            "owner_protected": bool(password and password.strip()),
            "security_policies": {
                "protection_mode": "OOXML Read-Only Enforcement",
                "hash_algorithm": "SHA-512 (100,000 spin cycles)",
                "modify_locked": disallow_modify
            }
        }
