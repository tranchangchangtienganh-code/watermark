"""
Node 3: Trình xử lý Watermark & Khóa File (Watermark Controller)
Chịu trách nhiệm:
1. Điều phối xử lý đa định dạng (PDF, Word, Hình ảnh)
2. Chèn chữ 'TRẦN THỊ THU TRANG' màu xám ở cuối trang/tệp
3. Đảm bảo giữ nguyên 100% định dạng, nội dung và chất lượng gốc
4. Áp dụng chính sách chống chỉnh sửa/chuyển đổi (Anti-tamper & Permissions Lock)
"""
from typing import Dict, Any, Optional
from core.processors.pdf_processor import PDFProcessor
from core.processors.docx_processor import DocxProcessor
from core.processors.image_processor import ImageProcessor
from config import DEFAULT_WATERMARK_TEXT, DEFAULT_SUB_TEXT, DEFAULT_GRAY_COLOR_HEX

class WatermarkController:
    """Bộ điều khiển trung tâm cho Watermark & Khóa File"""

    @classmethod
    def execute(
        cls,
        file_type: str,
        input_path: str,
        output_path: str,
        preview_output_path: str,
        watermark_text: str = DEFAULT_WATERMARK_TEXT,
        sub_text: str = DEFAULT_SUB_TEXT,
        position: str = "bottom-center",
        gray_color_hex: str = DEFAULT_GRAY_COLOR_HEX,
        font_size: Optional[float] = None,
        password: Optional[str] = None,
        disallow_copy: bool = True,
        disallow_modify: bool = True,
        disallow_print: bool = False,
        require_password_to_open: bool = False
    ) -> Dict[str, Any]:
        """
        Thực thi quy trình đóng watermark và áp dụng cơ chế khóa file
        phù hợp theo từng loại định dạng tệp.
        """
        text = watermark_text.strip() if watermark_text else DEFAULT_WATERMARK_TEXT

        if file_type == "pdf":
            # Xử lý tệp PDF
            fs = font_size if font_size else 9.5
            return PDFProcessor.process(
                input_path=input_path,
                output_path=output_path,
                preview_output_path=preview_output_path,
                watermark_text=text,
                sub_text=sub_text,
                position=position,
                gray_color_hex=gray_color_hex,
                font_size=fs,
                password=password,
                disallow_copy=disallow_copy,
                disallow_modify=disallow_modify,
                disallow_print=disallow_print,
                require_password_to_open=require_password_to_open
            )

        elif file_type == "docx":
            # Xử lý tệp Word
            fs = font_size if font_size else 9.0
            return DocxProcessor.process(
                input_path=input_path,
                output_path=output_path,
                preview_output_path=preview_output_path,
                watermark_text=text,
                sub_text=sub_text,
                position=position,
                gray_color_hex=gray_color_hex,
                font_size=fs,
                password=password,
                disallow_modify=disallow_modify
            )

        elif file_type == "image":
            # Xử lý tệp hình ảnh
            return ImageProcessor.process(
                input_path=input_path,
                output_path=output_path,
                preview_output_path=preview_output_path,
                watermark_text=text,
                sub_text=sub_text,
                position=position,
                gray_color_hex=gray_color_hex,
                font_size=font_size,
                opacity=0.90,
                include_banner=True
            )

        else:
            raise ValueError(f"Định dạng tệp '{file_type}' không được hỗ trợ bởi Trình xử lý Watermark.")
