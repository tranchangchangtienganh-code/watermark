"""
Core modules for Watermark and Document Protection System
"""
from core.security_middleware import SecurityMiddleware, SecurityCheckResult, admin_required
from core.watermark_controller import WatermarkController
from core.session_storage import SessionStorage
from core.admin_auth import AdminAuthManager

__all__ = [
    "SecurityMiddleware",
    "SecurityCheckResult",
    "WatermarkController",
    "SessionStorage",
    "AdminAuthManager",
    "admin_required"
]
