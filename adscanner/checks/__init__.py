"""
Package checks — nơi đăng ký tất cả các bài kiểm tra.

QUAN TRỌNG: import các module con ở đây để decorator @register được
kích hoạt. Nếu không import, registry sẽ trống.
"""
from adscanner.checks import trust
from adscanner.checks.base import (
    BaseCheck,
    CheckResult,
    CheckStatus,
    Finding,
    ScanContext,
    Severity,
)
from adscanner.checks.registry import (
    register,
    get_all_checks,
    get_checks_by_category,
    get_check_by_id,
    get_all_categories,
)

# === Import các module chứa check để kích hoạt @register ===
# Thứ tự import = thứ tự xuất hiện trong report
from adscanner.checks import account  # noqa: F401  (Nhóm A)
from adscanner.checks import acl  
from adscanner.checks import kerberos
from adscanner.checks import attack_path
from adscanner.checks import adcs
from adscanner.checks import gpo
__all__ = [
    "BaseCheck", "CheckResult", "CheckStatus", "Finding",
    "ScanContext", "Severity",
    "register", "get_all_checks", "get_checks_by_category",
    "get_check_by_id", "get_all_categories",
]