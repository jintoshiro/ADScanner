"""
Registry — đăng ký và truy xuất các check.

Cách dùng:
    @register
    class CheckA1(BaseCheck):
        id = "A1"
        ...

    checks = get_all_checks()  # → [CheckA1(), ...]
"""
from __future__ import annotations

from adscanner.checks.base import BaseCheck

# Danh sách class (không phải instance) đã đăng ký
_CHECK_CLASSES: list[type[BaseCheck]] = []


def register(cls: type[BaseCheck]) -> type[BaseCheck]:
    """
    Decorator đăng ký một check class.

    Kiểm tra trùng ID ngay lúc import để phát hiện sớm lỗi copy-paste.
    """
    if not issubclass(cls, BaseCheck):
        raise TypeError(f"{cls.__name__} phải kế thừa BaseCheck")

    for existing in _CHECK_CLASSES:
        if existing.id == cls.id:
            raise ValueError(
                f"Trùng check ID '{cls.id}': "
                f"{existing.__name__} và {cls.__name__}"
            )

    _CHECK_CLASSES.append(cls)
    return cls


def get_all_checks() -> list[BaseCheck]:
    """Trả về instance của tất cả check đã đăng ký."""
    return [cls() for cls in _CHECK_CLASSES]


def get_checks_by_category(category: str) -> list[BaseCheck]:
    """Lọc check theo category (ví dụ 'Account Security')."""
    return [cls() for cls in _CHECK_CLASSES if cls.category == category]


def get_check_by_id(check_id: str) -> BaseCheck | None:
    """Tìm check theo ID (dùng cho CLI --check A1)."""
    for cls in _CHECK_CLASSES:
        if cls.id == check_id:
            return cls()
    return None


def get_all_categories() -> list[str]:
    """Danh sách category (giữ thứ tự xuất hiện)."""
    seen: list[str] = []
    for cls in _CHECK_CLASSES:
        if cls.category not in seen:
            seen.append(cls.category)
    return seen