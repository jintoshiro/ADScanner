"""Tiện ích chuyển đổi thời gian AD (interval 100ns)."""
from datetime import timedelta
from typing import Optional

NEVER = -0x8000000000000000  # -9223372036854775808

def interval_to_days(value) -> Optional[float]:
    """Chuyển maxPwdAge/minPwdAge/lockoutDuration sang số ngày."""
    if value is None:
        return None
    if isinstance(value, timedelta):
        days = abs(value.total_seconds()) / 86_400
        return None if value == timedelta(0) or days > 36_500 else days
    try:
        v = int(value)
    except (ValueError, TypeError):
        return None
    if v == 0 or v == NEVER:
        return None
    return abs(v) / (10_000_000 * 86_400)