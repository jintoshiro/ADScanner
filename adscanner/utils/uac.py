"""
Tiện ích xử lý userAccountControl (UAC) và các kiểu dữ liệu AD.

Module này KHÔNG kết nối LDAP — chỉ là các hàm thuần túy (pure function)
để parse và hiển thị. Nhờ vậy dễ unit test.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any

from adscanner.config import UAC


# ============================================================
# PARSE userAccountControl
# ============================================================
def parse_uac(uac_value: int | None) -> dict[str, bool]:
    """
    Phân tích giá trị UAC (số nguyên) thành dict các cờ.

    Ví dụ: uac=0x10200 (66048)
      → {'DONT_EXPIRE_PASSWD': True, 'NORMAL_ACCOUNT': True, ...}

    Trả về dict với TẤT CẢ các cờ đã định nghĩa trong config.UAC,
    mỗi cờ là True/False.
    """
    if uac_value is None:
        return {name: False for name in UAC}
    return {
        name: bool(uac_value & mask)
        for name, mask in UAC.items()
    }


def describe_uac(uac_value: int | None) -> list[str]:
    """
    Trả về danh sách tên các cờ đang BẬT.
    Hữu ích để in log/report.
    """
    flags = parse_uac(uac_value)
    return [name for name, active in flags.items() if active]


# ============================================================
# HELPERS — kiểm tra cờ cụ thể
# ============================================================
def is_disabled(uac_value: int | None) -> bool:
    """Tài khoản bị vô hiệu hóa (không thể đăng nhập)."""
    return bool((uac_value or 0) & UAC["ACCOUNTDISABLE"])


def is_dont_expire_password(uac_value: int | None) -> bool:
    """Mật khẩu không bao giờ hết hạn."""
    return bool((uac_value or 0) & UAC["DONT_EXPIRE_PASSWD"])


def is_password_not_required(uac_value: int | None) -> bool:
    """Tài khoản không yêu cầu mật khẩu (nguy hiểm)."""
    return bool((uac_value or 0) & UAC["PASSWD_NOTREQD"])


def is_asrep_roastable(uac_value: int | None) -> bool:
    """Không yêu cầu Kerberos preauthentication → AS-REP Roastable."""
    return bool((uac_value or 0) & UAC["DONT_REQ_PREAUTH"])


def is_trusted_for_delegation(uac_value: int | None) -> bool:
    """Unconstrained Delegation (rất nguy hiểm nếu kết hợp với DC)."""
    return bool((uac_value or 0) & UAC["TRUSTED_FOR_DELEGATION"])


def is_sensitive_and_not_delegated(uac_value: int | None) -> bool:
    """Tài khoản nhạy cảm, không cho phép delegation."""
    return bool((uac_value or 0) & UAC["NOT_DELEGATED"])


def is_trusted_to_auth_for_delegation(uac_value: int | None) -> bool:
    """Constrained Delegation với protocol transition (S4U2Self)."""
    return bool((uac_value or 0) & UAC["TRUSTED_TO_AUTH_FOR_DELEGATION"])


def is_smartcard_required(uac_value: int | None) -> bool:
    """Yêu cầu smartcard để đăng nhập."""
    return bool((uac_value or 0) & UAC["SMARTCARD_REQUIRED"])


# ============================================================
# CHUẨN HÓA GIÁ TRỊ LDAP
# ============================================================
def ldap_scalar(value: Any) -> Any:
    """
    ldap3 trả về một số thuộc tính dưới dạng list dù chỉ có 1 giá trị.
    Hàm này chuẩn hóa: list 1 phần tử → phần tử; list rỗng → None.
    """
    if isinstance(value, list):
        if not value:
            return None
        if len(value) == 1:
            return value[0]
    return value


def ldap_list(value: Any) -> list:
    """
    Chuẩn hóa giá trị LDAP về list.
    None → []; scalar → [scalar]; list → giữ nguyên.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def ldap_int(value: Any, default: int = 0) -> int:
    """Chuẩn hóa về int, xử lý None và list."""
    v = ldap_scalar(value)
    if v is None:
        return default
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


# ============================================================
# CHUYỂN ĐỔI WINDOWS FILETIME
# ============================================================
# Windows FILETIME = số 100-nanosecond intervals kể từ 1601-01-01 UTC
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_datetime(filetime: Any) -> datetime | None:
    """
    Chuẩn hóa nhiều kiểu dữ liệu thời gian AD về datetime (UTC).

    Hỗ trợ:
      - list              : LDAP multi-valued → lấy phần tử đầu
      - datetime          : ldap3 đã tự convert (khi get_info=ALL)
      - int/str           : Windows FILETIME thô (100ns từ 1601-01-01)
      - None / 0          : chưa set

    Trả None cho các giá trị "sentinel":
      - FILETIME 0x7FFFFFFFFFFFFFFF (never) → ldap3 convert thành năm 9999
      - FILETIME 0 (chưa set)               → ldap3 convert thành năm 1601
    """
    # 1. Bóc list (LDAP multi-valued)
    if isinstance(filetime, list):
        if not filetime:
            return None
        filetime = filetime[0]

    # 2. ldap3 đã convert sẵn sang datetime
    if isinstance(filetime, datetime):
        dt = filetime
        # Guard: năm 1601 = epoch FILETIME = chưa set
        if dt.year <= 1601:
            return None
        # Guard: năm 9999 = 0x7FFFFFFFFFFFFFFF = "never"
        if dt.year >= 9999:
            return None
        # Chuẩn hóa về UTC nếu chưa có tzinfo
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    if filetime is None:
        return None

    # 3. Cố ép về int (FILETIME thô, phòng khi ldap3 không convert)
    try:
        value = int(filetime)
    except (ValueError, TypeError):
        return None

    if value == 0:
        return None
    if value == 0x7FFFFFFFFFFFFFFF:
        return None

    # 4. Công thức chuyển đổi FILETIME
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=value / 10)
    except (OverflowError, ValueError):
        return None

def filetime_age_days(filetime: Any) -> int | None:
    """
    Số ngày kể từ thời điểm FILETIME đến bây giờ.
    None nếu filetime không hợp lệ hoặc là "never".
    """
    dt = filetime_to_datetime(filetime)
    if dt is None:
        return None
    delta = datetime.now(timezone.utc) - dt
    return max(0, delta.days)


# ============================================================
# HIỂN THỊ
# ============================================================
def format_filetime(filetime: Any) -> str:
    """Format FILETIME thành chuỗi dễ đọc, dùng cho báo cáo."""
    dt = filetime_to_datetime(filetime)
    if dt is None:
        return "(chưa set / never)"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")