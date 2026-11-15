"""
Tiện ích xử lý SID (Security Identifier) và groupType của AD.

SID là định danh duy nhất, KHÔNG phụ thuộc ngôn ngữ. Dùng SID để nhận diện
nhóm đặc quyền thay vì tên (tên bị bản địa hóa: "Domain Admins" ở Mỹ,
"Administrateurs du domaine" ở Pháp).
"""
from __future__ import annotations

from typing import Any


# ============================================================
# WELL-KNOWN SIDs (giống nhau trên mọi domain/forest)
# ============================================================
WELL_KNOWN_GROUP_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
}

# Nhóm đặc quyền (dùng cho A3, A6, và các check về sau)
PRIVILEGED_BUILTIN_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
}

# Domain-relative RIDs (nối vào domain SID)
# Ví dụ: nếu domain SID = "S-1-5-21-111-222-333",
# Domain Admins = "S-1-5-21-111-222-333-512"
PRIVILEGED_DOMAIN_RIDS = {
    512: "Domain Admins",
    516: "Domain Controllers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    522: "Cloneable Domain Controllers",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
}


# ============================================================
# CHUYỂN ĐỔI SID
# ============================================================
def sid_bytes_to_string(sid_bytes: bytes) -> str | None:
    """
    Chuyển binary SID (định dạng gốc trong AD) sang chuỗi "S-1-5-...".

    Cấu trúc binary SID:
      - byte 0    : revision (thường = 1)
      - byte 1    : sub-authority count (N)
      - bytes 2-7 : identifier authority (48-bit, big-endian)
      - bytes 8+  : N sub-authorities, mỗi cái 4 bytes little-endian
    """
    if not isinstance(sid_bytes, (bytes, bytearray)) or len(sid_bytes) < 8:
        return None
    revision = sid_bytes[0]
    count = sid_bytes[1]
    authority = int.from_bytes(sid_bytes[2:8], byteorder="big")
    subs = []
    for i in range(count):
        offset = 8 + i * 4
        if offset + 4 > len(sid_bytes):
            break
        sub = int.from_bytes(sid_bytes[offset:offset + 4], byteorder="little")
        subs.append(str(sub))
    if not subs:
        return f"S-{revision}-{authority}"
    return f"S-{revision}-{authority}-" + "-".join(subs)


def normalize_sid(raw_sid: Any) -> str:
    """
    Chuẩn hóa SID từ nhiều nguồn:
      - bytes → chuyển sang string
      - list → lấy phần tử đầu
      - str → giữ nguyên
      - None → ""
    """
    if raw_sid is None:
        return ""
    if isinstance(raw_sid, list):
        raw_sid = raw_sid[0] if raw_sid else None
        if raw_sid is None:
            return ""
    if isinstance(raw_sid, (bytes, bytearray)):
        return sid_bytes_to_string(raw_sid) or ""
    return str(raw_sid)


# ============================================================
# PHÂN TÍCH SID
# ============================================================
def get_domain_sid_from_sid(sid: str) -> str | None:
    """
    Từ một SID của user/group trong domain, trả về domain SID.

    Ví dụ: "S-1-5-21-111-222-333-500" → "S-1-5-21-111-222-333"
    """
    if not sid or not sid.startswith("S-1-5-21-"):
        return None
    parts = sid.split("-")
    # S-1-5-21-a-b-c-rid → domain SID là 7 phần tử đầu
    if len(parts) < 8:
        return None
    return "-".join(parts[:7])


def get_rid(sid: str, domain_sid: str | None = None) -> int | None:
    """
    Lấy RID (Relative Identifier) từ SID.
    Nếu cung cấp domain_sid, chỉ lấy RID khi SID thuộc domain đó.
    """
    if not sid:
        return None
    if domain_sid:
        prefix = domain_sid + "-"
        if not sid.startswith(prefix):
            return None
        try:
            return int(sid[len(prefix):])
        except ValueError:
            return None
    # Không có domain SID → lấy phần tử cuối
    try:
        return int(sid.rsplit("-", 1)[-1])
    except (ValueError, IndexError):
        return None


# ============================================================
# XÁC ĐỊNH NHÓM ĐẶC QUYỀN
# ============================================================
def get_privileged_group_name(sid: str, domain_sid: str | None = None) -> str | None:
    """
    Trả về tên nhóm đặc quyền nếu SID thuộc danh sách, ngược lại None.
    Ưu tiên SID, không phụ thuộc ngôn ngữ hiển thị.
    """
    if not sid:
        return None
    if sid in PRIVILEGED_BUILTIN_SIDS:
        return PRIVILEGED_BUILTIN_SIDS[sid]
    rid = get_rid(sid, domain_sid)
    if rid is not None and rid in PRIVILEGED_DOMAIN_RIDS:
        return PRIVILEGED_DOMAIN_RIDS[rid]
    return None


# ============================================================
# PHÂN TÍCH groupType
# ============================================================
def parse_group_type(group_type: Any) -> tuple[str, str]:
    """
    Phân tích giá trị `groupType` (bitmask) thành (scope, kind).

    scope: "Global" | "Domain Local" | "Universal" | "Unknown"
    kind : "Security" | "Distribution"
    """
    try:
        gt = int(group_type or 0)
    except (ValueError, TypeError):
        return "Unknown", "Unknown"

    is_security = bool(gt & 0x80000000)
    kind = "Security" if is_security else "Distribution"

    scope_bit = gt & 0x0F
    scope = {
        0x02: "Global",
        0x04: "Domain Local",
        0x08: "Universal",
    }.get(scope_bit, "Unknown")

    return scope, kind