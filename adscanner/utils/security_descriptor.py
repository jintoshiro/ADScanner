"""
Tiện ích parse và phân tích Windows Security Descriptor.
Sử dụng impacket (ldaptypes). Dựa trên cấu trúc Structure.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from impacket.ldap import ldaptypes

logger = logging.getLogger(__name__)

# ============================================================
# Hằng số ACE Types và Flags
# ============================================================
ACE_ACCESS_ALLOWED        = 0x00
ACE_ACCESS_DENIED         = 0x01
ACE_ACCESS_ALLOWED_OBJECT = 0x05
ACE_ACCESS_DENIED_OBJECT  = 0x06

INHERIT_ONLY_ACE = 0x08
INHERITED_ACE    = 0x10

# ============================================================
# GUID Extended Rights
# ============================================================
GUID_DS_REPLICATION_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPLICATION_GET_CHANGES     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"

# Quyền mở rộng
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
GENERIC_ALL                 = 0x10000000


def _guid_to_str(raw: Any) -> Optional[str]:
    """16 byte little-endian -> chuỗi GUID chữ thường; rỗng/không hợp lệ -> None."""
    if not raw:
        return None
    raw = bytes(raw)
    if len(raw) != 16:
        return None
    return str(uuid.UUID(bytes_le=raw))


def _mask_to_int(mask_field: Any) -> int:
    """ACCESS_MASK là Structure có field 'Mask'; trả về int."""
    try:
        return int(mask_field['Mask'])
    except (TypeError, KeyError):
        return int(mask_field)


def extract_aces(raw_sd: Any) -> list[dict[str, Any]]:
    """Parse SD và trích xuất danh sách ACE dưới dạng dict phẳng."""
    if not raw_sd:
        return []
    if isinstance(raw_sd, list):
        raw_sd = raw_sd[0]

    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(raw_sd))
    except Exception as e:
        logger.warning("Không parse được SecurityDescriptor: %s", e)
        return []

    # Nếu SD không có DACL, impacket để b'' thay vì object ACL
    try:
        dacl = sd['Dacl']
        aces = getattr(dacl, 'aces', None)
        if not aces:
            return []
    except KeyError:
        return []

    result = []
    for ace in aces:
        try:
            ace_type = int(ace['AceType'])
            ace_flags = int(ace['AceFlags'])
            body = ace['Ace']

            # Với loại ACE impacket không hỗ trợ, body chỉ là bytes thô -> bỏ qua
            fields = getattr(body, 'fields', None)
            if not isinstance(fields, dict) or 'Mask' not in fields or 'Sid' not in fields:
                continue

            result.append({
                'type':        ace_type,
                'flags':       ace_flags,
                'inherited':   bool(ace_flags & INHERITED_ACE),
                'inherit_only': bool(ace_flags & INHERIT_ONLY_ACE),
                'mask':        _mask_to_int(fields['Mask']),
                'sid':         fields['Sid'].formatCanonical(),
                'object_type': _guid_to_str(fields.get('ObjectType')),
                'inherited_object_type': _guid_to_str(fields.get('InheritedObjectType')),
            })
        except Exception as e:
            logger.debug("Lỗi parse ACE: %s", e)
            continue

    return result


# ============================================================
# Logic tìm DCSync
# ============================================================
def _grants_extended_right(ace: dict, guid: str) -> bool:
    if ace['type'] not in (ACE_ACCESS_ALLOWED, ACE_ACCESS_ALLOWED_OBJECT):
        return False
    if ace['inherit_only']:
        return False
    if not ace['mask'] & (ADS_RIGHT_DS_CONTROL_ACCESS | GENERIC_ALL):
        return False
    return ace['object_type'] in (None, guid)


def find_dcsync_trustees(aces: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Trả về {sid: {'GetChanges', 'GetChangesAll'}} cho SID có đủ cả hai quyền."""
    rights = {}
    for ace in aces:
        if _grants_extended_right(ace, GUID_DS_REPLICATION_GET_CHANGES):
            rights.setdefault(ace['sid'], set()).add('GetChanges')
        if _grants_extended_right(ace, GUID_DS_REPLICATION_GET_CHANGES_ALL):
            rights.setdefault(ace['sid'], set()).add('GetChangesAll')
    
    # Lọc những SID có ĐỦ CẢ HAI
    return {sid: r for sid, r in rights.items() if r >= {'GetChanges', 'GetChangesAll'}}


def default_legit_sids(domain_sid: str) -> set[str]:
    """Danh sách các SID mặc định có quyền quản trị trong AD."""
    return {
        'S-1-5-18',            # SYSTEM
        'S-1-5-32-544',        # Administrators
        'S-1-5-32-548',        # Account Operators (Mặc định có WriteDacl trên User/Group)
        'S-1-5-32-549',        # Server Operators
        'S-1-5-32-550',        # Print Operators
        'S-1-5-32-551',        # Backup Operators
        'S-1-5-32-552',        # Replicators
        'S-1-5-9',             # Enterprise Domain Controllers
        f'{domain_sid}-500',   # Administrator (tài khoản gốc)
        f'{domain_sid}-512',   # Domain Admins
        f'{domain_sid}-516',   # Domain Controllers
        f'{domain_sid}-519',   # Enterprise Admins
        f'{domain_sid}-526',   # Key Admins
        f'{domain_sid}-527',   # Enterprise Key Admins
    }
# ============================================================
# Helpers cũ (giữ lại cho tương thích)
# ============================================================
def find_aces_for_guid(aces: list[dict[str, Any]], guid: str) -> list[dict[str, Any]]:
    target = guid.lower()
    return [a for a in aces if a.get("object_type") == target]

def find_dcsync_aces(aces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Hàm cũ, không dùng nữa nhưng giữ lại để không lỗi import
    return [a for a in aces if a.get("object_type") in (GUID_DS_REPLICATION_GET_CHANGES, GUID_DS_REPLICATION_GET_CHANGES_ALL)]

def get_sd_owner(raw_sd: Any) -> str | None:
    if not raw_sd: return None
    if isinstance(raw_sd, list): raw_sd = raw_sd[0]
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(raw_sd))
        owner = sd['Owner']
        if owner and hasattr(owner, "formatCanonical"):
            return owner.formatCanonical()
    except Exception:
        pass
    return None