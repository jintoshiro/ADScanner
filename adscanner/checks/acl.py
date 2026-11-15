"""
Nhóm C — Permissions & ACL Checks.
"""
from adscanner.checks.base import BaseCheck, Finding, ScanContext, Severity
from adscanner.checks.registry import register
from adscanner.utils.sid import get_domain_sid_from_sid
from adscanner.utils.security_descriptor import default_legit_sids
from adscanner.utils.acl_mapper import classify_ace

CATEGORY = "Permissions & ACL"


def _get_domain_sid(ctx: ScanContext) -> str | None:
    """Lấy SID của domain từ danh sách users hoặc groups."""
    for u in ctx.users:
        if u.sid:
            return get_domain_sid_from_sid(u.sid)
    for g in ctx.groups:
        if g.sid:
            return get_domain_sid_from_sid(g.sid)
    return None


def _build_sid_map(ctx: ScanContext) -> dict[str, str]:
    """Map SID -> Tên hiển thị (User/Group) để báo cáo dễ đọc."""
    m = {}
    for u in ctx.users:
        if u.sid:
            m[u.sid] = f"{u.sam} (user)"
    for g in ctx.groups:
        if g.sid:
            m[g.sid] = f"{g.sam} (group)"
    return m


# ============================================================
# C14 — GenericAll trên object quan trọng
# ============================================================
@register
class CheckC14GenericAll(BaseCheck):
    id = "C14"
    name = "Quyền GenericAll trên object quan trọng"
    category = CATEGORY
    severity = Severity.CRITICAL
    description = (
        "Một principal có quyền GenericAll (Toàn quyền/Full Control) trên User/Group. "
        "Kẻ tấn công có thể đổi mật khẩu, thêm vào nhóm đặc quyền, hoặc thực thi "
        "mọi hành động. Đây là đường tấn công phổ biến nhất (BloodHound)."
    )
    remediation = "Rà soát và gỡ bỏ ACE GenericAll không cần thiết trên object."

    def _check(self, ctx: ScanContext) -> Finding | None:
        domain_sid = _get_domain_sid(ctx)
        if not domain_sid:
            return None

        legit_sids = default_legit_sids(domain_sid)
        sid_map = _build_sid_map(ctx)

        affected = []
        for dn, acl in ctx.acls.items():
            # Bỏ qua Domain object vì DCSync (A8) và Attack Path (G1) đã xử lý
            if acl.target_label == "domain":
                continue

            for ace in acl.aces:
                # Chỉ xét ACE Allow (type 0, 5) và không phải Inherit-Only
             if ace['type'] in (0x00, 0x05) and not (ace['flags'] & 0x10): # Chỉ bỏ ACE bị kế thừa (0x10)
                    if ace['sid'] in legit_sids:
                        continue

                    # Sử dụng hàm phân loại chuẩn xác
                    rights = classify_ace(ace, acl.target_label)
                    
                    if 'GenericAll' in rights:
                        affected.append({
                            "object": dn,
                            "trustee": sid_map.get(ace['sid'], ace['sid']),
                            "target_type": acl.target_label
                        })

        if not affected:
            return None
        return self._make_finding(affected, f"{len(affected)} quyền GenericAll bất thường.")


# ============================================================
# C15 — WriteDacl / WriteOwner
# ============================================================
@register
class CheckC15WriteDaclOwner(BaseCheck):
    id = "C15"
    name = "Quyền WriteDacl / WriteOwner"
    category = CATEGORY
    severity = Severity.HIGH
    description = (
        "Quyền WriteDacl cho phép thay đổi ACL (tự cấp quyền GenericAll). "
        "WriteOwner cho phép chiếm quyền sở hữu object. Cả hai đều dẫn đến chiếm đoạt object."
    )
    remediation = "Gỡ bỏ quyền WriteDacl/WriteOwner không cần thiết."

    def _check(self, ctx: ScanContext) -> Finding | None:
        domain_sid = _get_domain_sid(ctx)
        if not domain_sid:
            return None

        legit_sids = default_legit_sids(domain_sid)
        sid_map = _build_sid_map(ctx)

        affected = []
        for dn, acl in ctx.acls.items():
            for ace in acl.aces:
                if ace['type'] in (0x00, 0x05) and not ace['inherit_only']:
                    if ace['sid'] in legit_sids:
                        continue

                    rights = classify_ace(ace, acl.target_label)
                    
                    if 'WriteDacl' in rights or 'WriteOwner' in rights:
                        affected.append({
                            "object": dn,
                            "trustee": sid_map.get(ace['sid'], ace['sid']),
                            "rights": " / ".join([r for r in rights if r in ('WriteDacl', 'WriteOwner')])
                        })

        if not affected:
            return None
        return self._make_finding(affected, f"{len(affected)} quyền WriteDacl/Owner bất thường.")


# ============================================================
# C16 — GenericWrite trên User
# ============================================================
@register
class CheckC16GenericWriteUser(BaseCheck):
    id = "C16"
    name = "Quyền GenericWrite trên User"
    category = CATEGORY
    severity = Severity.HIGH
    description = (
        "Quyền GenericWrite trên User cho phép kẻ tấn công thay đổi thuộc tính "
        "(ví dụ: gán SPN để Kerberoasting, hoặc bật AS-REP Roasting) mà không cần mật khẩu."
    )
    remediation = "Gỡ bỏ quyền GenericWrite không cần thiết trên User."

    def _check(self, ctx: ScanContext) -> Finding | None:
        domain_sid = _get_domain_sid(ctx)
        if not domain_sid:
            return None

        legit_sids = default_legit_sids(domain_sid)
        sid_map = _build_sid_map(ctx)

        affected = []
        for dn, acl in ctx.acls.items():
            if acl.target_label != "user":
                continue

            for ace in acl.aces:
                if ace['type'] in (0x00, 0x05) and not ace['inherit_only']:
                    if ace['sid'] in legit_sids:
                        continue

                    rights = classify_ace(ace, acl.target_label)
                    
                    if 'GenericWrite' in rights:
                        affected.append({
                            "object": dn,
                            "trustee": sid_map.get(ace['sid'], ace['sid'])
                        })

        if not affected:
            return None
        return self._make_finding(affected, f"{len(affected)} quyền GenericWrite trên User.")