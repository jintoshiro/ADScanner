"""
Nhóm C — Permissions & ACL Checks.
Thống nhất quy ước: giữ ACE kế thừa (inherited), chỉ bỏ ACE inherit_only (0x08).
"""
from adscanner.checks.base import BaseCheck, Finding, ScanContext, Severity
from adscanner.checks.registry import register
from adscanner.utils.sid import get_domain_sid_from_sid
from adscanner.utils.security_descriptor import default_legit_sids
from adscanner.utils.acl_mapper import classify_ace

CATEGORY = "Permissions & ACL"


def _get_domain_sid(ctx: ScanContext) -> str | None:
    for u in ctx.users:
        if u.sid:
            return get_domain_sid_from_sid(u.sid)
    for g in ctx.groups:
        if g.sid:
            return get_domain_sid_from_sid(g.sid)
    return None


def _build_sid_map(ctx: ScanContext) -> dict[str, str]:
    m = {}
    for u in ctx.users:
        if u.sid:
            m[u.sid] = f"{u.sam} (user)"
    for g in ctx.groups:
        if g.sid:
            m[g.sid] = f"{g.sam} (group)"
    return m


# ============================================================
# C14 — GenericAll
# ============================================================
@register
class CheckC14GenericAll(BaseCheck):
    id = "C14"
    name = "Quyền GenericAll trên object quan trọng"
    category = CATEGORY
    severity = Severity.CRITICAL
    description = (
        "Một principal có quyền GenericAll trên User/Group/OU. "
        "Kẻ tấn công có thể đổi mật khẩu, thêm vào nhóm đặc quyền."
    )
    remediation = "Rà soát và gỡ bỏ ACE GenericAll không cần thiết."

    def _check(self, ctx: ScanContext) -> Finding | None:
        # Kiểm tra trạng thái collector
        if ctx.collection_status.get("acls") != "ok":
            raise RuntimeError("Không thu thập được ACL — cần quyền đọc nTSecurityDescriptor")

        domain_sid = _get_domain_sid(ctx)
        if not domain_sid:
            raise RuntimeError("Không xác định được domain SID")

        legit_sids = default_legit_sids(domain_sid)
        sid_map = _build_sid_map(ctx)

        affected = []
        for dn, acl in ctx.acls.items():
            if acl.target_label == "domain":
                continue
            for ace in acl.aces:
                # Giữ inherited, chỉ bỏ inherit_only
                if ace['type'] in (0x00, 0x05) and not ace['inherit_only']:
                    if ace['sid'] in legit_sids:
                        continue
                    rights = classify_ace(ace, acl.target_label)
                    if 'GenericAll' in rights:
                        affected.append({
                            "object": dn,
                            "trustee": sid_map.get(ace['sid'], ace['sid']),
                            "target_type": acl.target_label,
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
        "WriteOwner cho phép chiếm quyền sở hữu object."
    )
    remediation = "Gỡ bỏ quyền WriteDacl/WriteOwner không cần thiết."

    def _check(self, ctx: ScanContext) -> Finding | None:
        if ctx.collection_status.get("acls") != "ok":
            raise RuntimeError("Không thu thập được ACL")

        domain_sid = _get_domain_sid(ctx)
        if not domain_sid:
            raise RuntimeError("Không xác định được domain SID")

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
                            "rights": " / ".join([r for r in rights if r in ('WriteDacl', 'WriteOwner')]),
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
        "Quyền GenericWrite trên User cho phép thay đổi thuộc tính "
        "(gán SPN để Kerberoasting, bật AS-REP Roasting)."
    )
    remediation = "Gỡ bỏ quyền GenericWrite không cần thiết trên User."

    def _check(self, ctx: ScanContext) -> Finding | None:
        if ctx.collection_status.get("acls") != "ok":
            raise RuntimeError("Không thu thập được ACL")

        domain_sid = _get_domain_sid(ctx)
        if not domain_sid:
            raise RuntimeError("Không xác định được domain SID")

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
                            "trustee": sid_map.get(ace['sid'], ace['sid']),
                        })

        if not affected:
            return None
        return self._make_finding(affected, f"{len(affected)} quyền GenericWrite trên User.")