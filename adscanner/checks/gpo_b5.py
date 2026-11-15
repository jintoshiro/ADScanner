"""
Check B5 — Quyền ghi trên GPO và OU liên kết nhạy cảm.
"""
import re
from collections import defaultdict
from adscanner.checks.base import BaseCheck, Finding, ScanContext, Severity
from adscanner.checks.registry import register
from adscanner.utils.acl_mapper import classify_ace
from adscanner.utils.sid import get_domain_sid_from_sid
from adscanner.utils.security_descriptor import default_legit_sids

CATEGORY = "GPO Audit"

# GUID của thuộc tính gPLink
GUID_GPLINK = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
GPLINK_REGEX = re.compile(r'\[LDAP://(?P<dn>[^;\]]+);(?P<opt>\d+)\]', re.I)
WRITE_RIGHTS = {'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner'}

@register
class CheckB5LooseGPOOnPrivilegedOU(BaseCheck):
    id = "B5"
    name = "Quyền ghi trên GPO hoặc OU liên kết nhạy cảm"
    category = CATEGORY
    severity = Severity.HIGH
    description = (
        "Principal không đặc quyền có quyền ghi trên GPO đang áp dụng cho Domain/DC, "
        "hoặc có quyền ghi thuộc tính gPLink trên OU chứa tài khoản đặc quyền. "
        "Đây là đường tấn công leo thang đặc quyền qua Group Policy."
    )
    remediation = "Rà soát và gỡ bỏ quyền ghi không cần thiết trên GPO/OU."

    def _check(self, ctx: ScanContext) -> Finding | None:
        # 1. Xác định domain SID và các SID hợp lệ
        domain_sid = None
        for u in ctx.users:
            if u.sid:
                domain_sid = get_domain_sid_from_sid(u.sid)
                break
        if not domain_sid:
            return None

        legit_sids = default_legit_sids(domain_sid)
        IGNORED_SIDS = {"S-1-3-0", "S-1-5-18", "S-1-5-11", "S-1-1-0"}
        legit_sids.update(IGNORED_SIDS)

        # 2. Xác định các container nhạy cảm (Domain Root + OU của DC)
        sensitive_containers = {ctx.profile.primary.domain_dn.lower()}
        dc_dn = None
        for c in ctx.computers:
            if c.sam.upper() == "DC01$": # Hoặc dùng primaryGroupID = 516
                dc_dn = c.dn.lower()
                break
        if dc_dn:
            # Thêm OU của DC (cắt bỏ CN=DC01)
            ou_dn = ",".join(dc_dn.split(",")[1:])
            sensitive_containers.add(ou_dn)

        # 3. Map GPO DN -> Các container mà nó được link tới
        # (Cần parse gPLink từ ctx.acls, nhưng hiện tại chưa lưu gPLink vào ObjectACL)
        # Tạm thời chỉ xét các OU nhạy cảm

        affected = []
        for dn, acl in ctx.acls.items():
            # Chỉ xét GPO và OU nhạy cảm
            if acl.target_label not in ("gpo", "ou"):
                continue
            
            # Nếu là OU, chỉ xét nếu nó nằm trong sensitive_containers
            if acl.target_label == "ou" and dn.lower() not in sensitive_containers:
                continue
            
            for ace in acl.aces:
                if ace['type'] not in (0x00, 0x05) or ace['inherited']:
                    continue
                if ace['sid'] in legit_sids:
                    continue
                
                rights = set(classify_ace(ace, acl.target_label))
                
                # Kiểm tra quyền ghi GPO
                if acl.target_label == "gpo" and (rights & WRITE_RIGHTS):
                    affected.append({
                        "type": "GPO_WRITE",
                        "target": dn,
                        "trustee": ace['sid'],
                        "rights": list(rights & WRITE_RIGHTS),
                    })
                
                # Kiểm tra quyền ghi gPLink trên OU
                if acl.target_label == "ou":
                    writes_gplink = (ace['mask'] & 0x20) and ace.get('object_type') in (None, GUID_GPLINK)
                    if (rights & WRITE_RIGHTS) or writes_gplink:
                        affected.append({
                            "type": "GPLINK_WRITE",
                            "target": dn,
                            "trustee": ace['sid'],
                            "rights": list(rights & WRITE_RIGHTS) or ["WriteProperty(gPLink)"],
                        })

        if not affected:
            return None
        
        severity = Severity.CRITICAL if any(a["target"].lower() == ctx.profile.primary.domain_dn.lower() for a in affected) else self.severity
        summary = f"{len(affected)} quyền ghi bất thường trên GPO/OU nhạy cảm."
        return self._make_finding(affected, summary, severity=severity)