"""
Nhóm F — Trust & Forest Checks.
"""
from adscanner.checks.base import BaseCheck, Finding, ScanContext, Severity
from adscanner.checks.registry import register

CATEGORY = "Trust & Forest"

@register
class CheckF1TrustSIDFiltering(BaseCheck):
    id = "F1"
    name = "Domain Trust thiếu SID Filtering"
    category = CATEGORY
    severity = Severity.HIGH
    description = (
        "Domain có trust với bên ngoài nhưng không bật SID Filtering. "
        "Kẻ tấn công từ domain đối tác có thể chèn SID của Domain Admins "
        "vào token để chiếm quyền."
    )
    remediation = "Bật SID Filtering: netdom trust <domain> /quarantine:yes"

    def _check(self, ctx: ScanContext) -> Finding | None:
        # Lấy dữ liệu trusts từ Context (sẽ được thu thập bên dưới)
        trusts = getattr(ctx, "trusts", [])
        affected = []
        
        for t in trusts:
            # 0x4 = TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL (SID filtering)
            # Nếu bit này không được bật, trust đó đang nguy hiểm
            if not (t.get("trust_attributes", 0) & 0x4):
                affected.append({
                    "trust_name": t.get("name"),
                    "direction": t.get("direction")
                })
        
        if not affected:
            return None
        return self._make_finding(affected, f"{len(affected)} trust không có SID Filtering.")

@register
class CheckF2SIDHistory(BaseCheck):
    id = "F2"
    name = "SID History Injection"
    category = "Trust & Forest"
    severity = Severity.CRITICAL
    description = "Tài khoản chứa SID History - dấu hiệu bị chèn SID của Domain Admins hoặc SID từ domain khác để leo thang đặc quyền."
    remediation = "Xóa SID History không cần thiết: Set-ADUser -Identity <user> -Clear sIDHistory."

    def _check(self, ctx: ScanContext) -> Finding | None:
        affected = []
        for u in ctx.users:
            if u.sid_history:
                affected.append({"sam": u.sam, "sid_history": u.sid_history})
        if not affected: return None
        return self._make_finding(affected, f"{len(affected)} tài khoản có SID History.")