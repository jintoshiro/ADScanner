"""
Nhóm E — Kerberos Checks.
"""
from adscanner.checks.base import BaseCheck, Finding, ScanContext, Severity
from adscanner.checks.registry import register
from adscanner.utils.security_descriptor import extract_aces

CATEGORY = "Kerberos"


# ============================================================
# E1 — Unconstrained Delegation
# ============================================================
@register
class CheckE1UnconstrainedDelegation(BaseCheck):
    id = "E1"
    name = "Unconstrained Delegation"
    category = CATEGORY
    severity = Severity.CRITICAL
    description = (
        "Tài khoản/máy tính được cấu hình Unconstrained Delegation. "
        "Kẻ tấn công chiếm được object này có thể đánh cắp TGT của Domain Admin."
    )
    remediation = "Tắt Unconstrained Delegation: Set-ADAccountControl -Identity <account> -TrustedForDelegation $false."

    def _check(self, ctx: ScanContext) -> Finding | None:
        affected = []
        # Quét Users
        for u in ctx.users:
            if u.uac_flags.get("TRUSTED_FOR_DELEGATION") and not u.disabled:
                affected.append({"sam": u.sam, "dn": u.dn, "type": "User"})
        
        # Quét Computers (loại trừ Domain Controller)
        for c in ctx.computers:
            if not c.is_unconstrained or c.disabled:
                continue
            # Loại trừ DC: primaryGroupID 516 (Domain Controllers) hoặc UAC 0x2000
            if getattr(c, 'primary_group_id', None) == 516:
                continue
            if hasattr(c, 'uac_raw') and (c.uac_raw & 0x2000):
                continue
            affected.append({"sam": c.sam, "dn": c.dn, "type": "Computer"})
        
        if not affected: return None
        return self._make_finding(affected, f"{len(affected)} object được bật Unconstrained Delegation.")


# ============================================================
# E2 — Constrained Delegation
# ============================================================
@register
class CheckE2ConstrainedDelegation(BaseCheck):
    id = "E2"
    name = "Constrained Delegation"
    category = CATEGORY
    severity = Severity.HIGH
    description = (
        "Tài khoản được cấu hình Constrained Delegation (msDS-AllowedToDelegateTo). "
        "Kẻ tấn công chiếm được tài khoản có thể mạo danh user khác để truy cập dịch vụ."
    )
    remediation = "Rà soát msDS-AllowedToDelegateTo. Đảm bảo tài khoản có mật khẩu mạnh."

    def _check(self, ctx: ScanContext) -> Finding | None:
        affected = []
        for u in ctx.users:
            if u.allowed_to_delegate_to and not u.disabled:
                affected.append({
                    "sam": u.sam,
                    "dn": u.dn,
                    "targets": u.allowed_to_delegate_to,
                    "admin_count": u.admin_count
                })

        if not affected: return None
        return self._make_finding(affected, f"{len(affected)} tài khoản có Constrained Delegation.")


# ============================================================
# E3 — Resource-Based Constrained Delegation (RBCD)
# ============================================================
@register
class CheckE3RBCD(BaseCheck):
    id = "E3"
    name = "Resource-Based Constrained Delegation (RBCD)"
    category = CATEGORY
    severity = Severity.HIGH
    description = (
        "Tài khoản/máy tính được cấu hình RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity). "
        "Kẻ tấn công có thể mạo danh bất kỳ ai để chiếm quyền Admin trên máy bị ảnh hưởng."
    )
    remediation = "Gỡ bỏ cấu hình RBCD nếu không cần thiết."

    def _check(self, ctx: ScanContext) -> Finding | None:
        affected = []
        
        # Build map SID -> tên
        sid_map = {}
        for u in ctx.users:
            if u.sid: sid_map[u.sid] = f"{u.sam} (user)"
        for g in ctx.groups:
            if g.sid: sid_map[g.sid] = f"{g.sam} (group)"

        # Đọc dữ liệu RBCD từ ctx.computers (thay vì ctx.rbcd_objects)
        for c in ctx.computers:
            # Kiểm tra an toàn: computer phải có thuộc tính rbcd_raw và khác rỗng
            if not hasattr(c, 'rbcd_raw') or not c.rbcd_raw:
                continue
            
            # Parse binary SD của thuộc tính RBCD
            aces = extract_aces(c.rbcd_raw)
            
            # Lấy các SID trong ACE Allow (type 0)
            allowed_sids = [ace['sid'] for ace in aces if ace['type'] == 0x00]
            if not allowed_sids:
                continue
                
            allowed_names = [sid_map.get(s, s) for s in allowed_sids]
            
            # Nâng mức độ nghiêm trọng nếu object là Domain Controller
            is_dc = getattr(c, 'primary_group_id', None) == 516
            severity = Severity.CRITICAL if is_dc else self.severity
            
            affected.append({
                "resource": c.sam,
                "dn": c.dn,
                "is_dc": is_dc,
                "allowed_principals": allowed_names
            })

        if not affected:
            return None
        
        # Nếu có bất kỳ DC nào bị RBCD, check tổng thể là CRITICAL
        is_critical = any(a['is_dc'] for a in affected)
        sev = Severity.CRITICAL if is_critical else self.severity
        
        summary = f"{len(affected)} object có cấu hình RBCD."
        return self._make_finding(affected, summary, severity=sev)


# ============================================================
# E4 — AS-REP Roasting
# ============================================================
@register
class CheckE4ASREPRoastable(BaseCheck):
    id = "E4"
    name = "Tài khoản có thể bị AS-REP Roasting"
    category = CATEGORY
    severity = Severity.HIGH
    description = (
        "Tài khoản bật cờ DONT_REQ_PREAUTH, cho phép kẻ tấn công request AS-REP "
        "và crack offline mà không cần xác thực trước."
    )
    remediation = "Bật Kerberos preauthentication cho tài khoản."

    def _check(self, ctx: ScanContext) -> Finding | None:
        affected = []
        for u in ctx.users:
            if u.is_asrep_roastable and not u.disabled:
                affected.append({"sam": u.sam, "dn": u.dn})
        if not affected: return None
        return self._make_finding(affected, f"{len(affected)} tài khoản có thể bị AS-REP Roasting.")