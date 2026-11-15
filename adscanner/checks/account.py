"""
Nhóm A — Account Security Checks.
"""
from datetime import datetime, timezone
from adscanner.checks.base import BaseCheck, Finding, ScanContext, Severity
from adscanner.checks.registry import register
from adscanner.utils.sid import get_domain_sid_from_sid
from adscanner.utils.security_descriptor import default_legit_sids

CATEGORY = "Account Security"
INACTIVE_DAYS_THRESHOLD = 90

# Tài khoản hệ thống được whitelist (false positive đã biết)
_WHITELIST_SAM = {"krbtgt"}

def _build_privileged_map(groups) -> dict[str, str]:
    return {g.dn: g.privileged_match for g in groups if g.is_privileged}

def _privileged_memberships(user, priv_map: dict[str, str]) -> list[str]:
    result = []
    for group_dn in user.member_of:
        name = priv_map.get(group_dn)
        if name:
            result.append(name)
    return result

# ============================================================
# A1 — Mật khẩu không bao giờ hết hạn
# ============================================================
@register
class CheckA1PasswordNeverExpires(BaseCheck):
    id = "A1"
    name = "Mật khẩu không bao giờ hết hạn"
    category = CATEGORY
    severity = Severity.HIGH
    description = (
        "Tài khoản được cấu hình DONT_EXPIRE_PASSWORD. Nếu mật khẩu bị lộ "
        "(qua breach, phishing, hoặc dump LSASS), kẻ tấn công có thể dùng "
        "vĩnh viễn mà không bị buộc đổi."
    )
    remediation = (
        "Gỡ cờ 'Password never expires' trong ADUC, hoặc chạy: "
        "Set-ADUser -Identity <user> -PasswordNeverExpires $false. "
        "Áp dụng chính sách xoay vòng mật khẩu cho service account."
    )

    def _check(self, ctx: ScanContext) -> Finding | None:
        affected = []
        for u in ctx.users:
            if not u.dont_expire_password:
                continue
            affected.append({
                "sam": u.sam,
                "dn": u.dn,
                "disabled": u.disabled,
                "pwd_age_days": u.pwd_age_days,
                "admin_count": u.admin_count,
            })

        if not affected:
            return None

        all_disabled = all(a["disabled"] for a in affected)
        severity = Severity.MEDIUM if all_disabled else self.severity
        enabled_count = sum(1 for a in affected if not a["disabled"])
        summary = (
            f"{len(affected)} tài khoản có DONT_EXPIRE_PASSWORD "
            f"({enabled_count} đang enabled, {len(affected) - enabled_count} disabled)"
        )
        return self._make_finding(affected, summary, severity=severity)


# ============================================================
# A2 — Tài khoản không yêu cầu mật khẩu
# ============================================================
@register
class CheckA2PasswordNotRequired(BaseCheck):
    id = "A2"
    name = "Tài khoản không yêu cầu mật khẩu"
    category = CATEGORY
    severity = Severity.CRITICAL
    description = (
        "Tài khoản có cờ PASSWD_NOTREQD, cho phép đăng nhập bằng mật khẩu "
        "rỗng. Đây là lỗ hổng nghiêm trọng — kẻ tấn công có thể đăng nhập "
        "mà không cần biết mật khẩu."
    )
    remediation = (
        "Gỡ cờ PASSWD_NOTREQD: Set-ADAccountControl -Identity <user> "
        "-PasswordNotRequired $false. Đồng thời enforce password policy "
        "ở domain level."
    )

    def _check(self, ctx: ScanContext) -> Finding | None:
        affected = [
            {
                "sam": u.sam,
                "dn": u.dn,
                "disabled": u.disabled,
                "admin_count": u.admin_count,
            }
            for u in ctx.users
            if u.password_not_required
        ]
        if not affected:
            return None
        enabled = [a for a in affected if not a["disabled"]]
        summary = (
            f"{len(affected)} tài khoản có PASSWD_NOTREQD "
            f"({len(enabled)} đang enabled)"
        )
        return self._make_finding(affected, summary)


# ============================================================
# A3 — Tài khoản disabled nhưng vẫn trong nhóm đặc quyền
# ============================================================
@register
class CheckA3DisabledInPrivilegedGroup(BaseCheck):
    id = "A3"
    name = "Tài khoản disabled còn trong nhóm đặc quyền"
    category = CATEGORY
    severity = Severity.MEDIUM
    description = (
        "Tài khoản đã bị vô hiệu hóa nhưng vẫn là thành viên của nhóm đặc "
        "quyền (Domain Admins, Enterprise Admins, Administrators...). Nếu "
        "kẻ tấn công có quyền Domain Admin và bật lại tài khoản này, chúng "
        "ngay lập tức có đặc quyền. Đây là tàn dư cấu hình nguy hiểm."
    )
    remediation = (
        "Gỡ tài khoản khỏi tất cả nhóm đặc quyền: "
        "Remove-ADGroupMember -Identity 'Domain Admins' -Members <user>. "
        "Nếu cần giữ lịch sử, ghi lại rồi xóa hẳn tài khoản sau thời gian "
        "grace. Áp dụng quy trình offboarding chuẩn."
    )

    def _check(self, ctx: ScanContext) -> Finding | None:
        if not ctx.groups:
            return None
        priv_map = _build_privileged_map(ctx.groups)
        if not priv_map:
            return None

        affected = []
        for u in ctx.users:
            if not u.disabled:
                continue
            if u.sam.lower() in _WHITELIST_SAM:
                continue
            priv_groups = _privileged_memberships(u, priv_map)
            if not priv_groups:
                continue
            affected.append({
                "sam": u.sam,
                "dn": u.dn,
                "privileged_groups": priv_groups,
                "pwd_age_days": u.pwd_age_days,
            })

        if not affected:
            return None
        summary = f"{len(affected)} tài khoản disabled vẫn ở trong nhóm đặc quyền"
        return self._make_finding(affected, summary)


# ============================================================
# A5 — Service account dễ bị Kerberoasting
# ============================================================
@register
class CheckA5Kerberoastable(BaseCheck):
    id = "A5"
    name = "Service account có thể bị Kerberoasting"
    category = CATEGORY
    severity = Severity.HIGH
    description = (
        "Tài khoản có ServicePrincipalName (SPN) và đang enabled. "
        "Bất kỳ user nào trong domain cũng có thể yêu cầu TGS cho SPN này "
        "và crack offline để lấy mật khẩu. Đặc biệt nguy hiểm nếu account "
        "có quyền cao (adminCount=1) hoặc mật khẩu yếu."
    )
    remediation = (
        "Với service account: dùng Group Managed Service Account (gMSA) "
        "thay vì user account. Nếu buộc phải dùng, đặt mật khẩu dài (>25 ký tự) "
        "và xoay vòng định kỳ. Với user thường có SPN: gỡ SPN nếu không cần."
    )

    def _check(self, ctx: ScanContext) -> Finding | None:
        affected = []
        for u in ctx.users:
            if not u.spn:
                continue
            if u.disabled:
                continue
            affected.append({
                "sam": u.sam,
                "dn": u.dn,
                "spn": u.spn,
                "admin_count": u.admin_count,
                "pwd_age_days": u.pwd_age_days,
                "is_admin": u.is_admin_count_set,
            })

        if not affected:
            return None
        admin_accounts = [a for a in affected if a["is_admin"]]
        summary = (
            f"{len(affected)} tài khoản có SPN và đang enabled "
            f"({len(admin_accounts)} có adminCount=1)"
        )
        severity = Severity.CRITICAL if admin_accounts else self.severity
        return self._make_finding(affected, summary, severity=severity)


# ============================================================
# A6 — adminCount=1 nhưng KHÔNG ở nhóm đặc quyền
# ============================================================
@register
class CheckA6StaleAdminCount(BaseCheck):
    id = "A6"
    name = "adminCount=1 nhưng không còn trong nhóm admin"
    category = CATEGORY
    severity = Severity.MEDIUM
    description = (
        "Tài khoản có adminCount=1 (dấu hiệu từng được AdminSDHolder bảo vệ) "
        "nhưng hiện KHÔNG thuộc bất kỳ nhóm đặc quyền nào. Đây là cấu hình "
        "tàn dư — có thể gây nhầm lẫn, hoặc tệ hơn: nếu kẻ tấn công thêm "
        "user vào một nhóm admin bất kỳ, chúng sẽ không cần thêm bước nào "
        "để có quyền cao."
    )
    remediation = (
        "Xóa cờ adminCount: Set-ADUser -Identity <user> -Clear adminCount. "
        "Hoặc chạy script chuẩn hóa AdminSDHolder. Kiểm tra lịch sử xem "
        "tài khoản từng ở nhóm nào để có quyết định đúng."
    )

    def _check(self, ctx: ScanContext) -> Finding | None:
        if not ctx.groups:
            return None
        priv_map = _build_privileged_map(ctx.groups)
        if not priv_map:
            return None

        affected = []
        for u in ctx.users:
            if not u.is_admin_count_set:
                continue
            if u.disabled:
                continue
            if u.sam.lower() in _WHITELIST_SAM:
                continue
            priv_groups = _privileged_memberships(u, priv_map)
            if priv_groups:
                continue
            affected.append({
                "sam": u.sam,
                "dn": u.dn,
                "member_of_count": len(u.member_of),
                "pwd_age_days": u.pwd_age_days,
            })

        if not affected:
            return None
        summary = (
            f"{len(affected)} tài khoản có adminCount=1 nhưng không ở nhóm "
            f"đặc quyền nào (adminCount là tàn dư)"
        )
        return self._make_finding(affected, summary)


# ============================================================
# A7 — Tài khoản không hoạt động > 90 ngày
# ============================================================
@register
class CheckA7InactiveAccounts(BaseCheck):
    id = "A7"
    name = f"Tài khoản không hoạt động > {INACTIVE_DAYS_THRESHOLD} ngày"
    category = CATEGORY
    severity = Severity.MEDIUM
    description = (
        f"Tài khoản enabled nhưng không đăng nhập trong hơn "
        f"{INACTIVE_DAYS_THRESHOLD} ngày. Đây là bề mặt tấn công không cần thiết "
        "— nếu bị compromise, khó phát hiện vì ít traffic bất thường."
    )
    remediation = (
        "Vô hiệu hóa tài khoản không dùng: Disable-ADAccount -Identity <user>. "
        "Sau thời gian grace (ví dụ 30 ngày), xóa hẳn. Áp dụng quy trình "
        "review tài khoản định kỳ (quarterly access review)."
    )

    def _check(self, ctx: ScanContext) -> Finding | None:
        affected = []
        for u in ctx.users:
            if u.disabled:
                continue
            
            # Logic mới: Dùng whenCreated làm fallback nếu chưa từng login
            age = u.last_logon_age_days
            if age is None and u.when_created:
                try:
                    dt = datetime.strptime(u.when_created[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
                    age = (datetime.now(timezone.utc) - dt).days
                except Exception:
                    pass

            if age is not None and age > INACTIVE_DAYS_THRESHOLD:
                affected.append({
                    "sam": u.sam,
                    "dn": u.dn,
                    "last_logon_age_days": age,
                    "admin_count": u.admin_count,
                    "has_spn": bool(u.spn),
                })

        if not affected:
            return None
        affected.sort(key=lambda a: a["last_logon_age_days"], reverse=True)
        oldest = affected[0]["last_logon_age_days"]
        summary = (
            f"{len(affected)} tài khoản enabled không đăng nhập > "
            f"{INACTIVE_DAYS_THRESHOLD} ngày (lâu nhất: {oldest} ngày)"
        )
        return self._make_finding(affected, summary)


# ============================================================
# ============================================================
# A8 — Tài khoản có quyền DCSync
# ============================================================
from adscanner.utils.security_descriptor import find_dcsync_trustees, default_legit_sids

@register
class CheckA8DCSyncRights(BaseCheck):
    id = "A8"
    name = "Tài khoản có quyền DCSync"
    category = CATEGORY
    severity = Severity.CRITICAL
    description = (
        "Một hoặc nhiều principal có quyền DCSync (DS-Replication-Get-Changes "
        "và/hoặc DS-Replication-Get-Changes-All) trên Domain object. Đây là "
        "quyền cho phép mô phỏng Domain Controller và dump toàn bộ hash NTLM "
        "của mọi user (bao gồm krbtgt) → chiếm toàn bộ domain."
    )
    remediation = (
        "Gỡ ACE cấp DCSync: mở ADSI Edit, tới domain object, "
        "Security → Advanced → xóa ACE có extended right "
        "'Replicating Directory Changes All'. Chỉ giữ lại cho "
        "Domain Controllers và System."
    )

    def _check(self, ctx: ScanContext) -> Finding | None:
        # 1. Tìm ObjectACL có target_label là "domain"
        domain_acl = next((acl for acl in ctx.acls.values() if acl.target_label == "domain"), None)
        if domain_acl is None:
            return None

        # 2. Lấy domain SID
        domain_sid = None
        for u in ctx.users:
            if u.sid: domain_sid = get_domain_sid_from_sid(u.sid); break
        if domain_sid is None:
            for g in ctx.groups:
                if g.sid: domain_sid = get_domain_sid_from_sid(g.sid); break
        
        if not domain_sid:
            return None

        # 3. Tìm các SID có đủ quyền DCSync (dùng hàm từ security_descriptor.py)
        trustees = find_dcsync_trustees(domain_acl.aces)
        legit_sids = default_legit_sids(domain_sid)
        
        # 4. Lọc ra các SID đáng ngờ (không nằm trong danh sách hợp lệ)
        suspicious = {sid: rights for sid, rights in trustees.items() if sid not in legit_sids}

        if not suspicious:
            return None

        # 5. Build map SID -> Tên để báo cáo dễ đọc
        sid_to_name = {}
        for u in ctx.users:
            if u.sid: sid_to_name[u.sid] = f"{u.sam} (user)"
        for g in ctx.groups:
            if g.sid: sid_to_name[g.sid] = f"{g.sam} (group)"

        affected = []
        for sid, rights in suspicious.items():
            affected.append({
                "trustee_sid": sid,
                "trustee_name": sid_to_name.get(sid, "Unknown"),
                "rights": list(rights)
            })

        summary = f"{len(affected)} principal KHÔNG MẶC ĐỊNH có quyền DCSync trên domain"
        return self._make_finding(affected, summary)
# ============================================================
# A9 — Tuổi mật khẩu krbtgt (Golden Ticket)
# ============================================================
@register
class CheckA9KrbtgtPasswordAge(BaseCheck):
    id = "A9"
    name = "Tuổi mật khẩu krbtgt quá cũ"
    category = CATEGORY
    severity = Severity.CRITICAL
    description = (
        "Mật khẩu tài khoản krbtgt không được đổi trong hơn 180 ngày. "
        "Nếu kẻ tấn công có được hash của krbtgt, chúng có thể tạo Golden Ticket "
        "để giả mạo bất kỳ user nào và tồn tại vĩnh viễn trong domain."
    )
    remediation = "Đổi mật khẩu krbtgt 2 lần liên tiếp (cách nhau ít nhất 10 giờ) để vô hiệu hóa các vé cũ."

    def _check(self, ctx: ScanContext) -> Finding | None:
        for u in ctx.users:
            if u.sam.lower() == "krbtgt":
                if u.pwd_age_days and u.pwd_age_days > 180:
                    return self._make_finding([{
                        "sam": "krbtgt",
                        "pwd_age_days": u.pwd_age_days
                    }], f"Mật khẩu krbtgt đã {u.pwd_age_days} ngày không đổi.")
        return None