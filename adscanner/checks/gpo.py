from adscanner.checks.base import BaseCheck, Finding, ScanContext, Severity
from adscanner.checks.registry import register

CATEGORY = "GPO Audit"

@register
class CheckB1NTLMv1(BaseCheck):
    id = "B1"
    name = "GPO cho phép giao thức NTLMv1/LM"
    category = CATEGORY
    severity = Severity.HIGH
    description = "GPO cấu hình LmCompatibilityLevel < 3, cho phép client sử dụng NTLMv1 (dễ bị crack/relay)."
    remediation = "Đặt LmCompatibilityLevel = 5 trong GPO Security Options."

    def _check(self, ctx: ScanContext) -> Finding | None:
        affected = []
        for g in ctx.gpos:
            if g.get("vulnerable_ntlm"):
                affected.append({"gpo_name": g["name"]})
        if not affected: return None
        return self._make_finding(affected, f"{len(affected)} GPO cho phép NTLMv1.")

@register
class CheckB2PasswordPolicy(BaseCheck):
    id = "B2"
    name = "GPO không enforce password policy mạnh"
    category = CATEGORY
    severity = Severity.MEDIUM
    description = "Default Domain Policy không yêu cầu độ phức tạp mật khẩu hoặc độ dài tối thiểu quá thấp."
    remediation = "Bật 'Password must meet complexity requirements' và đặt Minimum password length >= 14."

    def _check(self, ctx: ScanContext) -> Finding | None:
        affected = []
        for g in ctx.gpos:
            if g.get("password_policy_weak"):
                affected.append({"gpo_name": g["name"]})
        if not affected: return None
        return self._make_finding(affected, f"{len(affected)} GPO có password policy yếu.")


@register
class CheckB3AnonymousLDAP(BaseCheck):
    id = "B3"
    name = "GPO cho phép anonymous LDAP bind"
    category = CATEGORY
    severity = Severity.HIGH
    description = "Cấu hình dsHeuristics cho phép anonymous bind vào LDAP, mở đường cho kẻ tấn công liệt kê thông tin."
    remediation = "Đặt dsHeuristics = 0 hoặc giá trị không bật anonymous bind."

    def _check(self, ctx: ScanContext) -> Finding | None:
        affected = []
        for g in ctx.gpos:
            if g.get("anonymous_ldap"):
                affected.append({"gpo_name": g["name"]})
        if not affected: return None
        return self._make_finding(affected, f"{len(affected)} cấu hình cho phép anonymous LDAP.")


@register
class CheckB4SMBSigning(BaseCheck):
    id = "B4"
    name = "GPO không bắt buộc SMB Signing"
    category = CATEGORY
    severity = Severity.HIGH
    description = "SMB Signing không được bắt buộc, cho phép kẻ tấn công thực hiện SMB Relay."
    remediation = "Bật 'Microsoft network server: Digitally sign communications (always)'."

    def _check(self, ctx: ScanContext) -> Finding | None:
        affected = []
        for g in ctx.gpos:
            if g.get("smb_signing_not_required"):
                affected.append({"gpo_name": g["name"]})
        if not affected: return None
        return self._make_finding(affected, f"{len(affected)} GPO không bắt buộc SMB Signing.")


@register
class CheckB5LooseGPOOnPrivilegedOU(BaseCheck):
    id = "B5"
    name = "GPO lỏng lẻo trên OU chứa tài khoản đặc quyền"
    category = CATEGORY
    severity = Severity.MEDIUM
    description = "OU chứa tài khoản Domain Admins có GPO cho phép user thường chỉnh sửa."
    remediation = "Hạn chế quyền Edit Settings trên GPO của OU đặc quyền."

    def _check(self, ctx: ScanContext) -> Finding | None:
        # Cần dữ liệu GPO links và ACL của OU
        # Tạm thời để trống, sẽ bổ sung nếu có dữ liệu
        return None