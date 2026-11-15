"""Nhóm A, B — Chính sách mật khẩu (LDAP-based)."""
from adscanner.checks.base import BaseCheck, Finding, ScanContext, Severity
from adscanner.checks.registry import register

CATEGORY = "Password Policy"

@register
class CheckA4PasswordPolicy(BaseCheck):
    id = "A4"
    name = "Chính sách mật khẩu domain và rủi ro (gián tiếp)"
    category = CATEGORY
    severity = Severity.HIGH
    description = (
        "Domain có chính sách mật khẩu yếu (độ dài < 14, không phức tạp, không lockout). "
        "Đánh giá gián tiếp vì công cụ không thể kiểm tra mật khẩu từng user."
    )
    remediation = "Đặt minPwdLength >= 14, bật complexity, và lockoutThreshold > 0."

    def _check(self, ctx: ScanContext) -> Finding | None:
        cfg = getattr(ctx, "domain_config", None)
        if not cfg: return None
        
        issues = []
        if cfg.min_pwd_length < 14:
            issues.append(f"minPwdLength = {cfg.min_pwd_length} (< 14)")
        if not (cfg.pwd_properties & 0x1):
            issues.append("Không yêu cầu độ phức tạp mật khẩu")
        if cfg.lockout_threshold == 0:
            issues.append("lockoutThreshold = 0 (không giới hạn đăng nhập sai)")
        if cfg.max_pwd_age_days is None:
            issues.append("maxPwdAge = never (mật khẩu không bao giờ hết hạn ở cấp domain)")
        
        # Kiểm tra PSO nếu có
        if cfg.psos:
            for pso in cfg.psos:
                if pso["min_length"] < 14:
                    issues.append(f"PSO '{pso['name']}' có min_length = {pso['min_length']}")
        
        if not issues: return None
        return self._make_finding([{"issues": issues}], f"{len(issues)} vấn đề chính sách mật khẩu.")


@register
class CheckB2PasswordPolicy(BaseCheck):
    id = "B2"
    name = "Domain không enforce password policy mạnh"
    category = "GPO Audit"
    severity = Severity.MEDIUM
    description = "Chính sách mật khẩu domain yếu (đọc trực tiếp từ Domain object)."
    remediation = "Nâng cấp chính sách mật khẩu domain."

    def _check(self, ctx: ScanContext) -> Finding | None:
        cfg = getattr(ctx, "domain_config", None)
        if not cfg: return None
        
        if cfg.min_pwd_length < 8 or not (cfg.pwd_properties & 0x1):
            return self._make_finding([{
                "min_pwd_length": cfg.min_pwd_length,
                "complexity": bool(cfg.pwd_properties & 0x1)
            }], "Chính sách mật khẩu domain yếu.")
        return None


@register
class CheckB3AnonymousLDAP(BaseCheck):
    id = "B3"
    name = "Cho phép anonymous LDAP bind"
    category = "GPO Audit"
    severity = Severity.HIGH
    description = "dsHeuristics cho phép anonymous LDAP operations."
    remediation = "Đặt dsHeuristics = 0."

    def _check(self, ctx: ScanContext) -> Finding | None:
        cfg = getattr(ctx, "domain_config", None)
        if not cfg or not cfg.ds_heuristics:
            return None
        
        # Ký tự thứ 7 (index 6): '2' = cho phép anonymous
        if len(cfg.ds_heuristics) >= 7 and cfg.ds_heuristics[6] == '2':
            return self._make_finding([{
                "ds_heuristics": cfg.ds_heuristics,
                "flag": "fLDAPBlockAnonOps = 2"
            }], "Cấu hình dsHeuristics cho phép anonymous LDAP.")
        return None


@register
class CheckB4SMBSigning(BaseCheck):
    id = "B4"
    name = "DC không bắt buộc SMB Signing"
    category = "GPO Audit"
    severity = Severity.HIGH
    description = "Domain Controller không bắt buộc SMB Signing, có thể bị SMB Relay."
    remediation = "Bật 'Microsoft network server: Digitally sign communications (always)'."

    def _check(self, ctx: ScanContext) -> Finding | None:
        signing = getattr(ctx, "smb_signing_req", None)
        if signing is False:
            return self._make_finding([{
                "dc_ip": ctx.profile.primary.dc_ip
            }], "DC không bắt buộc SMB Signing.")
        return None