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
        if not cfg: 
            raise RuntimeError("Không có dữ liệu Domain Config")
        
        issues = []
        if cfg.min_pwd_length < 14:
            issues.append(f"minPwdLength = {cfg.min_pwd_length} (< 14)")
        if not (cfg.pwd_properties & 0x1):
            issues.append("Không yêu cầu độ phức tạp")
        if cfg.lockout_threshold == 0:
            issues.append("lockoutThreshold = 0")
        if cfg.max_pwd_age_days is None:
            issues.append("maxPwdAge = never")
        
        if cfg.psos:
            for pso in cfg.psos:
                if pso["min_length"] < 14:
                    issues.append(f"PSO '{pso['name']}' có min_length = {pso['min_length']}")
        
        if not issues: return None
        
        # Trả về dictionary có key "issues" rõ ràng
        affected = [{
            "object": "Domain Password Policy",
            "issues": issues
        }]
        return self._make_finding(affected, f"{len(issues)} vấn đề chính sách mật khẩu.")


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
        if not cfg: 
            raise RuntimeError("Không có dữ liệu Domain Config")
        
        if cfg.min_pwd_length < 8 or not (cfg.pwd_properties & 0x1):
            # Trả về dictionary có key "object" và "issues" để template hiển thị
            affected = [{
                "object": "Domain Password Policy",
                "issues": [
                    f"minPwdLength = {cfg.min_pwd_length}",
                    f"Complexity = {bool(cfg.pwd_properties & 0x1)}"
                ]
            }]
            return self._make_finding(affected, "Chính sách mật khẩu domain yếu.")
        return None

@register
class CheckB3AnonymousLDAP(BaseCheck):
    id = "B3"
    name = "Cho phép anonymous LDAP bind"
    category = "GPO Audit"
    severity = Severity.HIGH
    description = (
        "Cấu hình dsHeuristics cho phép anonymous LDAP operations. "
        "Kẻ tấn công có thể liệt kê thông tin AD mà không cần xác thực (nếu ACL cho phép)."
    )
    remediation = "Đặt dsHeuristics = 0 hoặc giá trị không bật fLDAPBlockAnonOps."

    def _check(self, ctx: ScanContext) -> Finding | None:
        cfg = getattr(ctx, "domain_config", None)
        if not cfg:
            raise RuntimeError("Không có dữ liệu Domain Config")
        
        if not cfg.ds_heuristics:
            return None  # Chuỗi rỗng = mặc định an toàn (PASS)
        
        # Ký tự thứ 7 (index 6) là fLDAPBlockAnonOps, '2' = cho phép anonymous
        if len(cfg.ds_heuristics) >= 7 and cfg.ds_heuristics[6] == '2':
            affected = [{
                "object": "dsHeuristics Configuration",
                "issues": [f"fLDAPBlockAnonOps = 2 (dsHeuristics={cfg.ds_heuristics})"]
            }]
            return self._make_finding(affected, "Cấu hình dsHeuristics cho phép anonymous LDAP.")
        return None