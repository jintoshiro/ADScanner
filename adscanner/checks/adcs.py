from adscanner.checks.base import BaseCheck, Finding, ScanContext, Severity
from adscanner.checks.registry import register

CATEGORY = "AD CS"

@register
class CheckD1ESC1(BaseCheck):
    id = "D1"
    name = "Certificate Template cho phép ESC1 (Mạo danh SAN)"
    category = CATEGORY
    severity = Severity.CRITICAL
    description = (
        "Template cho phép ENROLLEE_SUPPLIES_SUBJECT (tự điền Subject Alternative Name) "
        "kết hợp với EKU Client Authentication, cho phép bất kỳ user nào request chứng chỉ "
        "đứng tên Domain Admin để chiếm quyền."
    )
    remediation = "Tắt cờ ENROLLEE_SUPPLIES_SUBJECT hoặc yêu cầu CA Manager phê duyệt."

    def _check(self, ctx: ScanContext) -> Finding | None:
        if not ctx.adcs_data.get("templates"): return None
        
        # EKU cho phép xác thực (Client Auth, PKINIT, Any Purpose)
        AUTH_EKUS = {
            "1.3.6.1.5.5.7.3.2",           # Client Authentication
            "1.3.6.1.4.1.311.20.2.2",      # Smart Card Logon
            "1.3.6.1.5.2.3.4",             # PKINIT Client Auth
            "2.5.29.37.0",                 # Any Purpose
        }

        affected = []
        for t in ctx.adcs_data["templates"]:
            has_auth_eku = any(e in AUTH_EKUS for e in t["eku"]) or not t["eku"] # Không có EKU cũng nguy hiểm
            if t["enrollee_supplies_subject"] and has_auth_eku and not t["requires_manager_approval"]:
                affected.append({
                    "template_name": t["name"],
                    "eku": t["eku"],
                })

        if not affected: return None
        return self._make_finding(affected, f"{len(affected)} template có lỗ hổng ESC1.")

@register
class CheckD2DomainUsersEnroll(BaseCheck):
    id = "D2"
    name = "Template cho phép Domain Users enroll"
    category = CATEGORY
    severity = Severity.HIGH
    description = "Certificate Template cho phép nhóm Domain Users (hoặc Authenticated Users) request chứng chỉ, có thể bị lợi dụng để leo thang."
    remediation = "Hạn chế quyền Enroll chỉ cho các nhóm cần thiết."

    def _check(self, ctx: ScanContext) -> Finding | None:
        if not ctx.adcs_data.get("templates"): return None
        
        # SID của Domain Users và Authenticated Users
        DOMAIN_USERS_SID = "S-1-5-21-...-513" # Cần lấy động
        AUTH_USERS_SID = "S-1-5-11"
        
        affected = []
        for t in ctx.adcs_data["templates"]:
            for ace in t.get("enroll_aces", []):
                trustee = ace.get("trustee") 
                if trustee in ("S-1-5-11", "...-513"):
                    affected.append({"template_name": t["name"], "trustee": "Authenticated Users"})
                    break
        if not affected: return None
        return self._make_finding(affected, f"{len(affected)} template cho phép Domain Users enroll.")


@register
class CheckD3NoManagerApproval(BaseCheck):
    id = "D3"
    name = "Template không yêu cầu CA Manager phê duyệt"
    category = CATEGORY
    severity = Severity.INFO
    description = "Template cho phép request chứng chỉ mà không cần CA Manager phê duyệt, giảm rào cản cho kẻ tấn công."
    remediation = "Bật cờ 'CA certificate manager approval' trong template."

    def _check(self, ctx: ScanContext) -> Finding | None:
        if not ctx.adcs_data.get("templates"): return None
        
        affected = []
        for t in ctx.adcs_data["templates"]:
            if not t["requires_manager_approval"]:
                affected.append({"template_name": t["name"]})
        if not affected: return None
        return self._make_finding(affected, f"{len(affected)} template không yêu cầu CA Manager phê duyệt.")


@register
class CheckD4AuthEKU(BaseCheck):
    id = "D4"
    name = "Template cho phép Authentication EKU"
    category = CATEGORY
    severity = Severity.INFO
    description = "Template cấp chứng chỉ có EKU cho phép xác thực (Client Authentication, PKINIT), có thể dùng để mạo danh user."
    remediation = "Loại bỏ EKU xác thực nếu không cần thiết."

    def _check(self, ctx: ScanContext) -> Finding | None:
        if not ctx.adcs_data.get("templates"): return None
        
        AUTH_EKUS = {
            "1.3.6.1.5.5.7.3.2",           # Client Authentication
            "1.3.6.1.4.1.311.20.2.2",      # Smart Card Logon
            "1.3.6.1.5.2.3.4",             # PKINIT Client Auth
            "2.5.29.37.0",                 # Any Purpose
        }
        
        affected = []
        for t in ctx.adcs_data["templates"]:
            if any(e in AUTH_EKUS for e in t["eku"]):
                affected.append({"template_name": t["name"], "eku": t["eku"]})
        if not affected: return None
        return self._make_finding(affected, f"{len(affected)} template có Authentication EKU.")