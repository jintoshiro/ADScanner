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

