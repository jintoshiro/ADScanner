"""
Risk Scoring Engine — Tính điểm rủi ro bằng xác suất kết hợp.
Hỗ trợ trạng thái NOT_ASSESSED (không tính vào điểm nhưng báo cáo độ phủ).
"""
from dataclasses import dataclass
from adscanner.checks import CheckResult, CheckStatus, Severity

@dataclass
class RiskScore:
    total_score: float
    grade: str
    severity_counts: dict
    failed_checks: int
    passed_checks: int
    not_assessed_checks: int
    error_checks: int
    total_checks: int
    coverage: float           # Tỷ lệ check đã đánh giá được (PASS + FAIL) / tổng
    is_lower_bound: bool      # True nếu có check NOT_ASSESSED/ERROR

def calculate_risk_score(results: list[CheckResult]) -> RiskScore:
    SEVERITY_PROB = {
        Severity.CRITICAL: 0.30,
        Severity.HIGH:     0.15,
        Severity.MEDIUM:   0.07,
        Severity.LOW:      0.02,
        Severity.INFO:     0.0,
    }

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    survive = 1.0
    failed = passed = na = err = 0

    for res in results:
        if res.status == CheckStatus.FAIL and res.finding:
            sev = res.finding.severity
            severity_counts[sev.value] += 1
            survive *= (1.0 - SEVERITY_PROB.get(sev, 0.0))
            failed += 1
        elif res.status == CheckStatus.PASS:
            passed += 1
        elif res.status == CheckStatus.NOT_ASSESSED:
            na += 1
        else:
            err += 1

    total = len(results)
    total_score = round((1.0 - survive) * 100, 1)

    if total_score <= 20:
        grade = "An toàn"
    elif total_score <= 40:
        grade = "Cần cải thiện"
    elif total_score <= 60:
        grade = "Rủi ro trung bình"
    elif total_score <= 80:
        grade = "Rủi ro cao"
    else:
        grade = "Nghiêm trọng"

    return RiskScore(
        total_score=total_score,
        grade=grade,
        severity_counts=severity_counts,
        failed_checks=failed,
        passed_checks=passed,
        not_assessed_checks=na,
        error_checks=err,
        total_checks=total,
        coverage=(passed + failed) / total if total else 0.0,
        is_lower_bound=(na + err) > 0,
    )