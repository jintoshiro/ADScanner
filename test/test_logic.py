import pytest
from adscanner.utils.acl_mapper import classify_ace
from adscanner.scoring.engine import calculate_risk_score
from adscanner.checks import CheckResult, CheckStatus, Severity, Finding

def test_classify_ace():
    """Kiểm tra logic ánh xạ quyền."""
    base_ace = {"type": 0, "inherit_only": False, "sid": "S-1-5-21-X", "object_type": None}
    
    # Full Control (GenericAll)
    assert 'GenericAll' in classify_ace({**base_ace, "mask": 0xF01FF}, "user")
    
    # GenericWrite
    assert 'GenericWrite' in classify_ace({**base_ace, "mask": 0x20028}, "user")
    
    # WriteDacl
    assert 'WriteDacl' in classify_ace({**base_ace, "mask": 0x40000}, "user")

def test_scoring_decay():
    """Kiểm tra điểm không bị bão hòa (sửa lỗi thì điểm phải giảm)."""
    def make_finding(sev):
        return CheckResult("ID", "Name", "Cat", CheckStatus.FAIL, Finding("ID", "Name", "Cat", sev, "", "", 1, [{}]))

    # 3 Critical, 1 High
    results = [make_finding(Severity.CRITICAL)] * 3 + [make_finding(Severity.HIGH)]
    risk = calculate_risk_score(results)
    
    # Điểm phải < 100 và > 0
    assert 0 < risk.total_score < 100
    
    # Thử sửa 1 lỗi Critical (xóa khỏi list), điểm phải giảm
    results_fixed = [make_finding(Severity.CRITICAL)] * 2 + [make_finding(Severity.HIGH)]
    risk_fixed = calculate_risk_score(results_fixed)
    assert risk_fixed.total_score < risk.total_score