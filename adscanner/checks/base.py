"""
Framework nền tảng cho tất cả các bài kiểm tra (checks).
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ============================================================
# SEVERITY
# ============================================================
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def weight(self) -> float:
        return {
            Severity.CRITICAL: 10.0,
            Severity.HIGH:     7.0,
            Severity.MEDIUM:   4.0,
            Severity.LOW:      2.0,
            Severity.INFO:     0.5,
        }[self]

    @property
    def order(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH:     1,
            Severity.MEDIUM:   2,
            Severity.LOW:      3,
            Severity.INFO:     4,
        }[self]


# ============================================================
# TRẠNG THÁI CHECK
# ============================================================
class CheckStatus(str, Enum):
    PASS         = "PASS"          # Không phát hiện vấn đề
    FAIL         = "FAIL"          # Phát hiện vấn đề (có Finding)
    ERROR        = "ERROR"         # Check bị lỗi khi chạy
    NOT_ASSESSED = "NOT_ASSESSED"  # Không đánh giá được (thiếu quyền, lỗi mạng)


# ============================================================
# FINDING
# ============================================================
@dataclass
class Finding:
    check_id: str
    check_name: str
    category: str
    severity: Severity
    description: str
    remediation: str
    affected_count: int
    affected_objects: list[dict[str, Any]] = field(default_factory=list)
    evidence_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "category": self.category,
            "severity": self.severity.value,
            "description": self.description,
            "remediation": self.remediation,
            "affected_count": self.affected_count,
            "affected_objects": self.affected_objects,
            "evidence_summary": self.evidence_summary,
        }


# ============================================================
# CHECK RESULT (Đã bổ sung trường note)
# ============================================================
@dataclass
class CheckResult:
    check_id: str
    check_name: str
    category: str
    status: CheckStatus
    finding: Finding | None = None
    error: str | None = None
    duration_ms: float = 0.0
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "category": self.category,
            "status": self.status.value,
            "finding": self.finding.to_dict() if self.finding else None,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 2),
            "note": self.note,
        }


# ============================================================
# SCAN CONTEXT
# ============================================================
@dataclass
class ScanContext:
    profile: Any
    connector: Any
    users: list = field(default_factory=list)
    groups: list = field(default_factory=list)
    acls: dict = field(default_factory=dict)
    graph: Any = None
    rbcd_objects: list = field(default_factory=list)
    trusts: list = field(default_factory=list)
    computers: list = field(default_factory=list)
    adcs_data: dict = field(default_factory=dict)
    gpos: list = field(default_factory=list)
    domain_config: Any = None
    smb_signing_req: bool | None = None
    collection_status: dict = field(default_factory=dict)

# ============================================================
# BASE CHECK
# ============================================================
class BaseCheck(ABC):
    id: str = ""
    name: str = ""
    category: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    remediation: str = ""

    def run(self, ctx: ScanContext) -> CheckResult:
        start = time.monotonic()
        try:
            finding = self._check(ctx)
            duration_ms = (time.monotonic() - start) * 1000

            if finding is None:
                return CheckResult(
                    check_id=self.id, check_name=self.name,
                    category=self.category, status=CheckStatus.PASS,
                    duration_ms=duration_ms,
                )

            return CheckResult(
                check_id=self.id, check_name=self.name,
                category=self.category, status=CheckStatus.FAIL,
                finding=finding, duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = (time.monotonic() - start) * 1000
            return CheckResult(
                check_id=self.id, check_name=self.name,
                category=self.category, status=CheckStatus.NOT_ASSESSED,
                error=f"{type(e).__name__}: {e}",
                duration_ms=duration_ms,
            )

    @abstractmethod
    def _check(self, ctx: ScanContext) -> Finding | None:
        ...

    def _make_finding(
        self,
        affected: list[dict[str, Any]],
        evidence_summary: str = "",
        **extra_fields,
    ) -> Finding:
        return Finding(
            check_id=self.id, check_name=self.name,
            category=self.category,
            severity=extra_fields.pop("severity", self.severity),
            description=self.description, remediation=self.remediation,
            affected_count=len(affected), affected_objects=affected,
            evidence_summary=evidence_summary,
        )