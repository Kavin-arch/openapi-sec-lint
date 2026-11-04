from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    summary: str
    impact: str
    remediation: str
    affected_operations: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
