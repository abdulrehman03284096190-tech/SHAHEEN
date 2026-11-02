from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    description: str
    severity: str = "medium"
    enabled: bool = True
    config: dict[str, object] | None = None


DEFAULT_RULES = [
    DetectionRule(
        rule_id="PORT_SCAN",
        name="Potential port scanning",
        description="Source host attempts many unique destination ports.",
        severity="high",
        config={"threshold": 15, "window_seconds": 30},
    ),
    DetectionRule(
        rule_id="DNS_ANOMALY",
        name="Suspicious DNS activity",
        description="Repeated DNS queries or unusual domain patterns.",
        severity="medium",
        config={"threshold": 20},
    ),
    DetectionRule(
        rule_id="CONNECTION_RETRY",
        name="Repeated connection attempts",
        description="Many failed TCP connections in a short time window.",
        severity="high",
        config={"threshold": 10},
    ),
]
