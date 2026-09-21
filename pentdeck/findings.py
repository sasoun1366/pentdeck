"""Findings: what was seen, how bad it is, and what to do about it.

A pentest report is only worth reading if every line says three things — what was
found, why it matters, and what to change. The `Finding` type enforces that shape,
and the severity order follows the usual convention so that a client can sort the
list and start at the top.
"""

from __future__ import annotations

import dataclasses
import enum
from typing import Any, Dict, Iterable, List, Optional, Sequence


class Severity(str, enum.Enum):
    """Ordered, and sortable, because a report is worked top-down."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
        }[self.value]

    @property
    def label(self) -> str:
        return self.value.upper()

    @property
    def colour(self) -> str:
        return {
            "critical": "\033[1;35m",
            "high": "\033[1;31m",
            "medium": "\033[33m",
            "low": "\033[36m",
            "info": "\033[90m",
        }[self.value]


def severity_from(value: str) -> Severity:
    try:
        return Severity(str(value).strip().lower())
    except ValueError as exc:
        raise ValueError(
            f"unknown severity {value!r} — use one of {', '.join(item.value for item in Severity)}"
        ) from exc


@dataclasses.dataclass
class Finding:
    """One observation about one target."""

    check: str
    host: str
    severity: Severity = Severity.INFO
    title: str = ""
    detail: str = ""
    remediation: str = ""
    port: Optional[int] = None
    evidence: str = ""
    references: List[str] = dataclasses.field(default_factory=list)

    @property
    def target(self) -> str:
        return f"{self.host}:{self.port}" if self.port else self.host

    @property
    def key(self) -> tuple:
        """Used to de-duplicate findings from parallel checks."""
        return (self.check, self.host, self.port, self.title)

    def as_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["severity"] = self.severity.value
        data["target"] = self.target
        return data

    def one_line(self, colour: bool = False) -> str:
        head = f"{self.severity.label:<8} {self.target:<26} {self.title}"
        if colour:
            return f"{self.severity.colour}{head}\033[0m"
        return head


@dataclasses.dataclass
class ScanResult:
    """Everything a scan produced, in the order a report needs it."""

    scope_name: str = ""
    authorization: str = ""
    started: str = ""
    finished: str = ""
    hosts_scanned: List[str] = dataclasses.field(default_factory=list)
    hosts_total: int = 0
    hosts_up: List[str] = dataclasses.field(default_factory=list)
    checks_run: List[str] = dataclasses.field(default_factory=list)
    checks_skipped: List[tuple] = dataclasses.field(default_factory=list)
    findings: List[Finding] = dataclasses.field(default_factory=list)
    errors: List[str] = dataclasses.field(default_factory=list)
    license_tier: str = "free"
    tool_version: str = ""
    #: The operator pressed stop: the result is honest about being partial.
    interrupted: bool = False

    def add(self, findings: Iterable[Finding]) -> None:
        self.findings.extend(findings)

    def sorted_findings(self, minimum: Optional[Severity] = None) -> List[Finding]:
        items = list(self.findings)
        if minimum is not None:
            items = [item for item in items if item.severity.rank >= minimum.rank]
        # Worst first, then grouped by host so a client can work machine by machine.
        return sorted(items, key=lambda item: (-item.severity.rank, item.host, item.port or 0, item.title))

    def counts(self, minimum: Optional[Severity] = None) -> Dict[str, int]:
        counts = {item.value: 0 for item in Severity}
        for finding in self.sorted_findings(minimum):
            counts[finding.severity.value] += 1
        counts["total"] = sum(counts[item.value] for item in Severity)
        return counts

    @property
    def worst(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((item.severity for item in self.findings), key=lambda item: item.rank)

    def exit_code(self, fail_on: Severity = Severity.HIGH) -> int:
        """0 when nothing at or above the threshold was found, 1 otherwise."""
        return 1 if any(item.severity.rank >= fail_on.rank for item in self.findings) else 0

    def summary_line(self) -> str:
        counts = self.counts()
        interesting = [f"{counts[name]} {name}" for name in ("critical", "high", "medium", "low") if counts[name]]
        return (
            f"{len(self.hosts_up)}/{self.hosts_total} host(s) up · "
            + (", ".join(interesting) if interesting else "nothing above info")
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "scope": self.scope_name,
            "authorization": self.authorization,
            "started": self.started,
            "finished": self.finished,
            "tool_version": self.tool_version,
            "license_tier": self.license_tier,
            "hosts_total": self.hosts_total,
            "hosts_up": self.hosts_up,
            "hosts_scanned": self.hosts_scanned,
            "checks_run": self.checks_run,
            "checks_skipped": [list(item) for item in self.checks_skipped],
            "counts": self.counts(),
            "interrupted": self.interrupted,
            "errors": self.errors,
            "findings": [finding.as_dict() for finding in self.sorted_findings()],
        }


def deduplicate(findings: Sequence[Finding]) -> List[Finding]:
    """Keep the first of each identical finding — parallel checks can overlap."""
    seen = set()
    out: List[Finding] = []
    for finding in findings:
        if finding.key in seen:
            continue
        seen.add(finding.key)
        out.append(finding)
    return out
