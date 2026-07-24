"""
findings.py
-----------
Shared data model for a single vulnerability/finding produced by any module,
plus small helpers used across the reporting layer.
"""

from dataclasses import dataclass, field
from datetime import datetime

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


@dataclass
class Finding:
    module: str                 # e.g. "Security Headers"
    title: str                  # short name of the issue
    severity: str               # Critical / High / Medium / Low / Info
    description: str            # what was found
    evidence: str = ""          # raw evidence (header value, payload, response snippet)
    remediation: str = ""       # how to fix it
    location: str = ""          # URL / parameter / endpoint affected

    def severity_rank(self):
        return SEVERITY_ORDER.get(self.severity, 0)


@dataclass
class ScanResult:
    """Aggregates everything a module produced during one run."""
    module_name: str
    target: str
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    finished_at: str = ""

    def add(self, finding: Finding):
        self.findings.append(finding)

    def finish(self):
        self.finished_at = datetime.now().isoformat(timespec="seconds")
        return self


def overall_risk_rating(all_findings):
    """Derive a single overall risk rating from a list of Finding objects."""
    if not all_findings:
        return "Info"
    highest = max(f.severity_rank() for f in all_findings)
    for name, rank in SEVERITY_ORDER.items():
        if rank == highest:
            return name
    return "Info"
