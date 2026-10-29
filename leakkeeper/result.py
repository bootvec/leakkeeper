"""Structured result model shared by every check and the report renderer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


class Status:
    """Canonical outcome of a single check."""

    PASS = "pass"    # no leak / healthy
    FAIL = "fail"    # leak or misconfiguration detected
    WARN = "warn"    # suspicious, needs human review
    ERROR = "error"  # check could not run (tooling/network problem)
    SKIP = "skip"    # not applicable on this host

    ORDER = {PASS: 0, SKIP: 1, WARN: 2, ERROR: 3, FAIL: 4}

    @classmethod
    def worst(cls, statuses: list[str]) -> str:
        """Return the most severe status of a list."""
        if not statuses:
            return cls.SKIP
        if any(s not in cls.ORDER for s in statuses):
            return cls.ERROR
        return max(statuses, key=lambda s: cls.ORDER.get(s, 0))


@dataclass
class CheckResult:
    """A single, self-contained check outcome with evidence."""

    id: str
    name: str
    category: str
    status: str = Status.SKIP
    summary: str = ""
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
