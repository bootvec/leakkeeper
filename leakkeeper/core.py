"""Orchestrator — runs checks and aggregates an overall verdict."""

from __future__ import annotations

from .checks import CHECKS, DESCRIPTIONS, ORDER
from .config import CheckContext
from .platform import require_linux
from .result import CheckResult, Status


def run_checks(
    ctx: CheckContext,
    only: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[CheckResult]:
    """Run checks (in canonical order) and return their results."""
    require_linux()
    known = set(ORDER)
    unknown = [c for c in (only or []) if c not in known] + [
        c for c in (exclude or []) if c not in known
    ]
    if unknown:
        raise ValueError(f"unknown check id(s): {', '.join(dict.fromkeys(unknown))}")
    ids = [c for c in ORDER if c in CHECKS]
    if only:
        ids = [c for c in ids if c in only]
    if exclude:
        ids = [c for c in ids if c not in exclude]

    results: list[CheckResult] = []
    for cid in ids:
        module = CHECKS[cid]
        try:
            res = module.run(ctx)
        except Exception as exc:  # a check must never crash the whole run
            res = CheckResult(
                id=cid,
                name=DESCRIPTIONS.get(cid, cid),
                category="unknown",
                status=Status.ERROR,
                summary=f"check crashed: {exc.__class__.__name__}: {exc}",
            )
        results.append(res)
    return results


def overall_status(results: list[CheckResult]) -> str:
    return Status.worst([r.status for r in results])
