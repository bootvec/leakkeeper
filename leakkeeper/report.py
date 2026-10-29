"""Report rendering — JSON and human-readable Markdown output."""

from __future__ import annotations

import json

from .result import CheckResult, Status

_STATUS_MARK = {
    Status.PASS: "OK",
    Status.FAIL: "FAIL",
    Status.WARN: "WARN",
    Status.ERROR: "ERROR",
    Status.SKIP: "SKIP",
}


def to_json(results: list[CheckResult], overall: str) -> str:
    payload = {
        "overall": overall,
        "checks": [r.to_dict() for r in results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_markdown(results: list[CheckResult], overall: str) -> str:
    lines: list[str] = ["# leakkeeper report", ""]
    lines.append(f"**Overall:** `{overall}`")
    lines.append("")
    for r in results:
        mark = _STATUS_MARK.get(r.status, r.status)
        lines.append(f"## {mark} — {r.name} (`{r.id}`)")
        lines.append(f"Status: `{r.status}`")
        lines.append(f"Summary: {r.summary}")
        if r.evidence:
            lines.append("")
            lines.append("Evidence:")
            lines.append("```")
            lines.extend(r.evidence)
            lines.append("```")
        if r.details:
            lines.append("")
            lines.append("Details:")
            lines.append("```json")
            lines.append(json.dumps(r.details, indent=2, ensure_ascii=False, default=str))
            lines.append("```")
        lines.append("")
    return "\n".join(lines)


def to_terminal(results: list[CheckResult], overall: str, verbose: bool = False) -> str:
    lines: list[str] = []
    for r in results:
        mark = _STATUS_MARK.get(r.status, r.status)
        lines.append(f"[{mark:>5}] {r.name}: {r.summary}")
        if verbose and r.details:
            lines.append("      details: " + json.dumps(r.details, ensure_ascii=False, default=str))
    counts = {s: sum(1 for r in results if r.status == s) for s in _STATUS_MARK}
    tally = " ".join(f"{_STATUS_MARK[s]}={counts[s]}" for s in _STATUS_MARK if counts[s])
    lines.append(f"\n{tally} — Overall: {overall}")
    return "\n".join(lines)
