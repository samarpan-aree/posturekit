"""Render findings as human text, Markdown, JSON or SARIF 2.1.0."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Sequence

from .models import Finding, Severity
from .scoring import Score

SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_URI = "https://github.com/samarpan-aree/posturekit"

#: SARIF has three levels; map our five severities onto them.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


@dataclass(frozen=True)
class AuditResult:
    """Everything a renderer needs: the target, its findings and the score."""

    target: str
    findings: Sequence[Finding]
    score: Score
    version: str


def _failed(findings: Iterable[Finding]) -> list[Finding]:
    return [f for f in findings if not f.passed]


def to_text(result: AuditResult) -> str:
    """Terminal output: failures first, then a one-line verdict."""

    lines: list[str] = []
    lines.append(f"posturekit {result.version} - {result.target}")
    lines.append("")

    failures = _failed(result.findings)
    if failures:
        lines.append(f"{len(failures)} finding(s) to fix")
        lines.append("")
        for finding in failures:
            lines.append(f"  [{finding.severity.value.upper():8}] {finding.title} ({finding.check_id})")
            lines.append(f"             {finding.detail}")
            if finding.remediation:
                lines.append(f"             fix: {finding.remediation}")
            lines.append("")
    else:
        lines.append("No failures found.")
        lines.append("")

    lines.append(
        f"Score {result.score.earned}/{result.score.possible} "
        f"({result.score.percent}/100, grade {result.score.grade})"
    )
    return "\n".join(lines)


def to_markdown(result: AuditResult) -> str:
    """A table plus remediation notes, ready to paste into a report."""

    lines: list[str] = []
    lines.append(f"# Security posture - {result.target}")
    lines.append("")
    lines.append(
        f"**Score: {result.score.earned}/{result.score.possible} "
        f"({result.score.percent}/100) - grade {result.score.grade}**"
    )
    lines.append("")
    lines.append("| Check | Layer | Result | Weight |")
    lines.append("| --- | --- | --- | --- |")
    for finding in result.findings:
        mark = "pass" if finding.passed else f"**{finding.severity.value}**"
        lines.append(
            f"| {finding.title} | {finding.category.value} | {mark} | {finding.weight} |"
        )

    failures = _failed(result.findings)
    if failures:
        lines.append("")
        lines.append("## Remediation")
        lines.append("")
        for finding in failures:
            lines.append(f"### {finding.title}")
            lines.append("")
            lines.append(finding.detail)
            lines.append("")
            if finding.evidence:
                lines.append(f"Observed: `{finding.evidence}`")
                lines.append("")
            lines.append(f"**Fix:** {finding.remediation}")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def to_dict(result: AuditResult) -> dict:
    """The stable JSON shape other tools can consume."""

    return {
        "target": result.target,
        "tool": {"name": "posturekit", "version": result.version},
        "score": {
            "earned": result.score.earned,
            "possible": result.score.possible,
            "percent": result.score.percent,
            "grade": result.score.grade,
        },
        "summary": {
            "total": len(result.findings),
            "passed": sum(1 for f in result.findings if f.passed),
            "failed": len(_failed(result.findings)),
        },
        "findings": [
            {
                "check_id": f.check_id,
                "category": f.category.value,
                "severity": f.severity.value,
                "weight": f.weight,
                "title": f.title,
                "passed": f.passed,
                "detail": f.detail,
                "remediation": f.remediation,
                "evidence": f.evidence,
            }
            for f in result.findings
        ],
    }


def to_json(result: AuditResult, indent: int = 2) -> str:
    return json.dumps(to_dict(result), indent=indent)


def to_sarif(result: AuditResult) -> dict:
    """SARIF 2.1.0, so findings surface in GitHub code scanning."""

    rules: list[dict] = []
    results: list[dict] = []
    seen: set[str] = set()

    for finding in result.findings:
        if finding.check_id not in seen:
            seen.add(finding.check_id)
            rules.append(
                {
                    "id": finding.check_id,
                    "name": finding.title.replace(" ", ""),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.remediation},
                    "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
                    "helpUri": TOOL_URI,
                    "properties": {"category": finding.category.value},
                }
            )

        if finding.passed:
            continue

        message = finding.detail
        if finding.remediation:
            message = f"{message} Fix: {finding.remediation}"

        results.append(
            {
                "ruleId": finding.check_id,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": result.target, "uriBaseId": "%SRCROOT%"}
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity.value,
                    "weight": finding.weight,
                    "evidence": finding.evidence,
                },
            }
        )

    return {
        "$schema": SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "posturekit",
                        "version": result.version,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "score": result.score.percent,
                    "grade": result.score.grade,
                },
            }
        ],
    }


__all__ = [
    "AuditResult",
    "SCHEMA_URL",
    "to_dict",
    "to_json",
    "to_markdown",
    "to_sarif",
    "to_text",
]
