"""Weighted score and letter grade.

The rule is one line: earned weight is the sum of passed weights. Checks
carry their own weight, so adding a check automatically widens the
denominator without any central table to keep in sync.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from .models import Finding, Severity

#: Ordered descending so the first match wins.
GRADE_BANDS: tuple[tuple[int, str], ...] = (
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
)


def grade_for(percent: float) -> str:
    """Map a 0-100 percentage onto a letter grade."""

    for threshold, letter in GRADE_BANDS:
        if percent >= threshold:
            return letter
    return "F"


@dataclass(frozen=True)
class Score:
    """The audit result in one number plus its parts."""

    earned: int
    possible: int

    @property
    def percent(self) -> int:
        if self.possible <= 0:
            return 100
        return int(round(100.0 * self.earned / self.possible))

    @property
    def grade(self) -> str:
        return grade_for(self.percent)

    @property
    def failed_weights(self) -> int:
        """Weight still recoverable by fixing what failed."""

        return self.possible - self.earned


def score(findings: Iterable[Finding]) -> Score:
    """Sum the weights and return the resulting score."""

    items = list(findings)
    possible = sum(f.weight for f in items)
    earned = sum(f.weight for f in items if f.passed)
    return Score(earned=earned, possible=possible)


SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def failures_by_severity(findings: Sequence[Finding]) -> list[Finding]:
    """Worst first, so a report opens with the thing that matters."""

    failed = [f for f in findings if not f.passed]
    return sorted(failed, key=lambda f: (SEVERITY_RANK[f.severity], -f.weight))


__all__ = [
    "GRADE_BANDS",
    "SEVERITY_RANK",
    "Score",
    "failures_by_severity",
    "grade_for",
    "score",
]
