"""posturekit - external security posture scanning with zero dependencies."""

from __future__ import annotations

from .models import Category, Finding, Severity, TlsProbe
from .scoring import Score, score

__version__ = "1.0.0"

__all__ = [
    "Category",
    "Finding",
    "Score",
    "Severity",
    "TlsProbe",
    "__version__",
    "score",
]
