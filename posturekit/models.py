"""Core data model shared by every check module.

The model is deliberately tiny: a check either passes or fails, carries the
weight it contributes to the total score, and always ships a remediation
string. A finding is never allowed to say "something is wrong" without also
saying what to do about it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """How much a *failing* finding should worry the reader."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    """Which layer of the posture a finding belongs to."""

    TRANSPORT = "transport"
    HEADERS = "headers"
    COOKIES = "cookies"
    DNS = "dns"


@dataclass(frozen=True)
class Finding:
    """The result of exactly one check.

    ``passed`` is the only verdict. ``severity`` describes the failure mode
    and is ignored when ``passed`` is True, which keeps the scoring rule
    trivial to reason about: earned weight is the sum of passed weights.
    """

    check_id: str
    category: Category
    severity: Severity
    weight: int
    title: str
    passed: bool
    detail: str
    remediation: str
    evidence: str = ""


@dataclass(frozen=True)
class TlsProbe:
    """What a TLS handshake actually told us."""

    protocol: str
    certificate_expires_in_days: int
    certificate_hostname_valid: bool
    chain_trusted: bool
    weak_protocols_supported: tuple[str, ...] = ()


__all__ = ["Category", "Finding", "Severity", "TlsProbe"]
