"""DNS and email-authentication checks.

SPF and DMARC are the two records that decide whether anyone can spoof mail
from this domain, so they carry serious weight. Everything here consumes
record strings, never sockets.
"""

from __future__ import annotations

import re
from typing import Sequence

from .models import Category, Finding, Severity

#: RFC 7208 caps SPF at 10 DNS-querying mechanisms; going over it is
#: legal but resolves to permerror in the field.
MAX_SPF_LOOKUPS = 10

_SPF_COUNTERS = ("include:", "exists:", "redirect=", "ptr", "mx", "a")
_DMARC_TAG_RE = re.compile(r"\s*([a-z]+)\s*=\s*([^;]+)")

_SPF_FIX = "Publish exactly one SPF record ending in -all, and stay within 10 DNS lookups."
_DMARC_FIX = (
    "Publish a _dmarc TXT record with p=reject (or p=quarantine) "
    "and a rua reporting address."
)


def _spf_finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        "check_id": "spf",
        "category": Category.DNS,
        "severity": Severity.HIGH,
        "weight": 8,
        "title": "SPF policy",
        "passed": False,
        "detail": "",
        "remediation": _SPF_FIX,
        "evidence": "",
    }
    fields.update(overrides)
    return Finding(**fields)  # type: ignore[arg-type]


def _dmarc_finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        "check_id": "dmarc",
        "category": Category.DNS,
        "severity": Severity.HIGH,
        "weight": 8,
        "title": "DMARC policy",
        "passed": False,
        "detail": "",
        "remediation": _DMARC_FIX,
        "evidence": "",
    }
    fields.update(overrides)
    return Finding(**fields)  # type: ignore[arg-type]


def count_spf_lookups(record: str) -> int:
    """Count the SPF mechanisms that cost a DNS lookup."""

    lowered = record.lower()
    total = 0
    for token in _SPF_COUNTERS:
        if token in ("a", "mx", "ptr"):
            total += len(re.findall(rf"(?:^|\s)[+-]?{token}(?::|\s|$)", lowered))
        else:
            total += lowered.count(token)
    return total


def check_spf(txt_records: Sequence[str]) -> Finding:
    """Exactly one SPF record, ending in -all, inside the lookup budget."""

    records = [r.strip() for r in txt_records if r.strip().lower().startswith("v=spf1")]

    if not records:
        return _spf_finding(
            detail="No SPF record published, so any host may claim to send mail as this domain."
        )

    if len(records) > 1:
        return _spf_finding(
            severity=Severity.HIGH,
            detail=(
                f"{len(records)} SPF records found. RFC 7208 allows exactly one, and "
                "receivers resolve duplicates to permerror."
            ),
            evidence=" | ".join(records),
        )

    record = records[0]
    lowered = record.lower()

    if "+all" in lowered:
        return _spf_finding(
            severity=Severity.CRITICAL,
            detail="'+all' authorises every sender on the internet, which is worse than having no SPF at all.",
            evidence=record,
        )

    lookups = count_spf_lookups(record)
    if lookups > MAX_SPF_LOOKUPS:
        return _spf_finding(
            severity=Severity.MEDIUM,
            detail=(
                f"{lookups} DNS-querying mechanisms exceeds the RFC 7208 limit of "
                f"{MAX_SPF_LOOKUPS}; receivers will return permerror."
            ),
            evidence=record,
        )

    if not lowered.rstrip().endswith("-all"):
        softened = "~all" if lowered.rstrip().endswith("~all") else "unqualified"
        return _spf_finding(
            severity=Severity.MEDIUM,
            detail=(
                f"Record terminates with {softened} rather than -all, so unauthorised "
                "senders are marked, not rejected."
            ),
            evidence=record,
        )

    return _spf_finding(
        passed=True,
        detail=f"Single SPF record ending in -all with {lookups} DNS-querying mechanism(s).",
        evidence=record,
    )
