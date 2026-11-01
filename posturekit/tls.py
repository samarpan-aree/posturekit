"""Transport-layer checks driven by an already-completed handshake."""

from __future__ import annotations

from .models import Category, Finding, Severity, TlsProbe

#: Anything below TLS 1.2 is no longer considered safe to negotiate.
ACCEPTABLE_PROTOCOLS = ("TLSv1.2", "TLSv1.3")

#: Warn this far ahead of expiry so a renewal is never a fire drill.
EXPIRY_WARNING_DAYS = 21


def check_protocol(probe: TlsProbe) -> Finding:
    """The negotiated protocol, plus any weak protocol still accepted."""

    remediation = "Disable TLS 1.0 and 1.1 at the terminator; require TLS 1.2 or newer."

    if probe.protocol not in ACCEPTABLE_PROTOCOLS:
        return Finding(
            check_id="tls-version",
            category=Category.TRANSPORT,
            severity=Severity.CRITICAL,
            weight=12,
            title="TLS protocol version",
            passed=False,
            detail=f"Negotiated {probe.protocol}, which is deprecated and vulnerable to known downgrade attacks.",
            remediation=remediation,
            evidence=probe.protocol,
        )

    if probe.weak_protocols_supported:
        return Finding(
            check_id="tls-version",
            category=Category.TRANSPORT,
            severity=Severity.HIGH,
            weight=12,
            title="TLS protocol version",
            passed=False,
            detail=(
                f"Negotiated {probe.protocol}, but the host still completes handshakes for: "
                + ", ".join(probe.weak_protocols_supported)
                + "."
            ),
            remediation=remediation,
            evidence=probe.protocol,
        )

    return Finding(
        check_id="tls-version",
        category=Category.TRANSPORT,
        severity=Severity.CRITICAL,
        weight=12,
        title="TLS protocol version",
        passed=True,
        detail=f"Negotiated {probe.protocol} and no deprecated protocol was accepted.",
        remediation=remediation,
        evidence=probe.protocol,
    )


def check_certificate_expiry(probe: TlsProbe) -> Finding:
    """An expired certificate is an outage with a security label."""

    days = probe.certificate_expires_in_days
    remediation = "Automate renewal and alert at 30 days remaining."

    if days < 0:
        return Finding(
            check_id="cert-expiry",
            category=Category.TRANSPORT,
            severity=Severity.CRITICAL,
            weight=12,
            title="Certificate validity period",
            passed=False,
            detail=f"Certificate expired {-days} day(s) ago.",
            remediation=remediation,
        )

    if days < EXPIRY_WARNING_DAYS:
        return Finding(
            check_id="cert-expiry",
            category=Category.TRANSPORT,
            severity=Severity.HIGH,
            weight=12,
            title="Certificate validity period",
            passed=False,
            detail=f"Certificate expires in {days} day(s), inside the {EXPIRY_WARNING_DAYS}-day warning window.",
            remediation=remediation,
        )

    return Finding(
        check_id="cert-expiry",
        category=Category.TRANSPORT,
        severity=Severity.CRITICAL,
        weight=12,
        title="Certificate validity period",
        passed=True,
        detail=f"Certificate valid for another {days} day(s).",
        remediation=remediation,
    )


def check_certificate_hostname(probe: TlsProbe) -> Finding:
    """Hostname validation is what makes a certificate worth anything."""

    return Finding(
        check_id="cert-hostname",
        category=Category.TRANSPORT,
        severity=Severity.HIGH,
        weight=8,
        title="Certificate hostname match",
        passed=probe.certificate_hostname_valid,
        detail=(
            "Certificate subject alternative names cover the requested host."
            if probe.certificate_hostname_valid
            else "Certificate does not cover the requested host, so clients cannot bind the key to this identity."
        ),
        remediation="Issue a certificate whose SAN list includes the exact hostname served.",
    )


def check_certificate_chain(probe: TlsProbe) -> Finding:
    """An unverified chain means the client fell back to trust-on-faith."""

    return Finding(
        check_id="cert-chain",
        category=Category.TRANSPORT,
        severity=Severity.HIGH,
        weight=8,
        title="Certificate chain trust",
        passed=probe.chain_trusted,
        detail=(
            "Chain validates to a trusted root."
            if probe.chain_trusted
            else "Chain does not validate against the system trust store - an incomplete intermediate is the usual cause."
        ),
        remediation="Serve the full intermediate chain in the handshake.",
    )


def check_tls(probe: TlsProbe) -> list[Finding]:
    """Run every transport check."""

    return [
        check_protocol(probe),
        check_certificate_expiry(probe),
        check_certificate_hostname(probe),
        check_certificate_chain(probe),
    ]


__all__ = [
    "ACCEPTABLE_PROTOCOLS",
    "EXPIRY_WARNING_DAYS",
    "check_certificate_chain",
    "check_certificate_expiry",
    "check_certificate_hostname",
    "check_protocol",
    "check_tls",
]
