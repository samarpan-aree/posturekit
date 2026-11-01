"""Pure HTTP response-header and cookie checks.

Every function here takes already-collected data and returns findings. No
sockets are opened in this module, which is what makes the whole check suite
testable without a network or a running server.
"""

from __future__ import annotations

import re
from typing import Mapping, Sequence

from .models import Category, Finding, Severity

#: 180 days. Below this, browsers and the HSTS preload list treat the policy
#: as too short-lived to be meaningful.
MIN_HSTS_MAX_AGE = 15552000

_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_VERSION_RE = re.compile(r"\d+\.\d+")


def _normalise(headers: Mapping[str, str]) -> dict[str, str]:
    normalised: dict[str, str] = {}
    for key, value in headers.items():
        name = str(key).lower().strip()
        text = "" if value is None else str(value).strip()
        if name in normalised and normalised[name] and text:
            normalised[name] = normalised[name] + ", " + text
        else:
            normalised[name] = text
    return normalised


def _cookie_name(raw: str) -> str:
    head = raw.split(";", 1)[0]
    name = head.split("=", 1)[0].strip()
    return name or "<unnamed>"


def _cookie_flags(raw: str) -> set[str]:
    parts = raw.split(";")[1:]
    flags: set[str] = set()
    for part in parts:
        token = part.split("=", 1)[0].strip().lower()
        if token:
            flags.add(token)
    return flags


def check_hsts(headers: Mapping[str, str]) -> Finding:
    """HSTS must be present, long-lived and cover subdomains."""

    value = _normalise(headers).get("strict-transport-security", "")
    remediation = (
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
        "on every HTTPS response, then consider submitting to the preload list."
    )

    if not value:
        return Finding(
            check_id="hsts",
            category=Category.HEADERS,
            severity=Severity.HIGH,
            weight=10,
            title="HTTP Strict Transport Security",
            passed=False,
            detail=(
                "No Strict-Transport-Security header. A browser that reaches this "
                "host once over plain HTTP has no instruction to upgrade thereafter."
            ),
            remediation=remediation,
        )

    match = _MAX_AGE_RE.search(value)
    max_age = int(match.group(1)) if match else 0
    lowercase = value.lower()
    covers_subdomains = "includesubdomains" in lowercase

    if max_age < MIN_HSTS_MAX_AGE:
        return Finding(
            check_id="hsts",
            category=Category.HEADERS,
            severity=Severity.MEDIUM,
            weight=10,
            title="HTTP Strict Transport Security",
            passed=False,
            detail=(
                f"max-age={max_age}s is below the {MIN_HSTS_MAX_AGE}s floor used by the "
                "preload list, so the policy expires too quickly to protect a returning visitor."
            ),
            remediation=remediation,
            evidence=value,
        )

    if not covers_subdomains:
        return Finding(
            check_id="hsts",
            category=Category.HEADERS,
            severity=Severity.LOW,
            weight=10,
            title="HTTP Strict Transport Security",
            passed=False,
            detail=(
                f"max-age={max_age}s is adequate, but includeSubDomains is absent, so any "
                "sibling subdomain can still be downgraded to plain HTTP."
            ),
            remediation=remediation,
            evidence=value,
        )

    return Finding(
        check_id="hsts",
        category=Category.HEADERS,
        severity=Severity.HIGH,
        weight=10,
        title="HTTP Strict Transport Security",
        passed=True,
        detail=f"max-age={max_age}s with includeSubDomains.",
        remediation=remediation,
        evidence=value,
    )


def check_csp(headers: Mapping[str, str]) -> Finding:
    """A CSP that permits inline or eval script is barely a CSP."""

    value = _normalise(headers).get("content-security-policy", "")
    remediation = (
        "Serve a Content-Security-Policy with default-src 'self', nonce- or hash-based "
        "script-src, and no 'unsafe-inline' or 'unsafe-eval'."
    )

    if not value:
        return Finding(
            check_id="csp",
            category=Category.HEADERS,
            severity=Severity.HIGH,
            weight=12,
            title="Content Security Policy",
            passed=False,
            detail=(
                "No Content-Security-Policy. Any injected script string runs with the "
                "full privileges of the page."
            ),
            remediation=remediation,
        )

    lowercase = value.lower()
    weaknesses: list[str] = []
    if "'unsafe-inline'" in lowercase:
        weaknesses.append("'unsafe-inline'")
    if "'unsafe-eval'" in lowercase:
        weaknesses.append("'unsafe-eval'")
    if "script-src *" in lowercase or "default-src *" in lowercase:
        weaknesses.append("wildcard source")
    if "script-src" not in lowercase and "default-src" not in lowercase:
        weaknesses.append("no default-src or script-src")

    passed = not weaknesses
    detail = "Nonce or host allowlist in effect." if passed else (
        "Policy present but weakened by: " + ", ".join(weaknesses) + "."
    )

    return Finding(
        check_id="csp",
        category=Category.HEADERS,
        severity=Severity.HIGH if not passed else Severity.MEDIUM,
        weight=12,
        title="Content Security Policy",
        passed=passed,
        detail=detail,
        remediation=remediation,
        evidence=value,
    )


def check_frame_protection(headers: Mapping[str, str]) -> Finding:
    """frame-ancestors supersedes X-Frame-Options; either one is acceptable."""

    normalised = _normalise(headers)
    csp = normalised.get("content-security-policy", "").lower()
    xfo = normalised.get("x-frame-options", "")
    remediation = (
        "Add 'frame-ancestors none' to the CSP (preferred) or send "
        "'X-Frame-Options: DENY'."
    )

    if "frame-ancestors" in csp:
        return Finding(
            check_id="frame-ancestors",
            category=Category.HEADERS,
            severity=Severity.MEDIUM,
            weight=6,
            title="Clickjacking protection",
            passed=True,
            detail="CSP frame-ancestors is set, which is the current standard control.",
            remediation=remediation,
            evidence=csp,
        )

    if xfo:
        return Finding(
            check_id="frame-ancestors",
            category=Category.HEADERS,
            severity=Severity.MEDIUM,
            weight=6,
            title="Clickjacking protection",
            passed=True,
            detail="X-Frame-Options is set. Consider migrating to CSP frame-ancestors.",
            remediation=remediation,
            evidence=xfo,
        )

    return Finding(
        check_id="frame-ancestors",
        category=Category.HEADERS,
        severity=Severity.MEDIUM,
        weight=6,
        title="Clickjacking protection",
        passed=False,
        detail="Neither CSP frame-ancestors nor X-Frame-Options is present, so the page can be framed.",
        remediation=remediation,
    )


def check_content_type_options(headers: Mapping[str, str]) -> Finding:
    """nosniff stops the browser second-guessing declared content types."""

    value = _normalise(headers).get("x-content-type-options", "")
    passed = value.strip().lower() == "nosniff"
    return Finding(
        check_id="nosniff",
        category=Category.HEADERS,
        severity=Severity.MEDIUM,
        weight=5,
        title="Content type sniffing",
        passed=passed,
        detail=(
            "X-Content-Type-Options: nosniff is set."
            if passed
            else "Missing or malformed X-Content-Type-Options, so a response can be reinterpreted as a different MIME type."
        ),
        remediation="Send 'X-Content-Type-Options: nosniff' on every response.",
        evidence=value,
    )


def check_referrer_policy(headers: Mapping[str, str]) -> Finding:
    """Leaking full URLs to third parties leaks tokens and internal paths."""

    value = _normalise(headers).get("referrer-policy", "")
    lowercase = value.lower()
    passed = bool(value) and "unsafe-url" not in lowercase
    if passed:
        detail = f"Referrer-Policy is '{value}'."
    elif value:
        detail = "Referrer-Policy is 'unsafe-url', which sends the full URL to every destination."
    else:
        detail = "No Referrer-Policy header, so browser defaults decide what leaks cross-origin."

    return Finding(
        check_id="referrer-policy",
        category=Category.HEADERS,
        severity=Severity.LOW,
        weight=4,
        title="Referrer policy",
        passed=passed,
        detail=detail,
        remediation="Send 'Referrer-Policy: strict-origin-when-cross-origin'.",
        evidence=value,
    )


def check_permissions_policy(headers: Mapping[str, str]) -> Finding:
    """Explicitly deny powerful browser features the site does not use."""

    normalised = _normalise(headers)
    value = normalised.get("permissions-policy", "") or normalised.get("feature-policy", "")
    passed = bool(value)
    return Finding(
        check_id="permissions-policy",
        category=Category.HEADERS,
        severity=Severity.LOW,
        weight=4,
        title="Permissions policy",
        passed=passed,
        detail=(
            "Permissions-Policy restricts feature access."
            if passed
            else "No Permissions-Policy, so camera, microphone and geolocation stay available to any embedded frame."
        ),
        remediation="Send 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
        evidence=value,
    )


def check_cross_origin_opener(headers: Mapping[str, str]) -> Finding:
    """COOP severs the window reference an XS-Leak needs."""

    value = _normalise(headers).get("cross-origin-opener-policy", "")
    passed = bool(value)
    return Finding(
        check_id="coop",
        category=Category.HEADERS,
        severity=Severity.INFO,
        weight=3,
        title="Cross-origin opener policy",
        passed=passed,
        detail=(
            f"Cross-Origin-Opener-Policy is '{value}'."
            if passed
            else "No Cross-Origin-Opener-Policy. Documents opened from this page keep a window reference back to it."
        ),
        remediation="Send 'Cross-Origin-Opener-Policy: same-origin'.",
        evidence=value,
    )


def check_server_banner(headers: Mapping[str, str]) -> Finding:
    """A version string in Server/X-Powered-By is free reconnaissance."""

    normalised = _normalise(headers)
    leaks: list[str] = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        value = normalised.get(name, "")
        if value and _VERSION_RE.search(value):
            leaks.append(f"{name}: {value}")

    passed = not leaks
    return Finding(
        check_id="server-banner",
        category=Category.HEADERS,
        severity=Severity.LOW,
        weight=3,
        title="Version disclosure",
        passed=passed,
        detail=(
            "No product versions advertised in response headers."
            if passed
            else "Version strings exposed: " + "; ".join(leaks) + "."
        ),
        remediation="Suppress or genericise Server, X-Powered-By and X-AspNet-Version at the reverse proxy.",
        evidence="; ".join(leaks),
    )


def check_cookies(set_cookie_values: Sequence[str]) -> list[Finding]:
    """Session cookies must be Secure, HttpOnly and SameSite-scoped.

    Returns an empty list when the response sets no cookies at all - a site
    without cookies should not be penalised for cookie hygiene it never
    needed, and the score denominator simply shrinks.
    """

    if not set_cookie_values:
        return []

    secure_missing: list[str] = []
    httponly_missing: list[str] = []
    samesite_missing: list[str] = []

    for raw in set_cookie_values:
        name = _cookie_name(raw)
        flags = _cookie_flags(raw)
        if "secure" not in flags:
            secure_missing.append(name)
        if "httponly" not in flags:
            httponly_missing.append(name)
        if "samesite" not in flags:
            samesite_missing.append(name)

    findings: list[Finding] = []

    findings.append(
        Finding(
            check_id="cookie-secure",
            category=Category.COOKIES,
            severity=Severity.HIGH,
            weight=4,
            title="Cookie Secure flag",
            passed=not secure_missing,
            detail=(
                "Every cookie is marked Secure."
                if not secure_missing
                else "Cookie(s) without Secure will be sent over plain HTTP: "
                + ", ".join(secure_missing)
                + "."
            ),
            remediation="Add the Secure attribute to every cookie you set.",
        )
    )

    findings.append(
        Finding(
            check_id="cookie-httponly",
            category=Category.COOKIES,
            severity=Severity.MEDIUM,
            weight=3,
            title="Cookie HttpOnly flag",
            passed=not httponly_missing,
            detail=(
                "Every cookie is HttpOnly."
                if not httponly_missing
                else "Cookie(s) reachable from JavaScript: " + ", ".join(httponly_missing) + "."
            ),
            remediation="Add HttpOnly to session and auth cookies so injected script cannot read them.",
        )
    )

    findings.append(
        Finding(
            check_id="cookie-samesite",
            category=Category.COOKIES,
            severity=Severity.LOW,
            weight=3,
            title="Cookie SameSite attribute",
            passed=not samesite_missing,
            detail=(
                "Every cookie declares SameSite."
                if not samesite_missing
                else "Cookie(s) with no explicit SameSite: " + ", ".join(samesite_missing) + "."
            ),
            remediation="Set SameSite=Lax (or Strict) on cookies that do not need cross-site delivery.",
        )
    )

    return findings


def check_headers(headers: Mapping[str, str]) -> list[Finding]:
    """Run every header-level check in one call."""

    return [
        check_hsts(headers),
        check_csp(headers),
        check_frame_protection(headers),
        check_content_type_options(headers),
        check_referrer_policy(headers),
        check_permissions_policy(headers),
        check_cross_origin_opener(headers),
        check_server_banner(headers),
    ]


__all__ = [
    "MIN_HSTS_MAX_AGE",
    "check_content_type_options",
    "check_cookies",
    "check_cross_origin_opener",
    "check_csp",
    "check_frame_protection",
    "check_headers",
    "check_hsts",
    "check_permissions_policy",
    "check_referrer_policy",
    "check_server_banner",
]
