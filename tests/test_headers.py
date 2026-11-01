"""Header and cookie checks. Every case is a pure function call."""

from __future__ import annotations

import pytest

from posturekit.headers import (
    MIN_HSTS_MAX_AGE,
    check_content_type_options,
    check_cookies,
    check_cross_origin_opener,
    check_csp,
    check_frame_protection,
    check_hsts,
    check_permissions_policy,
    check_referrer_policy,
    check_server_banner,
)
from posturekit.models import Category, Severity

GOOD_HSTS = "max-age=31536000; includeSubDomains"
GOOD_CSP = "default-src 'self'; script-src 'nonce-abc123'; frame-ancestors 'none'"


class TestHsts:
    def test_missing_header_fails_high(self):
        finding = check_hsts({})
        assert not finding.passed
        assert finding.severity is Severity.HIGH
        assert finding.category is Category.HEADERS

    def test_full_policy_passes(self):
        finding = check_hsts({"Strict-Transport-Security": GOOD_HSTS})
        assert finding.passed
        assert "max-age=31536000s" in finding.detail
        assert "includeSubDomains" in finding.detail

    def test_short_max_age_fails_medium(self):
        finding = check_hsts({"strict-transport-security": "max-age=300; includeSubDomains"})
        assert not finding.passed
        assert finding.severity is Severity.MEDIUM

    def test_missing_subdomains_still_fails_low(self):
        finding = check_hsts({"strict-transport-security": "max-age=31536000"})
        assert not finding.passed
        assert finding.severity is Severity.LOW

    def test_header_name_is_case_insensitive(self):
        assert check_hsts({"STRICT-TRANSPORT-SECURITY": GOOD_HSTS}).passed

    def test_never_passes_without_remediation(self):
        assert check_hsts({}).remediation


class TestCsp:
    def test_missing_fails(self):
        finding = check_csp({})
        assert not finding.passed
        assert finding.severity is Severity.HIGH

    def test_nonce_policy_passes(self):
        assert check_csp({"Content-Security-Policy": GOOD_CSP}).passed

    @pytest.mark.parametrize(
        "policy",
        [
            "default-src 'self'; script-src 'unsafe-inline'",
            "default-src 'self'; script-src 'unsafe-eval'",
            "script-src *",
            "img-src 'self'",
        ],
    )
    def test_weak_policies_fail(self, policy):
        finding = check_csp({"Content-Security-Policy": policy})
        assert not finding.passed
        assert "weakened by" in finding.detail


class TestFrameProtection:
    def test_frame_ancestors_is_accepted(self):
        finding = check_frame_protection({"content-security-policy": GOOD_CSP})
        assert finding.passed
        assert "frame-ancestors" in finding.detail

    def test_x_frame_options_is_accepted(self):
        assert check_frame_protection({"x-frame-options": "DENY"}).passed

    def test_neither_fails(self):
        assert not check_frame_protection({}).passed


class TestContentTypeOptions:
    def test_nosniff_passes(self):
        assert check_content_type_options({"x-content-type-options": "nosniff"}).passed

    def test_wrong_value_fails(self):
        assert not check_content_type_options({"x-content-type-options": "none"}).passed

    @pytest.mark.parametrize("value", ["NOSNIFF", " nosniff "])
    def test_normalised_value_passes(self, value):
        assert check_content_type_options({"x-content-type-options": value}).passed


class TestReferrerPolicy:
    def test_present_passes(self):
        assert check_referrer_policy({"referrer-policy": "strict-origin-when-cross-origin"}).passed

    def test_unsafe_url_fails(self):
        assert not check_referrer_policy({"referrer-policy": "unsafe-url"}).passed

    def test_absent_fails(self):
        assert not check_referrer_policy({}).passed


class TestPermissionsPolicy:
    def test_present_passes(self):
        assert check_permissions_policy({"permissions-policy": "camera=()"}).passed

    def test_legacy_feature_policy_is_accepted(self):
        assert check_permissions_policy({"feature-policy": "camera 'none'"}).passed

    def test_absent_fails(self):
        assert not check_permissions_policy({}).passed


class TestCoop:
    def test_present_passes(self):
        assert check_cross_origin_opener({"cross-origin-opener-policy": "same-origin"}).passed

    def test_absent_fails(self):
        assert not check_cross_origin_opener({}).passed


class TestServerBanner:
    def test_version_string_fails(self):
        finding = check_server_banner({"server": "nginx/1.18.0"})
        assert not finding.passed
        assert "nginx/1.18.0" in finding.evidence

    def test_bare_product_passes(self):
        assert check_server_banner({"server": "nginx"}).passed

    def test_x_powered_by_version_fails(self):
        assert not check_server_banner({"x-powered-by": "PHP/8.1.2"}).passed


class TestCookies:
    def test_no_cookies_produces_no_findings(self):
        assert check_cookies([]) == []

    def test_hardened_cookie_passes_every_check(self):
        findings = check_cookies(["sid=abc; Secure; HttpOnly; SameSite=Lax"])
        assert len(findings) == 3
        assert all(f.passed for f in findings)

    def test_bare_cookie_fails_all_three(self):
        findings = check_cookies(["sid=abc"])
        assert {f.check_id for f in findings} == {
            "cookie-secure",
            "cookie-httponly",
            "cookie-samesite",
        }
        assert not any(f.passed for f in findings)

    def test_names_the_offending_cookie(self):
        findings = check_cookies(
            ["session=abc; HttpOnly", "theme=dark; Secure; HttpOnly; SameSite=Lax"]
        )
        secure = next(f for f in findings if f.check_id == "cookie-secure")
        assert "session" in secure.detail
        assert "theme" not in secure.detail
