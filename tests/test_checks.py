"""TLS, DNS, scoring, report rendering and CLI contract tests."""

from __future__ import annotations

import json

import pytest

from posturekit.cli import EXIT_OK, EXIT_THRESHOLD, EXIT_USAGE, main
from posturekit.dns import (
    MAX_SPF_LOOKUPS,
    check_caa,
    check_dmarc,
    check_spf,
    count_spf_lookups,
    parse_dmarc,
)
from posturekit.models import Category, Finding, Severity, TlsProbe
from posturekit.prober import host_of, is_public_host, normalise_target, parse_doh_txt
from posturekit.report import AuditResult, to_json, to_markdown, to_sarif, to_text
from posturekit.scoring import failures_by_severity, grade_for, score
from posturekit.tls import ACCEPTABLE_PROTOCOLS, check_certificate_expiry, check_protocol


class TestTlsProtocol:
    def test_tls12_passes(self):
        assert check_protocol(TlsProbe("TLSv1.2", 200, True, True)).passed

    def test_tls13_passes(self):
        assert check_protocol(TlsProbe("TLSv1.3", 200, True, True)).passed

    def test_tls10_is_critical(self):
        finding = check_protocol(TlsProbe("TLSv1", 200, True, True))
        assert not finding.passed
        assert finding.severity is Severity.CRITICAL

    def test_weak_version_still_offered_fails(self):
        finding = check_protocol(TlsProbe("TLSv1.3", 200, True, True, ("TLSv1.0",)))
        assert not finding.passed
        assert "TLSv1.0" in finding.detail

    def test_acceptable_set_is_explicit(self):
        assert ACCEPTABLE_PROTOCOLS == ("TLSv1.2", "TLSv1.3")


class TestCertificateExpiry:
    def test_expired_is_critical(self):
        finding = check_certificate_expiry(TlsProbe("TLSv1.3", -3, True, True))
        assert not finding.passed
        assert finding.severity is Severity.CRITICAL

    def test_within_warning_window_fails(self):
        finding = check_certificate_expiry(TlsProbe("TLSv1.3", 5, True, True))
        assert not finding.passed
        assert finding.severity is Severity.HIGH

    def test_healthy_certificate_passes(self):
        assert check_certificate_expiry(TlsProbe("TLSv1.3", 120, True, True)).passed


class TestSpf:
    def test_absent_fails(self):
        assert not check_spf([]).passed

    def test_perfect_record_passes(self):
        finding = check_spf(["v=spf1 include:_spf.google.com -all"])
        assert finding.passed
        assert finding.category is Category.DNS

    def test_multiple_records_fail(self):
        records = ["v=spf1 include:a.example -all", "v=spf1 include:b.example -all"]
        finding = check_spf(records)
        assert not finding.passed
        assert "2 SPF records" in finding.detail

    def test_plus_all_is_critical(self):
        finding = check_spf(["v=spf1 +all"])
        assert not finding.passed
        assert finding.severity is Severity.CRITICAL

    def test_softfail_fails(self):
        finding = check_spf(["v=spf1 include:a.example ~all"])
        assert not finding.passed
        assert finding.severity is Severity.MEDIUM

    def test_non_spf_txt_is_ignored(self):
        assert check_spf(["google-site-verification=abc", "v=spf1 -all"]).passed

    @pytest.mark.parametrize(
        "record,expected",
        [
            ("v=spf1 -all", 0),
            ("v=spf1 include:a.com -all", 1),
            ("v=spf1 include:a.com include:b.com mx a -all", 4),
        ],
    )
    def test_lookup_counting(self, record, expected):
        assert count_spf_lookups(record) == expected

    def test_over_budget_fails(self):
        parts = " ".join(f"include:s{i}.example" for i in range(MAX_SPF_LOOKUPS + 2))
        assert not check_spf([f"v=spf1 {parts} -all"]).passed


class TestDmarc:
    def test_absent_fails(self):
        assert not check_dmarc([]).passed

    def test_reject_passes(self):
        finding = check_dmarc(["v=DMARC1; p=reject; rua=mailto:d@example.com"])
        assert finding.passed
        assert "strongest" in finding.detail

    def test_quarantine_passes(self):
        assert check_dmarc(["v=DMARC1; p=quarantine"]).passed

    def test_none_fails(self):
        finding = check_dmarc(["v=DMARC1; p=none"])
        assert not finding.passed
        assert finding.severity is Severity.MEDIUM

    def test_missing_rua_is_noted(self):
        finding = check_dmarc(["v=DMARC1; p=reject"])
        assert finding.passed
        assert "rua" in finding.detail

    def test_parse_extracts_tags(self):
        tags = parse_dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:a@b.c")
        assert tags["p"] == "reject"
        assert tags["sp"] == "none"


class TestCaa:
    def test_present_passes(self):
        assert check_caa(['0 issue "letsencrypt.org"']).passed

    def test_absent_fails(self):
        assert not check_caa([]).passed


class TestScoring:
    def _finding(self, passed, weight):
        return Finding("x", Category.HEADERS, Severity.LOW, weight, "t", passed, "d", "r")

    @pytest.mark.parametrize(
        "percent,letter",
        [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (79, "C"), (60, "D"), (59, "F"), (0, "F")],
    )
    def test_grade_bands(self, percent, letter):
        assert grade_for(percent) == letter

    def test_all_passed_is_100(self):
        result = score([self._finding(True, 5), self._finding(True, 5)])
        assert result.percent == 100
        assert result.grade == "A"

    def test_half_passed(self):
        result = score([self._finding(True, 5), self._finding(False, 5)])
        assert (result.earned, result.possible) == (5, 10)
        assert result.percent == 50
        assert result.grade == "F"

    def test_empty_is_perfect(self):
        assert score([]).percent == 100

    def test_failed_weights(self):
        assert score([self._finding(True, 5), self._finding(False, 5)]).failed_weights == 5

    def test_failures_sorted_by_severity(self):
        low = Finding("a", Category.HEADERS, Severity.LOW, 1, "t", False, "d", "r")
        crit = Finding("b", Category.HEADERS, Severity.CRITICAL, 1, "t", False, "d", "r")
        ok = Finding("c", Category.HEADERS, Severity.HIGH, 1, "t", True, "d", "r")
        assert [f.check_id for f in failures_by_severity([low, crit, ok])] == ["b", "a"]


class TestReport:
    def _result(self):
        findings = [
            Finding("hsts", Category.HEADERS, Severity.HIGH, 10, "HSTS", False, "missing", "add it", ""),
            Finding("caa", Category.DNS, Severity.LOW, 4, "CAA", True, "present", "keep it", ""),
        ]
        return AuditResult("https://example.com", findings, score(findings), "1.0.0")

    def test_text_lists_failures_and_score(self):
        text = to_text(self._result())
        assert "HSTS" in text
        assert "grade F" in text

    def test_markdown_has_table_and_remediation(self):
        md = to_markdown(self._result())
        assert "| Check | Layer | Result | Weight |" in md
        assert "## Remediation" in md

    def test_json_is_stable_shape(self):
        payload = json.loads(to_json(self._result()))
        assert payload["tool"]["name"] == "posturekit"
        assert payload["summary"] == {"total": 2, "passed": 1, "failed": 1}
        assert payload["score"]["grade"] == "F"

    def test_sarif_shape(self):
        sarif = to_sarif(self._result())
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "posturekit"
        assert len(run["results"]) == 1
        assert run["results"][0]["ruleId"] == "hsts"
        assert run["results"][0]["level"] == "error"

    def test_sarif_rules_cover_passing_checks_too(self):
        rules = to_sarif(self._result())["runs"][0]["tool"]["driver"]["rules"]
        assert {r["id"] for r in rules} == {"hsts", "caa"}


class TestTargetHandling:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("example.com", "https://example.com"),
            ("https://example.com", "https://example.com"),
            ("  example.com/path  ", "https://example.com/path"),
        ],
    )
    def test_normalise(self, raw, expected):
        assert normalise_target(raw) == expected

    def test_empty_target_raises(self):
        with pytest.raises(ValueError):
            normalise_target("   ")

    def test_host_extraction(self):
        assert host_of("https://Example.COM:8443/x") == "example.com"

    @pytest.mark.parametrize(
        "host,public",
        [
            ("example.com", True),
            ("8.8.8.8", True),
            ("localhost", False),
            ("127.0.0.1", False),
            ("192.168.1.10", False),
            ("10.0.0.5", False),
            ("169.254.1.1", False),
            ("router.local", False),
            ("::1", False),
        ],
    )
    def test_public_host_guard(self, host, public):
        assert is_public_host(host) is public


class TestDohParsing:
    def test_txt_records_extracted(self):
        payload = {
            "Answer": [
                {"type": 16, "data": '"v=spf1 -all"'},
                {"type": 5, "data": "alias.example."},
            ]
        }
        assert parse_doh_txt(payload) == ["v=spf1 -all"]

    def test_segmented_txt_is_joined(self):
        payload = {"Answer": [{"type": 16, "data": '"part-one" "part-two"'}]}
        assert parse_doh_txt(payload) == ["part-onepart-two"]

    def test_empty_response(self):
        assert parse_doh_txt({}) == []


class TestCliContract:
    def test_private_target_refused_without_opt_in(self):
        assert main(["127.0.0.1"]) == EXIT_USAGE

    def test_localhost_refused(self):
        assert main(["localhost"]) == EXIT_USAGE

    def test_empty_target_rejected(self):
        assert main(["   "]) == EXIT_USAGE

    def test_grade_order_is_monotonic(self):
        from posturekit.cli import GRADE_ORDER, _grade_rank

        ranks = [_grade_rank(letter) for letter in GRADE_ORDER]
        assert ranks == sorted(ranks)

    def test_exit_codes_distinct(self):
        assert len({EXIT_OK, EXIT_THRESHOLD, EXIT_USAGE}) == 3
