"""The only module that touches the network.

Three collection surfaces, each with a matching pure-parsing helper so the
logic stays testable offline:

* HTTP  - one GET, capture status, headers and the redirect chain.
* TLS   - one handshake, capture protocol, expiry, hostname and chain.
* DNS   - TXT lookups over DNS-over-HTTPS (no dnspython, no UDP socket).

Everything network-bound is wrapped so an unreachable target produces a
finding, never a traceback.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Sequence

from .dns import check_dns
from .headers import check_cookies, check_headers
from .models import Category, Finding, Severity, TlsProbe
from .report import AuditResult
from .scoring import score
from .tls import check_tls

#: Cloudflare's DoH endpoint speaks the JSON API, which needs no dependencies.
DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query"

#: Hosts we refuse to touch without an explicit opt-in.
_RESERVED_SUFFIXES = (".local", ".internal", ".localhost")


def is_public_host(host: str) -> bool:
    """True when *host* is a name or address outside private/reserved space.

    This is a safety rail, not a security control: it stops the tool being
    pointed at someone else's internal network by accident, and gives an
    explicit opt-in for the case where you are auditing your own.
    """

    if not host:
        return False

    lowered = host.lower().strip("[]")
    if lowered in ("localhost", "::1"):
        return False
    for suffix in _RESERVED_SUFFIXES:
        if lowered.endswith(suffix):
            return False

    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return True  # a DNS name; the address class is unknown until resolved

    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
    )


def normalise_target(target: str) -> str:
    """Accept 'example.com', 'example.com/path' or a full URL."""

    text = (target or "").strip()
    if not text:
        raise ValueError("empty target")
    if "://" not in text:
        text = "https://" + text
    return text


def host_of(target: str) -> str:
    return urllib.parse.urlsplit(normalise_target(target)).hostname or ""


@dataclass
class HttpResponse:
    """What one GET actually returned."""

    final_url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    error: str = ""


class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
    """Keep the hop list, which is how we detect a plain-HTTP first leg."""

    def __init__(self) -> None:
        self.chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str, timeout: float = 10.0, user_agent: str = "posturekit/1.0") -> HttpResponse:
    """One GET, no retries, no crawling. Failures come back as data."""

    recorder = _RedirectRecorder()
    opener = urllib.request.build_opener(recorder)
    request = urllib.request.Request(url, method="GET")
    request.add_header("User-Agent", user_agent)
    request.add_header("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.headers
            headers = {k: v for k, v in raw.items()}
            return HttpResponse(
                final_url=response.geturl(),
                status=response.status,
                headers=headers,
                set_cookies=raw.get_all("Set-Cookie") or [],
                redirect_chain=list(recorder.chain),
            )
    except urllib.error.HTTPError as exc:
        # A 4xx/5xx is still a real response with real headers worth grading.
        raw_headers = exc.headers
        headers = {k: v for k, v in raw_headers.items()} if raw_headers else {}
        cookies = (raw_headers.get_all("Set-Cookie") if raw_headers else None) or []
        return HttpResponse(
            final_url=url,
            status=exc.code,
            headers=headers,
            set_cookies=cookies,
            redirect_chain=list(recorder.chain),
        )
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
        return HttpResponse(final_url=url, status=0, error=str(exc))


def days_until(moment: str) -> int:
    """Days from now until a notAfter string, negative when already expired."""

    parsed = datetime.strptime(moment, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    delta = parsed - datetime.now(timezone.utc)
    return int(delta.total_seconds() // 86400)


def probe_tls(host: str, port: int = 443, timeout: float = 10.0) -> tuple[TlsProbe | None, str]:
    """One verified handshake, then separate attempts at deprecated versions.

    Returns ``(probe, error)``. A failure to connect is reported, not raised.
    """

    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                certificate = tls_sock.getpeercert() or {}
                protocol = tls_sock.version() or "unknown"
    except ssl.SSLCertVerificationError as exc:
        return None, f"certificate verification failed: {exc.verify_message}"
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        return None, f"TLS handshake failed: {exc}"

    expiry = certificate.get("notAfter", "")
    try:
        expires_in = days_until(expiry)
    except (ValueError, TypeError):
        expires_in = -1

    hostname_valid = False
    if certificate:
        try:
            if hasattr(ssl, "match_hostname"):  # removed in 3.12
                ssl.match_hostname(certificate, host)  # type: ignore[attr-defined]
                hostname_valid = True
            else:
                hostname_valid = True  # handshake already validated the name
        except ssl.CertificateError:
            hostname_valid = False

    weak: list[str] = []
    for label, version in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        if _accepts_version(host, port, version, timeout):
            weak.append(label)

    probe = TlsProbe(
        protocol=protocol,
        certificate_expires_in_days=expires_in,
        certificate_hostname_valid=hostname_valid,
        chain_trusted=True,  # reaching here means the chain already verified
        weak_protocols_supported=tuple(weak),
    )
    return probe, ""


def _accepts_version(host: str, port: int, version: "ssl.TLSVersion", timeout: float) -> bool:
    """True when the host completes a handshake at *version*."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return False  # the local OpenSSL refuses to even offer it

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, socket.timeout, OSError):
        return False


def parse_doh_txt(payload: dict) -> list[str]:
    """Flatten a DoH JSON response into the TXT strings it carries."""

    answers = payload.get("Answer") or []
    records: list[str] = []
    for answer in answers:
        if answer.get("type") != 16:  # TXT
            continue
        data = str(answer.get("data", ""))
        # DoH JSON wraps each character-string in quotes; join the segments.
        if data.startswith('"'):
            data = "".join(part.strip('"') for part in data.split('" "'))
            data = data.strip('"')
        records.append(data)
    return records


def resolve_txt(name: str, doh_url: str = DEFAULT_DOH_URL, timeout: float = 10.0) -> list[str]:
    """TXT records for *name* over DoH. Returns [] on any failure."""

    query = urllib.parse.urlencode({"name": name, "type": "TXT"})
    request = urllib.request.Request(f"{doh_url}?{query}")
    request.add_header("Accept", "application/dns-json")

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return parse_doh_txt(json.loads(response.read().decode("utf-8")))
    except (urllib.error.URLError, socket.timeout, json.JSONDecodeError, OSError, UnicodeDecodeError):
        return []


def resolve_caa(name: str, doh_url: str = DEFAULT_DOH_URL, timeout: float = 10.0) -> list[str]:
    """CAA records for *name* over DoH. Returns [] on any failure."""

    query = urllib.parse.urlencode({"name": name, "type": "CAA"})
    request = urllib.request.Request(f"{doh_url}?{query}")
    request.add_header("Accept", "application/dns-json")

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, socket.timeout, json.JSONDecodeError, OSError, UnicodeDecodeError):
        return []

    values: list[str] = []
    for answer in payload.get("Answer") or []:
        if answer.get("type") == 257:  # CAA
            values.append(str(answer.get("data", "")))
    return values


def _error_finding(check_id: str, title: str, detail: str, weight: int) -> Finding:
    return Finding(
        check_id=check_id,
        category=Category.TRANSPORT,
        severity=Severity.INFO,
        weight=weight,
        title=title,
        passed=False,
        detail=detail,
        remediation="Confirm the host is reachable and try again.",
    )


def audit(
    target: str,
    version: str = "1.0.0",
    timeout: float = 10.0,
    skip: Sequence[str] = (),
    doh_url: str = DEFAULT_DOH_URL,
) -> AuditResult:
    """Run every check layer against *target* and package the result."""

    url = normalise_target(target)
    host = host_of(url)
    skipped = {item.lower() for item in skip}
    findings: list[Finding] = []

    if "headers" not in skipped or "cookies" not in skipped:
        response = fetch(url, timeout=timeout)
        if response.error:
            findings.append(
                _error_finding("http-reachable", "HTTP reachability", response.error, 5)
            )
        else:
            if "headers" not in skipped:
                findings.extend(check_headers(response.headers))
            if "cookies" not in skipped:
                findings.extend(check_cookies(response.set_cookies))

    if "tls" not in skipped:
        probe, error = probe_tls(host, timeout=timeout)
        if probe is None:
            findings.append(_error_finding("tls-handshake", "TLS handshake", error, 12))
        else:
            findings.extend(check_tls(probe))

    if "dns" not in skipped and host:
        txt = resolve_txt(host, doh_url=doh_url, timeout=timeout)
        dmarc = resolve_txt(f"_dmarc.{host}", doh_url=doh_url, timeout=timeout)
        caa = resolve_caa(host, doh_url=doh_url, timeout=timeout)
        findings.extend(check_dns(txt, dmarc, caa))

    return AuditResult(
        target=url,
        findings=findings,
        score=score(findings),
        version=version,
    )


__all__ = [
    "DEFAULT_DOH_URL",
    "HttpResponse",
    "audit",
    "days_until",
    "fetch",
    "host_of",
    "is_public_host",
    "normalise_target",
    "parse_doh_txt",
    "probe_tls",
    "resolve_caa",
    "resolve_txt",
]
