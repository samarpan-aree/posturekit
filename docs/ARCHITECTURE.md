# Architecture

## The one constraint that shaped everything

Every check must be testable without a network. That single rule produced the
module split.

```
posturekit/
├── models.py     Finding, Severity, Category, TlsProbe   (no logic)
├── headers.py    pure: Mapping[str, str] -> Finding
├── tls.py        pure: TlsProbe -> Finding
├── dns.py        pure: list[str] -> Finding
├── scoring.py    pure: list[Finding] -> Score
├── report.py     pure: AuditResult -> str | dict
├── prober.py     THE ONLY FILE WITH SOCKETS
└── cli.py        argparse, exit codes, output routing
```

`prober.py` collects, everything else decides. A check module that needed a
socket could not be tested against the case that matters most: a server sending
a malformed header.

## Data model

```python
@dataclass(frozen=True)
class Finding:
    check_id: str      # stable identifier, appears in SARIF ruleId
    category: Category # transport | headers | cookies | dns
    severity: Severity # critical | high | medium | low | info
    weight: int        # contribution to the score
    title: str         # human name
    passed: bool       # the only verdict
    detail: str        # what was observed and why it matters
    remediation: str   # what to do - never optional
    evidence: str      # the raw header / record / protocol string
```

Frozen so a finding cannot be mutated after a check returns it, and so a list of
findings is safe to sort and reuse across renderers.

`remediation` is required, not optional. A tool that tells you something is wrong
without telling you how to fix it has moved the work back onto you.

## Scoring

```python
def score(findings):
    possible = sum(f.weight for f in findings)
    earned   = sum(f.weight for f in findings if f.passed)
    return Score(earned=earned, possible=possible)
```

There is no central weight table. Weight lives on the finding, which means:

- Adding a check automatically widens the denominator.
- A check that only applies conditionally can simply not be emitted - the
  denominator shrinks and the percentage stays honest. This is what happens for
  cookies: a site that sets none is not penalised for cookie hygiene it never
  needed, because `check_cookies([])` returns `[]`.
- `percent == 100` for an empty finding list, which is correct: nothing was
  checked, nothing failed.

Grade bands are `A >= 90`, `B >= 80`, `C >= 70`, `D >= 60`, `F` below.

### Deliberate severity choices

| Situation | Severity | Why |
| --- | --- | --- |
| `+all` in SPF | **critical** | Works as an explicit authorisation for the whole internet to send as you - strictly worse than no SPF |
| TLS 1.0 negotiated | **critical** | Known downgrade and padding-oracle territory |
| Certificate expired | **critical** | An outage with a security label |
| HSTS present but short `max-age` | medium | The mechanism is there, the policy is too weak to survive a return visit |
| HSTS present, no `includeSubDomains` | low | Main host protected, siblings exposed |
| Version string in `Server` | low | Reconnaissance, not a vulnerability |

The point of grading this way is that severity drives order in the report, and
order is what a reader acts on.

## Network layer

### HTTP

One `GET`, using `urllib` with a custom `HTTPRedirectHandler` that records each
hop. A `4xx`/`5xx` is still a real response with real headers worth grading, so
`HTTPError` is caught and parsed rather than discarded - a 404 on `/` may still
serve a hardened header set, and a 500 that leaks `Server: nginx/1.18.0` is a
genuine finding.

### TLS

`ssl.create_default_context()`, one verified handshake. Reaching the far side of
that call is itself proof the chain validated, which is why `chain_trusted` is
set on arrival rather than checked again.

Deprecated protocol detection needs separate handshakes with
`minimum_version == maximum_version` set to the version under test. If the local
OpenSSL refuses to even offer it (`set_ciphers` raising), the check reports "not
accepted" rather than "good" - failing closed on an inconclusive probe.

`ssl.match_hostname` was removed in Python 3.12, so the hostname check branches:
use it where present, and where absent rely on the verified handshake, which
already performed the same validation.

### DNS

Over DNS-over-HTTPS against Cloudflare's JSON API. No `dnspython`, no UDP socket,
no resolver configuration to get wrong, and it works from CI runners behind an
egress proxy that blocks outbound port 53. A failed lookup returns `[]` and the
SPF/DMARC check then reports "missing" - which is the honest reading, since an
unreachable record and an absent record both mean you cannot rely on it.

`parse_doh_txt` handles the one fiddly part: DoH wraps each character-string of a
TXT record in its own pair of quotes, so a record split across segments arrives
as `"part-one" "part-two"` and must be rejoined into `part-onepart-two`.

## Call budget

A full scan is **five** network operations:

1. one `GET` (plus redirects the server chooses)
2. one verified TLS handshake
3. up to two unverified handshakes, only for TLS 1.0/1.1
4. three DoH queries (`TXT`, `_dmarc` `TXT`, `CAA`)

Deliberately small. This is a posture check, not a recon tool, and the difference
is measurable in the logs of the system you point it at.

## Test strategy

100 tests, none touching the network.

- **Check modules** are exercised with literal header mappings and record
  strings. Each case asserts both the verdict *and* the severity, because
  severity is what orders the report.
- **Negative cases dominate.** A checker that never fires is worthless; most
  tests assert that a specific weakness is caught.
- **Scoring** is tested at the band boundaries (89 vs 90, 79 vs 80) rather than
  in the middle, where a threshold bug would hide.
- **Renderers** are tested for shape, not wording: that SARIF has
  `version: 2.1.0`, that every rule appears even for passing checks, that only
  failures become results.
- **CLI contract** is tested for exit codes and the private-address guard -
  the two behaviours a CI pipeline depends on.

## Known limitations

- No IPv6-aware redirect analysis: the tool grades the final URL, not the path
  taken to it.
- DKIM is not checked. Selector discovery is not safely automatable without a
  wordlist, and a guessed selector produces false "missing" results.
- `Permissions-Policy` syntax is checked for presence, not parsed for whether the
  directives are sensible for the page.
- The grade is a comparative signal, not compliance. An `A` does not mean
  "audited"; it means the eighteen things this tool looks at look right.
