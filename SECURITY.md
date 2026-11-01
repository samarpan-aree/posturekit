# Ethical use and responsible disclosure

## Intended use

`posturekit` is a **defensive** tool. It reads what a server already sends to
any anonymous visitor - response headers, a TLS handshake, and public DNS
records - and grades the result. It performs no exploitation, no injection, no
credential guessing, and no crawling beyond a single redirect chain.

**Only run it against hosts you own or have documented written authorisation to
test.** Unauthorised scanning is illegal in most jurisdictions, including under
the Computer Misuse Act (UK), the Computer Fraud and Abuse Act (US) and
comparable legislation elsewhere.

The tool enforces this by default: private, loopback and reserved addresses are
refused unless you pass `--allow-private`, which exists for auditing your own
internal estate.

## What it will never do

- Send a request body, or attempt authentication
- Probe for vulnerabilities beyond checking which TLS versions a server accepts
- Follow links, crawl pages, or enumerate paths
- Resolve subdomains or scan ports
- Retain or transmit scan data anywhere

## Reporting a vulnerability in posturekit

If you find a security problem in this project itself, please do **not** open a
public issue. Report it privately via GitHub's private vulnerability reporting
on the Security tab of this repository, with:

- affected version
- a minimal reproduction
- the impact you believe it has

You can expect an acknowledgement within 72 hours and a fix or mitigation
within 30 days for confirmed issues. Credit will be given in the release notes
unless you prefer otherwise.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | yes |
