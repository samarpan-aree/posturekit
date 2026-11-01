"""Command-line entry point.

Design notes:

* Exit codes are stable so this works as a CI gate: 0 met the threshold,
  1 fell below it, 2 was a usage or network problem.
* Output format is a flag, not a separate binary, so a GitHub Action is a
  three-line YAML file.
* Scanning is refuse-by-default for private address space. Auditing your own
  internal estate is legitimate, so there is an explicit opt-in.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .prober import audit, host_of, is_public_host, normalise_target
from .report import to_json, to_markdown, to_sarif, to_text

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_USAGE = 2

GRADE_ORDER = ("F", "D", "C", "B", "A")
FORMATS = ("text", "json", "markdown", "sarif")


def _grade_rank(grade: str) -> int:
    try:
        return GRADE_ORDER.index(grade.upper())
    except ValueError:
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="posturekit",
        description=(
            "Audit the external security posture of a host you own: HTTP security "
            "headers, cookies, TLS and DNS email authentication."
        ),
        epilog=(
            "Only scan hosts you own or are authorised to test. Private address "
            "space requires --allow-private."
        ),
    )
    parser.add_argument("target", help="host or URL, e.g. example.com or https://example.com")
    parser.add_argument(
        "--format",
        "-f",
        default="text",
        choices=FORMATS,
        help="output format (default: text)",
    )
    parser.add_argument("--output", "-o", default="", help="write the report to a file")
    parser.add_argument(
        "--min-grade",
        "-g",
        default="F",
        choices=GRADE_ORDER,
        help="fail the run below this grade (default: F, i.e. never fail)",
    )
    parser.add_argument(
        "--skip",
        default="",
        help="comma-separated layers to skip: headers,cookies,tls,dns",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="per-probe timeout in seconds")
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="permit scanning private, loopback or reserved addresses you own",
    )
    parser.add_argument("--doh-url", default="", help="override the DNS-over-HTTPS resolver")
    parser.add_argument("--version", action="version", version=f"posturekit {__version__}")
    return parser


def _render(result, fmt: str) -> str:  # type: ignore[no-untyped-def]
    if fmt == "json":
        return to_json(result) + "\n"
    if fmt == "markdown":
        return to_markdown(result)
    if fmt == "sarif":
        return json.dumps(to_sarif(result), indent=2) + "\n"
    return to_text(result)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        url = normalise_target(args.target)
    except ValueError:
        print("posturekit: target must not be empty", file=sys.stderr)
        return EXIT_USAGE

    host = host_of(url)
    if not host:
        print(f"posturekit: could not parse a host from {args.target!r}", file=sys.stderr)
        return EXIT_USAGE

    if not args.allow_private and not is_public_host(host):
        print(
            f"posturekit: {host} is a private, loopback, reserved or local address.\n"
            "Only scan hosts you own. Re-run with --allow-private if this is yours.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    skip = [item.strip() for item in args.skip.split(",") if item.strip()]
    kwargs = {"timeout": args.timeout, "skip": skip}
    if args.doh_url:
        kwargs["doh_url"] = args.doh_url

    result = audit(args.target, version=__version__, **kwargs)  # type: ignore[arg-type]
    rendered = _render(result, args.format)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        print(f"posturekit: wrote {args.format} report to {args.output}")
    else:
        sys.stdout.write(rendered)

    if _grade_rank(result.score.grade) < _grade_rank(args.min_grade):
        print(
            f"posturekit: grade {result.score.grade} is below the required "
            f"{args.min_grade}",
            file=sys.stderr,
        )
        return EXIT_THRESHOLD

    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
