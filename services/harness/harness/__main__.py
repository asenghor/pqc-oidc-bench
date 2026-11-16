"""Command line of the harness.

    python -m harness wait        wait until every component answers
    python -m harness smoke       acceptance scenarios, then the matrix
    python -m harness run         the matrix only
    python -m harness threshold   bisect the size a chain accepts on a channel
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

import httpx2

from . import smoke
from .channels import CHANNELS
from .client import HTTP_VERSIONS, Emitter, Transport, base_url, tls_client_factory
from .matrix import load_matrix
from .runner import Context, run_matrix
from .threshold import DEFAULT_UPPER_BOUND, find_threshold

READINESS_TIMEOUT_SECONDS = 120  # bench setting


def _settings() -> tuple[Path, Path, Path]:
    certs = Path(os.environ.get("CERTS_DIR", "/certs"))
    matrix = Path(os.environ.get("MATRIX_FILE", "bench/matrix.yaml"))
    results = Path(os.environ.get("RESULTS_DIR", "results/_local"))
    return certs, matrix, results


def _context(certs: Path) -> Context:
    factory = tls_client_factory(str(certs / "ca.crt"))
    lab_key = (certs / "lab-key").read_text(encoding="ascii").strip()
    return Context(Transport(factory), Emitter(factory), lab_key)


def wait(certs: Path, components: list[str]) -> int:
    """Poll /healthz on the emitter, the echo backend and through every intermediary."""
    deadline = time.monotonic() + READINESS_TIMEOUT_SECONDS
    pending = ["emitter", "echo", *components]
    while pending and time.monotonic() < deadline:
        still_pending = []
        for component in pending:
            try:
                with tls_client_factory(str(certs / "ca.crt"))("1.1") as client:
                    ready = client.get(base_url(component) + "/healthz").status_code == 200
            except (httpx2.HTTPError, OSError):
                ready = False
            if not ready:
                still_pending.append(component)
        pending = still_pending
        if pending:
            time.sleep(1)
    if pending:
        print(f"not ready after {READINESS_TIMEOUT_SECONDS} s: {', '.join(pending)}", file=sys.stderr)
        return 1
    print("every component answers")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("wait")
    commands.add_parser("smoke")
    commands.add_parser("run")
    threshold = commands.add_parser("threshold")
    threshold.add_argument("--chain", default="", help="comma-separated intermediaries, empty for direct")
    threshold.add_argument("--channel", choices=CHANNELS, default="authorization")
    threshold.add_argument("--http", choices=HTTP_VERSIONS, default="1.1")
    threshold.add_argument("--upper", type=int, default=DEFAULT_UPPER_BOUND)
    arguments = parser.parse_args(argv)

    certs, matrix_file, results = _settings()
    matrix = load_matrix(matrix_file)
    if arguments.command == "wait":
        return wait(certs, list(matrix.intermediaries))

    context = _context(certs)
    if arguments.command == "smoke":
        try:
            smoke.run(context, matrix, results)
        except smoke.SmokeFailure as failure:
            print(f"SMOKE FAILED: {failure}", file=sys.stderr)
            return 1
        print("smoke passed")
        return 0
    if arguments.command == "run":
        directory, counts = run_matrix(context, matrix, results)
        print(f"{sum(counts.values())} cells: {counts}; results in {directory}")
        return 0

    chain = tuple(filter(None, arguments.chain.split(",")))
    largest, refusal = find_threshold(context, arguments.channel, chain, arguments.http, arguments.upper)
    label = ">".join(chain) or "direct"
    if largest is None:
        print(f"{label} {arguments.channel} HTTP/{arguments.http}: nothing accepted ({refusal})")
    elif refusal is None:
        print(f"{label} {arguments.channel} HTTP/{arguments.http}: no refusal up to {largest} characters")
    else:
        print(
            f"{label} {arguments.channel} HTTP/{arguments.http}: largest accepted filler {largest} characters; "
            f"one more gives {refusal.verdict} attributed to {refusal.attributed_to} "
            f"({refusal.attribution}, {refusal.detail})"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
