"""Smoke scenarios: the acceptance criteria of the local bench."""

from __future__ import annotations

import itertools
from collections.abc import Callable
from pathlib import Path

from .client import HTTP_VERSIONS
from .matrix import Cell, Matrix
from .runner import Context, probe, run_cell, run_matrix

# Acceptance criterion of the local bench: "a 64 kB header is rejected".
OVERSIZE_HEADER_BYTES = 64 * 1024
BASELINE = ("ES256", "access_token_rfc9068", "kid", "authorization")


class SmokeFailure(AssertionError):
    pass


def baseline_everywhere(context: Context, matrix: Matrix, log: Callable[[str], None]) -> None:
    """An ES256 token crosses every intermediary with the verdict ok."""
    variant, profile, header_variant, channel = BASELINE
    chains = [()] + [(name,) for name in matrix.intermediaries]
    for chain, version in itertools.product(chains, HTTP_VERSIONS):
        cell = Cell(variant, profile, header_variant, channel, chain, version, matrix.config_profile)
        result = run_cell(context, cell)
        log(f"  {cell.chain_label:<10} HTTP/{result['http_version'] or '?':<4} {result['verdict']} {result['detail']}")
        if result["verdict"] != "ok":
            raise SmokeFailure(f"ES256 token through {cell.chain_label} (HTTP/{version}): {result['verdict']}")


def expected_culprit(chain: tuple[str, ...], rejects_alone: dict[str, bool]) -> str | None:
    """First component of the chain that refuses the request when addressed alone."""
    return next((name for name in chain if rejects_alone[name]), None)


def oversize_attribution(context: Context, matrix: Matrix, log: Callable[[str], None]) -> None:
    """A 64 kB header is rejected and the component at fault is named in two-hop chains.

    The reference is measured, not assumed: each intermediary is first probed
    alone, then every ordered pair is checked against the first component of
    the pair that refused alone.
    """
    rejects_alone: dict[str, bool] = {}
    for name in matrix.intermediaries:
        outcome = probe(context, "authorization", OVERSIZE_HEADER_BYTES, (name,))[2]
        rejects_alone[name] = outcome.verdict != "ok"
        log(f"  {name:<10} alone: {outcome.verdict} {outcome.detail} ({outcome.attribution})")
        if rejects_alone[name] and outcome.attributed_to != name:
            raise SmokeFailure(f"{name} alone: rejection attributed to {outcome.attributed_to}")
    if not any(rejects_alone.values()):
        raise SmokeFailure("no intermediary rejected the oversized header")

    for chain in itertools.permutations(matrix.intermediaries, 2):
        outcome = probe(context, "authorization", OVERSIZE_HEADER_BYTES, chain)[2]
        culprit = expected_culprit(chain, rejects_alone)
        label = ">".join(chain)
        log(f"  {label:<18} {outcome.verdict:<16} attributed to {outcome.attributed_to} ({outcome.attribution})")
        if culprit is None:
            if outcome.verdict != "ok":
                raise SmokeFailure(f"{label}: both hops accept alone, the chain gives {outcome.verdict}")
        elif outcome.verdict == "ok" or outcome.attributed_to != culprit:
            raise SmokeFailure(f"{label}: expected a rejection by {culprit}, got {outcome}")


def run(context: Context, matrix: Matrix, results_root: Path, log: Callable[[str], None] = print) -> None:
    log("1. ES256 token through every intermediary")
    baseline_everywhere(context, matrix, log)
    log(f"2. {OVERSIZE_HEADER_BYTES}-byte header: rejection and attribution")
    oversize_attribution(context, matrix, log)
    log(f"3. matrix '{matrix.name}' ({len(matrix.cells)} cells)")
    directory, counts = run_matrix(context, matrix, results_root)
    for verdict, count in sorted(counts.items()):
        log(f"  {verdict:<20} {count}")
    log(f"  results written to {directory}")
