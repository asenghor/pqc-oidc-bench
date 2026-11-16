"""Bisection of the exact size at which a chain stops accepting a channel."""

from __future__ import annotations

from collections.abc import Callable

from .runner import Context, probe
from .verdict import Outcome

# Bench setting: upper bound of the search, well above the default limits of
# HTTP intermediaries. A chain that still accepts it is reported as unbounded
# within the search range.
DEFAULT_UPPER_BOUND = 4 * 1024 * 1024


def bisect(accepts: Callable[[int], bool], low: int, high: int) -> int | None:
    """Largest size in [low, high] that `accepts`, assuming acceptance is monotonic.

    Returns None when even `low` is refused, and `high` when nothing is
    refused in the range.
    """
    if not accepts(low):
        return None
    if accepts(high):
        return high
    while high - low > 1:
        middle = (low + high) // 2
        if accepts(middle):
            low = middle
        else:
            high = middle
    return low


def find_threshold(
    context: Context, channel: str, chain: tuple[str, ...], http_version: str = "1.1", upper: int = DEFAULT_UPPER_BOUND
) -> tuple[int | None, Outcome | None]:
    """Largest accepted filler size, and the outcome one character above it."""
    last_refusal: dict[int, Outcome] = {}

    def accepts(size: int) -> bool:
        outcome = probe(context, channel, size, chain, http_version)[2]
        if outcome.verdict != "ok":
            last_refusal[size] = outcome
        return outcome.verdict == "ok"

    largest = bisect(accepts, 1, upper)
    if largest is None:
        return None, last_refusal.get(1)
    return largest, last_refusal.get(largest + 1)
