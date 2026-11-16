"""Attribution of a response to a component, and verdict of a cell.

Attribution relies on the X-Hop-<name> response headers. Every intermediary
sets its own to "proxied" on a response it relays and to "origin" on a
response it produces itself; the echo backend sets X-Hop-Echo. Some early
rejections (a request refused while it is parsed) leave no header at all.

Walking the chain from the entry point:

- "origin": this component produced the response (attribution `tagged`);
- no header: this component is at fault but left no tag (attribution
  `untagged`). Either it produced an untagged response that the previous hop
  relayed, or it gave no HTTP answer and the previous hop reported the
  failure with a status of its own;
- "proxied": the response comes from further down, move to the next hop.

Verdicts
--------
ok                  the echo received exactly what was sent
silent_degradation  no error was reported, but what arrived differs from
                    what was sent (truncated, dropped or altered)
explicit_reject     an HTTP error attributed to a component, or a connection
                    closed without any HTTP response
upstream_error      a gateway failure: 502, 503 or 504, or a 5xx reported on
                    behalf of a hop that left no tag
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .channels import WATCHED_HEADERS, Request, entry_point

ECHO = "echo"
VERDICTS = ("ok", "silent_degradation", "explicit_reject", "upstream_error")
_GATEWAY_STATUSES = (502, 503, 504)  # RFC 9110, Sections 15.6.3 to 15.6.5


@dataclass(frozen=True)
class Observation:
    """What came back for one request."""

    status: int | None = None
    http_version: str = ""
    hops: dict[str, str] | None = None  # component -> role, from X-Hop-* headers
    report: dict[str, Any] | None = None  # JSON document of the echo backend, if any
    error: str = ""  # transport failure, when there is no HTTP response
    latency_ms: float = 0.0


@dataclass(frozen=True)
class Outcome:
    verdict: str
    attributed_to: str
    attribution: str  # tagged | untagged
    detail: str = ""


def attribute(chain: tuple[str, ...], hops: dict[str, str]) -> tuple[str, str]:
    """Component the response is attributed to, and how: tagged or untagged."""
    for component in chain:
        role = hops.get(component)
        if role is None:
            return component, "untagged"
        if role != "proxied":
            return component, "tagged"
    return ECHO, "tagged" if ECHO in hops else "untagged"


def _measure(value: bytes) -> dict[str, Any]:
    return {"length": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def _compare(name: str, sent: bytes, received: dict[str, Any] | None) -> str:
    expected = _measure(sent)
    if received == expected:
        return ""
    if not isinstance(received, dict) or "length" not in received:
        return f"{name}:missing"
    if received["length"] < expected["length"]:
        return f"{name}:truncated(sent={expected['length']},received={received['length']})"
    return f"{name}:altered(sent={expected['length']},received={received['length']})"


def differences(request: Request, report: dict[str, Any]) -> list[str]:
    """Everything the echo received that differs from what was sent."""
    found = []
    watched = report.get("watched_headers") or {}
    for name in WATCHED_HEADERS:
        entry = watched.get(name) or {"count": 0, "values": []}
        sent = request.watched.get(name)
        if sent is None:
            if entry["count"]:
                found.append(f"{name}:unexpected")
        elif entry["count"] == 0:
            found.append(f"{name}:dropped")
        elif entry["count"] > 1:
            found.append(f"{name}:split(count={entry['count']})")
        else:
            found.append(_compare(name, sent.encode("latin-1"), entry["values"][0]))
    found.append(_compare("target", request.target.encode("latin-1"), report.get("target")))
    found.append(_compare("body", request.body, report.get("body")))
    return [item for item in found if item]


def classify(request: Request, chain: tuple[str, ...], observation: Observation) -> Outcome:
    if observation.status is None:
        return Outcome("explicit_reject", entry_point(chain), "untagged", f"no_http_response:{observation.error}")

    component, attribution = attribute(chain, observation.hops or {})
    status = observation.status
    if component == ECHO and attribution == "tagged":
        report = observation.report or {}
        if status == 200 and report.get("service") == ECHO and "error" not in report:
            found = differences(request, report)
            if found:
                return Outcome("silent_degradation", ECHO, attribution, ";".join(found))
            return Outcome("ok", ECHO, attribution)
        if status == 401 and report.get("error") == "lab_key_required":
            # The key was sent: it was lost or altered on the way.
            return Outcome("silent_degradation", ECHO, attribution, "x-lab-key:not_received")
        return Outcome("explicit_reject", ECHO, attribution, f"status={status}")

    if status < 400:
        return Outcome("silent_degradation", component, attribution, f"answered_without_echo(status={status})")
    if status in _GATEWAY_STATUSES or (attribution == "untagged" and status >= 500):
        return Outcome("upstream_error", component, attribution, f"status={status}")
    return Outcome("explicit_reject", component, attribution, f"status={status}")
