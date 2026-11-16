from __future__ import annotations

import time

import hpack
import pytest
from harness.channels import build
from harness.client import send_http2_header_values_as_raw_literals
from harness.threshold import bisect
from harness.verdict import Observation, attribute, classify

CHAIN = ("alpha", "beta")


@pytest.mark.parametrize(
    ("hops", "expected"),
    [
        ({"alpha": "proxied", "beta": "proxied", "echo": "1"}, ("echo", "tagged")),
        ({"alpha": "proxied", "beta": "proxied"}, ("echo", "untagged")),
        ({"alpha": "proxied", "beta": "origin"}, ("beta", "tagged")),
        ({"alpha": "proxied"}, ("beta", "untagged")),
        ({"alpha": "origin"}, ("alpha", "tagged")),
        ({}, ("alpha", "untagged")),
        # A hop further down cannot be blamed while an earlier one claims the response.
        ({"alpha": "origin", "beta": "proxied", "echo": "1"}, ("alpha", "tagged")),
    ],
)
def test_attribution_walks_the_chain(hops, expected):
    assert attribute(CHAIN, hops) == expected


def test_attribution_without_intermediary():
    assert attribute((), {"echo": "1"}) == ("echo", "tagged")
    assert attribute((), {}) == ("echo", "untagged")


@pytest.mark.parametrize(
    ("status", "hops", "verdict", "component"),
    [
        (400, {"alpha": "origin"}, "explicit_reject", "alpha"),
        (431, {}, "explicit_reject", "alpha"),
        (431, {"alpha": "proxied", "beta": "origin"}, "explicit_reject", "beta"),
        (400, {"alpha": "proxied"}, "explicit_reject", "beta"),
        (500, {"alpha": "proxied"}, "upstream_error", "beta"),
        (502, {"alpha": "origin"}, "upstream_error", "alpha"),
        (504, {"alpha": "proxied", "beta": "proxied"}, "upstream_error", "echo"),
        (500, {"alpha": "origin"}, "explicit_reject", "alpha"),
        (200, {"alpha": "origin"}, "silent_degradation", "alpha"),
        (404, {"alpha": "proxied", "beta": "proxied", "echo": "1"}, "explicit_reject", "echo"),
    ],
)
def test_classification_of_error_responses(status, hops, verdict, component):
    request = build("authorization", "token", CHAIN, "key", "id-1")
    outcome = classify(request, CHAIN, Observation(status=status, hops=hops))
    assert (outcome.verdict, outcome.attributed_to) == (verdict, component)


def test_no_http_response_is_an_explicit_reject_by_the_entry_point():
    request = build("authorization", "token", CHAIN, "key", "id-1")
    outcome = classify(request, CHAIN, Observation(error="RemoteProtocolError"))
    assert (outcome.verdict, outcome.attributed_to, outcome.attribution) == ("explicit_reject", "alpha", "untagged")
    assert outcome.detail == "no_http_response:RemoteProtocolError"


def test_lost_lab_key_is_a_degradation():
    request = build("authorization", "token", CHAIN, "key", "id-1")
    hops = {"alpha": "proxied", "beta": "proxied", "echo": "1"}
    observation = Observation(status=401, hops=hops, report={"service": "echo", "error": "lab_key_required"})
    assert classify(request, CHAIN, observation).verdict == "silent_degradation"


def test_bisect_finds_the_exact_boundary():
    for limit in (1, 2, 7, 8190, 65535):
        calls = []

        def accepts(size, limit=limit):
            calls.append(size)
            return size <= limit

        assert bisect(accepts, 1, 1_000_000) == limit
        assert len(calls) <= 22
    assert bisect(lambda size: False, 1, 100) is None
    assert bisect(lambda size: True, 1, 100) == 100


def test_http2_header_values_are_sent_as_raw_literals():
    send_http2_header_values_as_raw_literals()
    send_http2_header_values_as_raw_literals()  # idempotent
    value = b"A" * 2_000_000
    started = time.perf_counter()
    block = hpack.Encoder().encode([(b"cookie", value)])
    assert time.perf_counter() - started < 5, "encoding must stay linear"
    assert value in block, "the value travels as a raw literal"
    assert hpack.Decoder(max_header_list_size=len(value) * 2).decode(block) == [("cookie", value.decode())]
