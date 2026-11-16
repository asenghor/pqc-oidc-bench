"""Harness against an in-process stack: real echo, real emitter, simulated hops."""

from __future__ import annotations

import csv
import json

import pytest
from emitter.catalog import bench_dir
from harness import smoke
from harness.matrix import Cell, load_matrix
from harness.runner import COLUMNS, exchange, probe, run_cell, run_matrix
from harness.threshold import find_threshold
from harness.verdict import VERDICTS

from .conftest import FakeNetwork


def cell(chain, channel="authorization", variant="ML-DSA-65", version="1.1"):
    return Cell(variant, "access_token_rfc9068", "kid", channel, chain, version, "default")


@pytest.mark.parametrize("chain", [(), ("alpha",), ("alpha", "beta"), ("beta", "alpha")])
@pytest.mark.parametrize("channel", ["authorization", "dpop", "cookie", "query", "form_post"])
def test_calibrated_token_arrives_intact(network, chain, channel):
    result = run_cell(network.context(), cell(chain, channel))
    assert result["verdict"] == "ok", result
    assert result["attributed_to"] == "echo" and result["status"] == 200
    assert result["channel_bytes"] >= result["token_length"] > 3309  # more than a raw ML-DSA-65 signature
    assert set(result) == set(COLUMNS)


def test_injected_truncation_yields_silent_degradation():
    """A hop that silently cuts the Authorization header: no error, different bytes."""
    network = FakeNetwork().add("alpha").add("cutter", truncate=4096)
    context = network.context()

    for chain in (("cutter",), ("alpha", "cutter"), ("cutter", "alpha")):
        result = run_cell(context, cell(chain))
        assert result["status"] == 200, "the truncating hop reports no error"
        assert result["verdict"] == "silent_degradation"
        sent = result["channel_bytes"]
        assert result["detail"] == f"authorization:truncated(sent={sent},received=4096)"

    # The same token through a sound hop, and a short value through the cutter, are fine.
    assert run_cell(context, cell(("alpha",)))["verdict"] == "ok"
    assert probe(context, "authorization", 100, ("cutter",))[2].verdict == "ok"


def test_injected_header_drop_yields_silent_degradation():
    network = FakeNetwork().add("dropper", drop="cookie")
    result = run_cell(network.context(), cell(("dropper",), channel="cookie"))
    assert (result["verdict"], result["detail"]) == ("silent_degradation", "cookie:dropped")
    lost_key = FakeNetwork().add("dropper", drop="x-lab-key")
    result = run_cell(lost_key.context(), cell(("dropper",)))
    assert (result["verdict"], result["detail"]) == ("silent_degradation", "x-lab-key:not_received")


@pytest.mark.parametrize("tagged", [True, False])
def test_rejection_is_attributed_to_the_right_hop(tagged):
    network = FakeNetwork().add("wide").add("narrow", limit=8000, tagged=tagged)
    context = network.context()
    expected = "tagged" if tagged else "untagged"
    for chain in (("narrow",), ("wide", "narrow"), ("narrow", "wide")):
        outcome = probe(context, "authorization", 9000, chain)[2]
        assert (outcome.verdict, outcome.attributed_to, outcome.attribution) == ("explicit_reject", "narrow", expected)
        assert probe(context, "authorization", 7000, chain)[2].verdict == "ok"


def test_smoke_attribution_scenario_passes_and_detects_a_wrong_tag(tmp_path):
    names = ("wide", "narrow", "silent")
    network = FakeNetwork().add("wide").add("narrow", limit=8000).add("silent", limit=16000, tagged=False)
    matrix = load_matrix(bench_dir() / "matrix.yaml")
    matrix = type(matrix)(matrix.name, matrix.config_profile, names, matrix.cells, matrix.source)
    smoke.oversize_attribution(network.context(), matrix, lambda line: None)

    # A hop that claims the responses it merely relays breaks attribution: the scenario must fail.
    class Liar(type(network.apps["wide"])):
        async def __call__(self, scope, receive, send):
            async def lying_send(message):
                if message["type"] == "http.response.start" and message["status"] >= 400:
                    headers = [(n, b"origin" if n == b"x-hop-wide" else v) for n, v in message["headers"]]
                    message = {**message, "headers": headers}
                await send(message)

            await super().__call__(scope, receive, lying_send)

    network.apps["wide"] = Liar("wide", network)
    with pytest.raises(smoke.SmokeFailure):
        smoke.oversize_attribution(network.context(), matrix, lambda line: None)


def test_smoke_expected_culprit():
    alone = {"a": False, "b": True, "c": True}
    assert smoke.expected_culprit(("a", "b"), alone) == "b"
    assert smoke.expected_culprit(("b", "a"), alone) == "b"
    assert smoke.expected_culprit(("c", "b"), alone) == "c"
    assert smoke.expected_culprit(("a",), alone) is None


def test_threshold_is_found_to_the_byte():
    network = FakeNetwork().add("wide").add("narrow", limit=8000)
    context = network.context()
    # The limit applies to the whole header value, "Bearer " included.
    largest, refusal = find_threshold(context, "authorization", ("wide", "narrow"), upper=100_000)
    assert largest == 8000 - len("Bearer ")
    assert (refusal.verdict, refusal.attributed_to) == ("explicit_reject", "narrow")
    assert find_threshold(context, "authorization", ("wide",), upper=20_000) == (20_000, None)


def test_run_writes_results_versions_and_matrix(network, tmp_path, monkeypatch):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  nginx:\n    image: nginx:1@sha256:abc\n  echo:\n    build:\n      dockerfile: x/Dockerfile\n")
    monkeypatch.setenv("COMPOSE_FILE_PATH", str(compose))
    monkeypatch.setenv("GIT_COMMIT", "0123abc")
    matrix = load_matrix(bench_dir() / "matrix.yaml")
    chains = {(), ("alpha",), ("alpha", "beta")}
    cells = tuple(
        Cell(c.variant, c.profile, c.header_variant, c.channel, chain, c.http_version, c.config_profile)
        for c in matrix.cells
        if c.chain == () and c.http_version == "1.1"
        for chain in chains
    )
    matrix = type(matrix)(matrix.name, matrix.config_profile, ("alpha", "beta"), cells, matrix.source)

    directory, counts = run_matrix(network.context(), matrix, tmp_path / "results")
    assert counts == {"ok": len(cells)}
    assert directory.name.endswith("-testrun")
    assert (directory / "matrix.yaml").read_text() == matrix.source
    versions = json.loads((directory / "versions.json").read_text())
    assert versions["git_commit"] == "0123abc" and versions["images"]["nginx"] == "nginx:1@sha256:abc"
    assert versions["images"]["echo"] == "built from x/Dockerfile" and "httpx2" in versions["harness"]
    with (directory / "results.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == len(cells) and tuple(rows[0]) == COLUMNS
    assert {row["verdict"] for row in rows} <= set(VERDICTS)
    assert len({row["request_id"] for row in rows}) == len(rows)
    # No token and no key in the result file.
    text = (directory / "results.csv").read_text()
    assert "eyJ" not in text and "k" * 64 not in text


def test_exchange_reports_latency_and_version(network):
    request, observation, outcome = exchange(network.context(), "authorization", "token", ("alpha",), "1.1")
    assert observation.status == 200 and observation.http_version == "1.1" and observation.latency_ms > 0
    assert observation.hops == {"alpha": "proxied", "echo": "1"} and outcome.verdict == "ok"
