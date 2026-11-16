from __future__ import annotations

from pathlib import Path

import pytest
from emitter.catalog import bench_dir, load_profiles, load_variants
from harness.channels import CHANNELS, build, entry_point, path
from harness.matrix import MatrixError, load_matrix

TOKEN = "aaa.bbb.ccc"


def test_each_channel_carries_the_token_where_announced():
    requests = {channel: build(channel, TOKEN, (), "key", "id-1", proof="proof") for channel in CHANNELS}
    assert requests["authorization"].watched == {"authorization": f"Bearer {TOKEN}"}
    assert requests["dpop"].watched == {"authorization": f"DPoP {TOKEN}", "dpop": "proof"}
    assert requests["cookie"].watched == {"cookie": f"session={TOKEN}"}
    assert requests["query"].target == f"/bench?id_token_hint={TOKEN}" and not requests["query"].watched
    assert requests["form_post"].method == "POST" and requests["form_post"].body == f"id_token={TOKEN}".encode()
    for channel, request in requests.items():
        # Identifier and lab key come before any token-bearing header.
        assert [name for name, _ in request.headers[:2]] == ["X-Request-Id", "X-Lab-Key"], channel
        assert request.channel_bytes >= len(TOKEN)
    assert requests["dpop"].channel_bytes == len(f"DPoP {TOKEN}") + len("proof")


def test_chain_routing():
    assert (entry_point(()), path(())) == ("echo", "/bench")
    assert (entry_point(("nginx",)), path(("nginx",))) == ("nginx", "/bench")
    assert (entry_point(("nginx", "apache")), path(("nginx", "apache"))) == ("nginx", "/via/apache/bench")
    with pytest.raises(ValueError):
        path(("a", "b", "c"))
    with pytest.raises(ValueError):
        build("fragment", TOKEN, (), "key", "id-1")


def test_reduced_matrix_is_consistent_with_the_catalog():
    matrix = load_matrix(bench_dir() / "matrix.yaml")
    variants, profiles = load_variants(), load_profiles()
    assert matrix.cells and matrix.config_profile == "default"
    assert {cell.variant for cell in matrix.cells} <= set(variants)
    assert {cell.profile for cell in matrix.cells} <= set(profiles)
    chains = {cell.chain for cell in matrix.cells}
    assert () in chains and {(name,) for name in matrix.intermediaries} <= chains
    assert any(len(chain) == 2 for chain in chains)
    axes = [{getattr(c, a) for c in matrix.cells} for a in ("variant", "profile", "header_variant", "channel", "chain", "http_version")]
    product = 1
    for axis in axes:
        product *= len(axis)
    assert len(matrix.cells) == product


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("  - [nginx, apache]", "  - [nginx, apache, envoy]"),
        ("  - [nginx, apache]", "  - [nginx, caddy]"),
        ("  - [nginx, apache]", "  - [nginx, nginx]"),
        ("  - query", "  - fragment"),
        ('  - "2"', '  - "3"'),
        ("name: reduced", "name: ''"),
    ],
)
def test_malformed_matrix_is_refused(tmp_path: Path, old, new):
    text = (bench_dir() / "matrix.yaml").read_text(encoding="utf-8")
    assert old in text
    broken = tmp_path / "matrix.yaml"
    broken.write_text(text.replace(old, new), encoding="utf-8")
    with pytest.raises(MatrixError):
        load_matrix(broken)
