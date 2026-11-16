"""sizes.yaml is well formed and agrees with real classical keys."""

from __future__ import annotations

import pytest
from emitter.catalog import CatalogError, bench_dir, load_variants

FAMILIES = {"classical", "ml-dsa", "composite", "fn-dsa", "slh-dsa"}


def test_every_variant_is_sourced(variants):
    assert variants, "sizes.yaml lists no variant"
    for variant in variants.values():
        assert variant.family in FAMILIES
        assert variant.source and variant.jose_source, variant.name
        assert variant.signature_length in ("fixed", "maximum")
        # A draft source carries its version and date.
        if variant.status == "draft":
            assert "draft-" in variant.source and "Internet-Draft," in variant.source, variant.name


def test_every_family_of_the_plan_is_present(variants):
    assert {variant.family for variant in variants.values()} == FAMILIES


@pytest.mark.parametrize("alg", ["ES256", "RS256"])
def test_classical_sizes_match_generated_keys(alg, variants, keyring):
    key = keyring.signing_key(alg)
    assert len(key.sign(b"message")) == variants[alg].signature_bytes
    assert len(key.raw_public_key) == variants[alg].public_key_bytes


def test_missing_source_is_rejected(tmp_path):
    text = (bench_dir() / "sizes.yaml").read_text(encoding="utf-8")
    broken = tmp_path / "sizes.yaml"
    broken.write_text(text.replace("jose_source: RFC 7518, Section 3.4", 'jose_source: ""'), encoding="utf-8")
    with pytest.raises(CatalogError):
        load_variants(broken)
