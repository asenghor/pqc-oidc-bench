"""Declarative test matrix."""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .channels import CHANNELS, MAX_CHAIN_LENGTH
from .client import HTTP_VERSIONS

_COMPONENT = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_AXES = ("variants", "profiles", "header_variants", "channels", "chains", "http_versions")


class MatrixError(ValueError):
    """The matrix file is malformed."""


@dataclass(frozen=True)
class Cell:
    variant: str
    profile: str
    header_variant: str
    channel: str
    chain: tuple[str, ...]
    http_version: str
    config_profile: str

    @property
    def chain_label(self) -> str:
        return ">".join(self.chain) if self.chain else "direct"


@dataclass(frozen=True)
class Matrix:
    name: str
    config_profile: str
    intermediaries: tuple[str, ...]
    cells: tuple[Cell, ...]
    source: str  # raw text, copied next to the results


def load_matrix(path: Path) -> Matrix:
    source = path.read_text(encoding="utf-8")
    document = yaml.safe_load(source)
    missing = [key for key in ("name", "config_profile", "intermediaries", *_AXES) if not document.get(key)]
    if missing:
        raise MatrixError(f"{path.name}: missing or empty: {', '.join(missing)}")
    intermediaries = tuple(document["intermediaries"])
    for component in intermediaries:
        if not _COMPONENT.fullmatch(str(component)):
            raise MatrixError(f"{path.name}: invalid intermediary name: {component}")
    chains = [tuple(chain) for chain in document["chains"]]
    for chain in chains:
        if len(chain) > MAX_CHAIN_LENGTH or len(set(chain)) != len(chain):
            raise MatrixError(f"{path.name}: a chain holds at most {MAX_CHAIN_LENGTH} distinct intermediaries: {chain}")
        unknown = [component for component in chain if component not in intermediaries]
        if unknown:
            raise MatrixError(f"{path.name}: chain uses an undeclared intermediary: {unknown[0]}")
    for channel in document["channels"]:
        if channel not in CHANNELS:
            raise MatrixError(f"{path.name}: unknown channel: {channel}")
    http_versions = [str(version) for version in document["http_versions"]]
    for version in http_versions:
        if version not in HTTP_VERSIONS:
            raise MatrixError(f"{path.name}: unknown HTTP version: {version}")
    cells = tuple(
        Cell(variant, profile, header_variant, channel, chain, version, document["config_profile"])
        for variant, profile, header_variant, channel, chain, version in itertools.product(
            document["variants"],
            document["profiles"],
            document["header_variants"],
            document["channels"],
            chains,
            http_versions,
        )
    )
    return Matrix(document["name"], document["config_profile"], intermediaries, cells, source)
