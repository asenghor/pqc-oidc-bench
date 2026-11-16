"""Execution of cells and probes, and the result files of a run."""

from __future__ import annotations

import csv
import datetime
import importlib.metadata
import json
import os
import platform
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .channels import Request, build
from .client import Emitter, Transport
from .matrix import Cell, Matrix
from .verdict import Observation, Outcome, classify

DPOP_PROFILE = "dpop_proof"
DPOP_HEADER_VARIANT = "jwk"
COLUMNS = (
    "run_id", "request_id", "variant", "profile", "header_variant", "channel", "chain", "config_profile",
    "http_version_requested", "http_version", "token_length", "channel_bytes", "target_length", "body_length",
    "status", "attributed_to", "attribution", "hops", "verdict", "detail", "latency_ms",
)  # fmt: skip


@dataclass
class Context:
    transport: Transport
    emitter: Emitter | None
    lab_key: str
    run_id: str = field(default_factory=lambda: secrets.token_hex(4))
    _sequence: int = 0

    def next_request_id(self) -> str:
        self._sequence += 1
        return f"{self.run_id}-{self._sequence:05d}"


def exchange(
    context: Context, channel: str, token: str, chain: tuple[str, ...], http_version: str, proof: str = ""
) -> tuple[Request, Observation, Outcome]:
    """Send `token` on `channel` through `chain` and classify what came back."""
    request = build(channel, token, chain, context.lab_key, context.next_request_id(), proof)
    observation = context.transport.send(request, chain, http_version)
    return request, observation, classify(request, chain, observation)


def probe(
    context: Context, channel: str, size: int, chain: tuple[str, ...], http_version: str = "1.1"
) -> tuple[Request, Observation, Outcome]:
    """Same as `exchange` with a filler of `size` characters instead of a token."""
    return exchange(context, channel, "x" * size, chain, http_version)


def row(
    context: Context, cell: Cell, token_length: int, request: Request, observation: Observation, outcome: Outcome
) -> dict[str, Any]:
    return {
        "run_id": context.run_id,
        "request_id": dict(request.headers)["X-Request-Id"],
        "variant": cell.variant,
        "profile": cell.profile,
        "header_variant": cell.header_variant,
        "channel": cell.channel,
        "chain": cell.chain_label,
        "config_profile": cell.config_profile,
        "http_version_requested": cell.http_version,
        "http_version": observation.http_version,
        "token_length": token_length,
        "channel_bytes": request.channel_bytes,
        "target_length": len(request.target),
        "body_length": len(request.body),
        "status": "" if observation.status is None else observation.status,
        "attributed_to": outcome.attributed_to,
        "attribution": outcome.attribution,
        "hops": " ".join(f"{name}={role}" for name, role in sorted((observation.hops or {}).items())),
        "verdict": outcome.verdict,
        "detail": outcome.detail,
        "latency_ms": f"{observation.latency_ms:.1f}",
    }


def run_cell(context: Context, cell: Cell) -> dict[str, Any]:
    if context.emitter is None:
        raise RuntimeError("an emitter is required to run matrix cells")
    token = context.emitter.token(cell.variant, cell.profile, cell.header_variant)["token"]
    proof = ""
    if cell.channel == "dpop":
        proof = context.emitter.token(cell.variant, DPOP_PROFILE, DPOP_HEADER_VARIANT)["token"]
    request, observation, outcome = exchange(context, cell.channel, token, cell.chain, cell.http_version, proof)
    return row(context, cell, len(token), request, observation, outcome)


def versions(run_id: str) -> dict[str, Any]:
    """What produced a run: commit, client libraries and pinned images."""
    images: dict[str, str] = {}
    compose_file = os.environ.get("COMPOSE_FILE_PATH")
    if compose_file and Path(compose_file).is_file():
        services = yaml.safe_load(Path(compose_file).read_text(encoding="utf-8")).get("services", {})
        for name, service in services.items():
            build_section = service.get("build") or {}
            images[name] = service.get("image") or f"built from {build_section.get('dockerfile', 'Dockerfile')}"
    return {
        "run_id": run_id,
        "started": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "git_commit": os.environ.get("GIT_COMMIT", ""),
        "harness": {
            "python": platform.python_version(),
            **{name: importlib.metadata.version(name) for name in ("httpx2", "h2")},
        },
        "images": images,
    }


class RunWriter:
    """results/<date>-<id>/ with results.csv, versions.json and the matrix used."""

    def __init__(self, root: Path, run_id: str, matrix: Matrix) -> None:
        date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        self.directory = root / f"{date}-{run_id}"
        self.directory.mkdir(parents=True, exist_ok=False)
        (self.directory / "matrix.yaml").write_text(matrix.source, encoding="utf-8")
        (self.directory / "versions.json").write_text(json.dumps(versions(run_id), indent=2) + "\n", encoding="utf-8")
        self._file = (self.directory / "results.csv").open("w", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._file, fieldnames=COLUMNS)
        self._writer.writeheader()

    def write(self, result: dict[str, Any]) -> None:
        self._writer.writerow(result)

    def close(self) -> None:
        self._file.close()


def run_matrix(context: Context, matrix: Matrix, root: Path) -> tuple[Path, dict[str, int]]:
    """Run every cell; returns the run directory and the count of each verdict."""
    writer = RunWriter(root, context.run_id, matrix)
    counts: dict[str, int] = {}
    try:
        for cell in matrix.cells:
            result = run_cell(context, cell)
            writer.write(result)
            counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
    finally:
        writer.close()
    return writer.directory, counts
