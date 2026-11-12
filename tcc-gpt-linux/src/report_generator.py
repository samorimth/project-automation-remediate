"""Persistência mínima de resultados reais (CSV/JSON). Sem dados fictícios."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from .config import RESULTS_DIR
from .metrics import ExperimentMetrics

CSV_FIELDS = [
    "cve_id",
    "repetition",
    "model",
    "generation_latency_ms",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "validation_passed",
    "execution_authorized",
    "execution_status",
    "version_before",
    "version_after",
    "remediation_success",
    "notes",
]


def append_experiment(metrics: ExperimentMetrics) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    cve_dir = RESULTS_DIR / metrics.cve_id
    cve_dir.mkdir(parents=True, exist_ok=True)

    json_path = cve_dir / f"rep{metrics.repetition:02d}.json"
    json_path.write_text(
        json.dumps(metrics.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    csv_path = RESULTS_DIR / "experiments.csv"
    _append_csv(csv_path, [metrics])

    experiments_json = RESULTS_DIR / "experiments.json"
    existing: list[dict] = []
    if experiments_json.is_file():
        existing = json.loads(experiments_json.read_text(encoding="utf-8"))
        if not isinstance(existing, list):
            existing = []
    existing.append(metrics.to_dict())
    experiments_json.write_text(
        json.dumps(existing, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return json_path


def _append_csv(path: Path, rows: Iterable[ExperimentMetrics]) -> None:
    write_header = not path.is_file()
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()
        for row in rows:
            writer.writerow(row.to_csv_row())
