from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from data.generate import generate
from data.store import reset_runtime


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("data")
    os.environ["MSG_DATA_DIR"] = str(out)
    generate(out, seed=7)
    return out


@pytest.fixture(scope="session")
def ground_truth(data_dir: Path) -> dict:
    return json.loads((data_dir / "ground_truth.json").read_text())


@pytest.fixture(autouse=True)
def clean_runtime(data_dir: Path) -> None:
    """Every test starts with no payments, messages, flags or categories."""
    reset_runtime()
