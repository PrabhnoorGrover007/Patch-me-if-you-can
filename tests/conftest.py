"""Make the project root importable when pytest is run from anywhere."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _disable_local_granite(monkeypatch):
    """Keep API contract tests deterministic even when the local AI server runs."""
    monkeypatch.setenv("LOCAL_GRANITE_DISABLED", "1")
