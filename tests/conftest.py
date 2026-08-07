from pathlib import Path

import pytest

from tools import build_blocklist


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_urlopen(url: str, timeout: int) -> None:
        raise AssertionError(f"unexpected network access: {url}, timeout={timeout}")

    monkeypatch.setattr(build_blocklist.urllib.request, "urlopen", fail_urlopen)
