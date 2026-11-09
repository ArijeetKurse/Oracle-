import pytest

from oracle import core


@pytest.fixture(autouse=True)
def isolated_sqlite_database(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DB_PATH", tmp_path / "oracle-test.db")
    core.collector.seen.clear()
    core.collector._baseline = True
    core.collector._last_prune = 0
    yield
