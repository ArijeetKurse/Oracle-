import pytest

from oracle import core, resources, settings


@pytest.fixture(autouse=True)
def isolated_sqlite_database(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DB_PATH", tmp_path / "oracle-test.db")
    core.collector.seen.clear()
    core.collector._baseline = True
    core.collector._last_prune = 0
    core.collector._last_resource_sample = 0
    core.collector._last_process_resource_sample = 0
    resources.reset_sampler_state_for_tests()
    settings.reset_cache_for_tests()
    yield
