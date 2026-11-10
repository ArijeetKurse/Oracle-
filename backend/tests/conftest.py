import pytest

from oracle import alerting, core, resources, settings


@pytest.fixture(autouse=True)
def isolated_sqlite_database(tmp_path, monkeypatch):
    # Never let developer .env credentials turn tests into live provider calls.
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("GNANI_API_KEY", raising=False)
    monkeypatch.setattr(core, "DB_PATH", tmp_path / "oracle-test.db")
    core.collector.seen.clear()
    core.collector._baseline = True
    core.collector._last_prune = 0
    core.collector._last_resource_sample = 0
    core.collector._last_process_resource_sample = 0
    resources.reset_sampler_state_for_tests()
    settings.reset_cache_for_tests()
    alerting.reset_workers_for_tests()
    yield
