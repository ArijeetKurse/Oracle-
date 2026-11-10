import pytest
from fastapi import HTTPException

from oracle import main, settings


def test_alert_and_monitor_settings_persist_in_sqlite():
    saved=main.patch_settings({"spoken_alerts":True,"spoken_alert_min_severity":"high","network_persistence_samples":3,"cpu_sensitivity":4.5})
    assert saved["spoken_alerts"] is True
    assert saved["spoken_alert_min_severity"]=="high"
    assert saved["network_persistence_samples"]==3
    assert settings.get_settings()["cpu_sensitivity"]==4.5


@pytest.mark.parametrize("payload",[
    {"spoken_alerts":"true"},{"spoken_alert_min_severity":"urgent"},
    {"network_persistence_samples":4},{"alert_cooldown_seconds":10},{"max_alerts":10},
])
def test_settings_reject_invalid_values(payload):
    with pytest.raises(HTTPException) as error: main.patch_settings(payload)
    assert error.value.status_code==400
