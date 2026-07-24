from pathlib import Path
import pytest
from backend.services.settings import ThemeService, SchedulerService

def test_theme_service_persists_valid_colors(tmp_path: Path):
    service=ThemeService(tmp_path); theme=service.load(); theme["Primary_Blue"]="#123456"
    assert service.save(theme)["Primary_Blue"]=="#123456"
    assert ThemeService(tmp_path).load()["Primary_Blue"]=="#123456"
    theme["Primary_Blue"]="red"
    with pytest.raises(ValueError): service.save(theme)

class Refresh:
    pass

def test_scheduler_settings_are_persistent(tmp_path: Path):
    service=SchedulerService(tmp_path,Refresh());saved=service.save({"enabled":True,"interval":15,"targets":["detections","invalid"]})
    assert saved["enabled"] is True
    assert saved["interval"]==15
    assert saved["targets"]==["detections"]
    loaded=SchedulerService(tmp_path,Refresh()).get()
    assert loaded["enabled"] is True
