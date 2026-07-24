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

def test_theme_service_migrates_legacy_blue_ui_colors(tmp_path: Path):
    path=tmp_path/"env/Color_env.txt";path.parent.mkdir(parents=True)
    path.write_text("Primary_Blue=#0863e2\nCard_Title_Text=#007fc7\nTable_Header_Text=#0088e2\n",encoding="utf-8")
    theme=ThemeService(tmp_path).load()
    assert theme["Primary_Blue"]=="#ff4d8d"
    assert theme["Card_Title_Text"]=="#ffb347"
    assert theme["Table_Header_Text"]=="#e4d4f2"
