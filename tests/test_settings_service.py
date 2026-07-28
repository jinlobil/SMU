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

class ScheduledRefresh:
    def __init__(self): self.calls=[]
    def _record(self,name): self.calls.append(name); return {"ok":True}
    def refresh_detections(self,*args): return self._record("detections")
    def refresh_inbound(self,*args): return self._record("inbound")
    def refresh_dlp_range(self,*args): return self._record("dlp")
    def refresh_outbound_range(self,*args): return self._record("outbound")
    def refresh_endpoints(self,*args): return self._record("endpoints")
    def refresh_organizations(self,*args): return self._record("organizations")
    def refresh_users(self,*args): return self._record("users")

class ScheduledIndex:
    def __init__(self): self.calls=0
    def rebuild_all(self,progress): self.calls+=1;progress("done");return {"ok":True}

def test_scheduler_runs_every_target_then_index(tmp_path: Path):
    refresh=ScheduledRefresh();index=ScheduledIndex();service=SchedulerService(tmp_path,refresh,index)
    targets=["detections","inbound","dlp","outbound","endpoints","organizations","users"]
    saved=service.save({"enabled":True,"interval":1,"targets":targets})
    assert saved["nextRun"] is not None
    service._run_cycle()
    state=service.get()
    assert refresh.calls==targets
    assert index.calls==1
    assert "index:OK" in state["lastResult"]
    assert state["lastRun"] is not None
    assert state["phase"] == "idle"
    assert state["targetStatus"]["dlp"]["status"] == "SUCCESS"
