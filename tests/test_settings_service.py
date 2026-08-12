from pathlib import Path
import pytest
import os
from backend.services.settings import DEFAULT_THEME, SchedulerService, ThemePresetService, ThemeService

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

def test_theme_has_all_role_tokens_and_old_files_receive_defaults(tmp_path: Path):
    path=tmp_path/"env/Color_env.txt";path.parent.mkdir(parents=True)
    path.write_text("Primary_Blue=#123456\n",encoding="utf-8")
    theme=ThemeService(tmp_path).load()
    assert len(DEFAULT_THEME)==59
    assert theme["Primary_Blue"]=="#123456"
    assert theme["UI_Background_Deep"]==DEFAULT_THEME["UI_Background_Deep"]
    assert theme["Glow_Accent"]==DEFAULT_THEME["Glow_Accent"]

def test_theme_presets_are_complete_separate_and_replace_by_name(tmp_path: Path):
    service=ThemePresetService(tmp_path)
    first={**DEFAULT_THEME,"Primary_Blue":"#112233"}
    saved=service.save("My Purple Theme",first)
    assert saved[0]["theme"]["Primary_Blue"]=="#112233"
    assert len(saved[0]["theme"])==59
    assert not (tmp_path/"env/Color_env.txt").exists()
    saved=service.save("my purple theme",{**first,"Primary_Blue":"#334455"})
    assert len(saved)==1
    assert saved[0]["theme"]["Primary_Blue"]=="#334455"
    assert service.delete("my purple theme")==[]

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
    def __init__(self): self.calls=0;self.targets=[];self.chain_index=False;self.start=None;self.end=None
    def start_fetch_job(self,targets,start,end,chain_index=False):
        self.targets=list(targets);self.start=start;self.end=end;self.chain_index=chain_index;return {"id":"fetch-1"}
    def wait_for_fetch_job(self,job,progress,wait_for_index=False):
        self.calls+=1;progress("FETCHING · 완료");progress("스마트 증분 완료")
        return {**{target:{"status":"SUCCESS","data":{"ok":True}} for target in self.targets},"index":{"ok":True}}

def test_scheduler_runs_every_target_then_index(tmp_path: Path):
    refresh=ScheduledRefresh();index=ScheduledIndex();service=SchedulerService(tmp_path,refresh,index)
    targets=["detections","inbound","dlp","outbound","endpoints","organizations","users"]
    saved=service.save({"enabled":True,"interval":1,"targets":targets})
    assert saved["nextRun"] is not None
    service._run_cycle()
    state=service.get()
    assert refresh.calls==[]
    assert index.targets==targets
    assert index.chain_index is True
    assert index.start is None and index.end is None
    assert index.calls==1
    assert index.mode == "smart"
    assert "index:OK" in state["lastResult"]
    assert state["lastRun"] is not None
    assert state["phase"] == "idle"
    assert state["targetStatus"]["dlp"]["status"] == "SUCCESS"


def test_scheduler_retries_windows_permission_error(tmp_path: Path, monkeypatch):
    service = SchedulerService(tmp_path, Refresh())
    real_replace = os.replace
    attempts = {"count": 0}
    def flaky_replace(source, destination):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise PermissionError(5, "access denied")
        return real_replace(source, destination)
    monkeypatch.setattr(os, "replace", flaky_replace)

    service.save({"enabled": False, "interval": 10, "targets": ["inbound"]})

    assert attempts["count"] == 3
    assert service.path.exists()
