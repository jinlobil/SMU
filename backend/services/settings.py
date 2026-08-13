import json, logging, os, re, threading, time, uuid
from datetime import date
from pathlib import Path
from typing import Any

DEFAULT_THEME = {
    "Primary_Blue": "#ff4d8d", "Primary_Blue_Dark": "#7c3aed",
    "Accent_Soft": "#ff75b1", "Accent_Bright": "#ff7aad", "Accent_Secondary_Soft": "#c45cff",
    "UI_Background": "#120b20", "UI_Background_Deep": "#10091d", "UI_Background_Mid": "#1b0e2d",
    "UI_Background_Glow": "#34205b", "UI_Surface": "#211238", "UI_Surface_Raised": "#28153f",
    "UI_Surface_Secondary": "#1b0e2d", "UI_Surface_Toolbar": "#241239",
    "UI_Input_Background": "#170c29", "UI_Modal_Background": "#211238", "UI_Raw_Background": "#0c1c31",
    "Card_Border": "#4c2864", "Border_Soft": "#56306c", "Border_Strong": "#653582",
    "Border_Action": "#94406f", "Border_Danger": "#ff4d6d", "Border_Table_Row": "#3d2252",
    "Card_Title_Text": "#ffb347", "Text_Primary": "#f4eefa", "Text_Bright": "#ffffff",
    "Text_Secondary": "#cdb9da", "Text_Muted": "#ad96bf", "Text_Subtle": "#927ca4",
    "Text_Table_Accent": "#ff5bb0", "Text_Entity": "#ffb347", "Text_Department": "#b68cff",
    "Table_Header_Background": "#2c1746", "Table_Header_Text": "#e4d4f2",
    "Table_Selection_Background": "#3b1c55", "Table_Selection_Text": "#ffffff",
    "Table_Row_Hover": "#321b48", "Control_Hover_Background": "#351b4d", "Focus_Color": "#ff4d8d",
    "Status_Success_Text": "#41e6a1", "Status_Success_Bright": "#59efad",
    "Status_Warning_Text": "#ffb347", "Status_Warning_Bright": "#ffcc74",
    "Status_Fail_Text": "#ff5f79", "Status_Fail_Bright": "#ff899c",
    "Sidebar_Background_Start": "#200f36", "Sidebar_Background_End": "#11091f",
    "Sidebar_Text": "#c6afd8", "Sidebar_Text_Muted": "#aa91bf", "Sidebar_Hover_Background": "#32194c",
    "Sidebar_Selected_Text": "#ffb7d0", "Sidebar_Selected_Background": "#34194e",
    "Modal_Overlay": "#051224", "Glow_Accent": "#ff4d8d", "Glow_Secondary": "#7c3aed",
    "Threat_trend_Detection": "#ff4d8d", "Threat_trend_Detection_XDR": "#ff8a3d",
    "Threat_trend_Email": "#30d5c8", "Threat_trend_Outbound_Mail": "#c45cff",
    "Threat_trend_File": "#ffd166",
}
HEX=re.compile(r"^#[0-9a-fA-F]{6}$")
class ThemeService:
 def __init__(self,root:Path):self.path=root/"env/Color_env.txt"
 def load(self):
  result=dict(DEFAULT_THEME)
  if self.path.exists():
   for line in self.path.read_text(encoding="utf-8").splitlines():
    if "=" in line and not line.lstrip().startswith("#"):
     k,v=line.split("=",1)
     if k.strip() in result and HEX.fullmatch(v.strip()):result[k.strip()]=v.strip()
  legacy_blue={"#0863e2","#054fb8","#075fc9","#007fc7","#0088e2","#0568e5"}
  for key in ("Primary_Blue","Primary_Blue_Dark","Card_Title_Text","Table_Header_Text","Table_Selection_Text"):
   if result[key].lower() in legacy_blue:result[key]=DEFAULT_THEME[key]
  return result
 def save(self,data):
  result=dict(DEFAULT_THEME)
  for key in result:
   value=str(data.get(key,result[key]))
   if not HEX.fullmatch(value):raise ValueError(f"Invalid color: {key}")
   result[key]=value
  self.path.parent.mkdir(parents=True,exist_ok=True);tmp=self.path.with_suffix(".tmp");tmp.write_text("# UI Color Settings\n"+"\n".join(f"{k}={v}" for k,v in result.items())+"\n",encoding="utf-8");os.replace(tmp,self.path);return result


class ThemePresetService:
    """Stores complete user theme snapshots separately from the applied theme."""

    def __init__(self, root: Path):
        self.path = root / "env/theme_presets.json"
        self.lock = threading.Lock()

    def load(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        presets = []
        for item in data if isinstance(data, list) else []:
            if isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("theme"), dict):
                presets.append({"name": item["name"], "theme": self._normalize(item["theme"])})
        return presets

    @staticmethod
    def _normalize(data: dict[str, Any]) -> dict[str, str]:
        result = dict(DEFAULT_THEME)
        for key in result:
            value = str(data.get(key, result[key]))
            if not HEX.fullmatch(value):
                raise ValueError(f"Invalid color: {key}")
            result[key] = value
        return result

    def save(self, name: str, theme: dict[str, Any]) -> list[dict[str, Any]]:
        name = str(name).strip()
        if not name or len(name) > 60 or any(char in name for char in "\\/\r\n\t"):
            raise ValueError("Invalid preset name")
        normalized = self._normalize(theme)
        with self.lock:
            presets = [item for item in self.load() if item["name"].casefold() != name.casefold()]
            presets.append({"name": name, "theme": normalized})
            presets.sort(key=lambda item: item["name"].casefold())
            self._write(presets)
        return presets

    def delete(self, name: str) -> list[dict[str, Any]]:
        with self.lock:
            presets = [item for item in self.load() if item["name"] != name]
            self._write(presets)
        return presets

    def _write(self, presets: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(presets, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, self.path)
class SchedulerService:
    TARGETS = {"detections", "inbound", "dlp", "outbound", "endpoints", "organizations", "users"}

    def __init__(self, root: Path, refresh_service, index_service=None):
        self.path = root / "runtime/scheduler.json"
        self.refresh = refresh_service
        self.index = index_service
        self.lock = threading.Lock()
        self.run_lock = threading.Lock()
        self.wake = threading.Event()
        self.log = logging.getLogger("smu.web.scheduler")
        self.state = {
            "enabled": False, "interval": 10, "targets": ["detections", "inbound"],
            "lastRun": None, "lastResult": "-", "nextRun": None, "running": False,
            "targetStatus": {},
            "phase": "idle", "currentTarget": None, "currentMessage": "대기 중",
        }
        self._next_run_at: float | None = None
        self._load()
        if self.state["enabled"]:
            self._schedule_next()
        threading.Thread(target=self._loop, daemon=True, name="smu-scheduler").start()

    def _load(self):
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            self.state.update(loaded)
            self.state["targets"] = [target for target in self.state["targets"] if target in self.TARGETS]
            if not isinstance(self.state.get("targetStatus"), dict):
                self.state["targetStatus"] = {}
            self.state["running"] = False
            self.state["phase"] = "idle"
            self.state["currentTarget"] = None
        except Exception:
            pass

    def _persist_locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f"{self.path.name}.{uuid.uuid4().hex}.tmp")
        temporary.write_text(json.dumps(self.state, ensure_ascii=False, indent=2), encoding="utf-8")
        for attempt in range(20):
            try:
                os.replace(temporary, self.path)
                return
            except PermissionError:
                if attempt < 19:
                    time.sleep(0.1)
        self.log.error("Scheduler state file remained locked after retries: %s", self.path)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass

    @staticmethod
    def _display_time(timestamp: float) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

    def _schedule_next(self):
        with self.lock:
            self._next_run_at = time.time() + int(self.state["interval"]) * 60
            self.state["nextRun"] = self._display_time(self._next_run_at)
            self._persist_locked()

    def get(self):
        with self.lock:
            return dict(self.state)

    def save(self, data):
        interval = max(1, min(1440, int(data.get("interval", 10))))
        targets = [target for target in data.get("targets", []) if target in self.TARGETS]
        enabled = bool(data.get("enabled"))
        with self.lock:
            self.state.update(enabled=enabled, interval=interval, targets=targets)
            if not enabled:
                self._next_run_at = None
                self.state["nextRun"] = None
            self._persist_locked()
        if enabled:
            self._schedule_next()
        self.wake.set()
        self.log.info("Scheduler saved enabled=%s interval=%s targets=%s", enabled, interval, targets)
        return self.get()

    def _refresh_target(self, target: str, start: date, today: date):
        progress = lambda message: self._update_progress("collecting", target, message)
        if target == "detections":
            return self.refresh.refresh_detections(start, today, progress)
        if target == "inbound":
            return self.refresh.refresh_inbound(start, today, progress)
        if target == "dlp":
            return self.refresh.refresh_dlp_range(start, today, progress)
        if target == "outbound":
            return self.refresh.refresh_outbound_range(start, today, progress)
        if target == "endpoints":
            return self.refresh.refresh_endpoints(progress)
        if target == "organizations":
            return self.refresh.refresh_organizations(progress)
        return self.refresh.refresh_users(progress)

    def _update_progress(self, phase: str, target: str, message: str):
        self.log.info("scheduler phase=%s target=%s %s", phase, target, message)
        with self.lock:
            self.state.update(phase=phase, currentTarget=target, currentMessage=str(message))
            self._persist_locked()

    def _run_cycle(self):
        if not self.run_lock.acquire(blocking=False):
            self.log.warning("Scheduler cycle skipped because another cycle is running")
            return
        try:
            with self.lock:
                self.state["running"] = True
                self.state["lastResult"] = "수집 작업 실행 중"
                self.state.update(phase="collecting", currentTarget=None, currentMessage="수집 작업 준비 중")
                self._persist_locked()
            messages = []; targets = self.get()["targets"]
            if targets and self.index is not None and hasattr(self.index, "start_fetch_job"):
                try:
                    fetch_job = self.index.start_fetch_job(targets, None, None, chain_index=True)
                    result = self.index.wait_for_fetch_job(fetch_job, lambda message: self._update_progress("collecting" if "FETCHING" in message or "수집" in message else "indexing", "fetcher", message), wait_for_index=True)
                    for target in targets:
                        target_result = result.get(target) or {"status": "FAIL", "error": "결과 없음"}
                        state = target_result.get("status", "FAIL"); detail = target_result.get("error", "")
                        messages.append(f"{target}:{'OK' if state == 'SUCCESS' else 'FAIL ' + detail}")
                        with self.lock:
                            self.state["targetStatus"][target] = {"time": self._display_time(time.time()), "status": state, "message": detail}
                            self._persist_locked()
                    messages.append("index:OK")
                except Exception as exc:
                    self.log.exception("Scheduled Fetcher/Indexer chain failed")
                    messages.append(f"fetch/index:FAIL {type(exc).__name__}: {exc}")
            elif not targets:
                messages.append("선택된 수집 대상 없음")
            with self.lock:
                self.state["lastRun"] = self._display_time(time.time())
                self.state["lastResult"] = " / ".join(messages) or "선택된 수집 대상 없음"
                self.state["running"] = False
                self.state.update(phase="idle", currentTarget=None, currentMessage="완료")
                self._persist_locked()
        finally:
            self.run_lock.release()
            if self.get()["enabled"]:
                self._schedule_next()

    def run_now(self):
        if self.run_lock.locked():
            return {**self.get(), "accepted": False}
        threading.Thread(target=self._run_cycle, daemon=True, name="smu-scheduler-manual").start()
        return {**self.get(), "accepted": True}

    def _loop(self):
        while True:
            state = self.get()
            if not state["enabled"] or self._next_run_at is None:
                self.wake.wait()
                self.wake.clear()
                continue
            timeout = max(0.0, self._next_run_at - time.time())
            if self.wake.wait(timeout):
                self.wake.clear()
                continue
            self._run_cycle()
