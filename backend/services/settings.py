import json, logging, os, re, threading, time
from datetime import date, timedelta
from pathlib import Path
from typing import Any

DEFAULT_THEME={"Primary_Blue":"#ff4d8d","Primary_Blue_Dark":"#7c3aed","UI_Background":"#120b20","UI_Surface":"#211238","Card_Border":"#4c2864","Card_Title_Text":"#ffb347","Table_Header_Background":"#2c1746","Table_Header_Text":"#e4d4f2","Table_Selection_Background":"#3b1c55","Table_Selection_Text":"#ffffff","Status_Success_Text":"#41e6a1","Status_Fail_Text":"#ff5f79","Threat_trend_Detection":"#ff4d8d","Threat_trend_Detection_XDR":"#ff8a3d","Threat_trend_Email":"#30d5c8","Threat_trend_Outbound_Mail":"#c45cff","Threat_trend_File":"#ffd166"}
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
        except Exception:
            pass

    def _persist_locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.state, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, self.path)

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
        progress = lambda message: self.log.info("scheduler target=%s %s", target, message)
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

    def _run_cycle(self):
        if not self.run_lock.acquire(blocking=False):
            self.log.warning("Scheduler cycle skipped because another cycle is running")
            return
        try:
            with self.lock:
                self.state["running"] = True
                self.state["lastResult"] = "수집 작업 실행 중"
                self._persist_locked()
            today = date.today()
            start = today - timedelta(days=1)
            messages = []
            for target in self.get()["targets"]:
                try:
                    self._refresh_target(target, start, today)
                    messages.append(f"{target}:OK")
                    with self.lock:
                        self.state["targetStatus"][target] = {"time": self._display_time(time.time()), "status": "SUCCESS", "message": ""}
                        self._persist_locked()
                except Exception as exc:
                    self.log.exception("Scheduled refresh failed target=%s", target)
                    messages.append(f"{target}:FAIL {type(exc).__name__}: {exc}")
                    with self.lock:
                        self.state["targetStatus"][target] = {"time": self._display_time(time.time()), "status": "FAIL", "message": f"{type(exc).__name__}: {exc}"}
                        self._persist_locked()
            if self.index is not None:
                try:
                    self.index.rebuild_all(lambda message: self.log.info("scheduler indexing: %s", message))
                    messages.append("index:OK")
                except Exception as exc:
                    self.log.exception("Scheduled indexing failed")
                    messages.append(f"index:FAIL {type(exc).__name__}: {exc}")
            with self.lock:
                self.state["lastRun"] = self._display_time(time.time())
                self.state["lastResult"] = " / ".join(messages) or "선택된 수집 대상 없음"
                self.state["running"] = False
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
