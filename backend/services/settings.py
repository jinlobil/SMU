import json, os, re, threading, time
from datetime import date, timedelta
from pathlib import Path
from typing import Any

DEFAULT_THEME={"Primary_Blue":"#0863e2","Primary_Blue_Dark":"#054fb8","UI_Background":"#ffffff","UI_Surface":"#ffffff","Card_Border":"#dfe8f3","Card_Title_Text":"#075fc9","Table_Header_Background":"#f7f9fc","Table_Header_Text":"#63748a","Table_Selection_Background":"#edf5ff","Table_Selection_Text":"#075fc9","Status_Success_Text":"#16a34a","Status_Fail_Text":"#dc2626","Threat_trend_Detection":"#0863e2","Threat_trend_Detection_XDR":"#18b6df","Threat_trend_Email":"#16a394","Threat_trend_Outbound_Mail":"#e83e8c","Threat_trend_File":"#ef9400"}
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
  return result
 def save(self,data):
  result=dict(DEFAULT_THEME)
  for key in result:
   value=str(data.get(key,result[key]))
   if not HEX.fullmatch(value):raise ValueError(f"Invalid color: {key}")
   result[key]=value
  self.path.parent.mkdir(parents=True,exist_ok=True);tmp=self.path.with_suffix(".tmp");tmp.write_text("# UI Color Settings\n"+"\n".join(f"{k}={v}" for k,v in result.items())+"\n",encoding="utf-8");os.replace(tmp,self.path);return result
class SchedulerService:
 def __init__(self,root:Path,refresh_service):
  self.path=root/"runtime/scheduler.json";self.refresh=refresh_service;self.lock=threading.Lock();self.state={"enabled":False,"interval":10,"targets":["detections","inbound"],"lastRun":None,"lastResult":"-"};self._load();threading.Thread(target=self._loop,daemon=True,name="smu-scheduler").start()
 def _load(self):
  try:self.state.update(json.loads(self.path.read_text(encoding="utf-8")))
  except Exception:pass
 def get(self):
  with self.lock:return dict(self.state)
 def save(self,data):
  interval=max(1,min(1440,int(data.get("interval",10))));targets=[x for x in data.get("targets",[]) if x in {"detections","inbound","dlp","outbound"}]
  with self.lock:self.state.update(enabled=bool(data.get("enabled")),interval=interval,targets=targets);self.path.parent.mkdir(parents=True,exist_ok=True);self.path.write_text(json.dumps(self.state,ensure_ascii=False,indent=2),encoding="utf-8");return dict(self.state)
 def _run(self):
  today=date.today();start=today-timedelta(days=1);messages=[]
  for target in self.get()["targets"]:
   try:
    if target=="detections":result=self.refresh.refresh_detections(start,today,lambda m:None)
    elif target=="inbound":result=self.refresh.refresh_inbound(start,today,lambda m:None)
    elif target=="dlp":result=self.refresh.refresh_dlp(today,lambda m:None)
    else:result=self.refresh.refresh_outbound(today,lambda m:None)
    messages.append(f"{target}:OK")
   except Exception as exc:messages.append(f"{target}:FAIL {type(exc).__name__}: {exc}")
  with self.lock:self.state["lastRun"]=time.strftime("%Y-%m-%d %H:%M:%S");self.state["lastResult"]=" / ".join(messages);self.path.write_text(json.dumps(self.state,ensure_ascii=False,indent=2),encoding="utf-8")
 def _loop(self):
  waited=0
  while True:
   time.sleep(30);waited+=30;state=self.get()
   if not state["enabled"]:waited=0;continue
   if waited>=state["interval"]*60:waited=0;self._run()
