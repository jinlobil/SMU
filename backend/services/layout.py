import json
import os
from pathlib import Path
from typing import Any
from backend.services.endpoints import load_json_list

class LayoutService:
    def __init__(self, root: Path): self.root=root; self.path=root/"env/layout/Layout_User.json"
    def default(self): return {"floors":{"18F":{"image":"env/layout/18f.png","seats":[]},"19F":{"image":"env/layout/19f.png","seats":[]}}}
    def load(self):
        data=self.default()
        if self.path.exists():
            try:
                loaded=json.loads(self.path.read_text(encoding="utf-8"))
                for floor,value in loaded.get("floors",{}).items():
                    if floor in data["floors"] and isinstance(value,dict): data["floors"][floor].update(value)
            except Exception: pass
        return data
    def save(self,data):
        floors=data.get("floors") if isinstance(data,dict) else None
        if not isinstance(floors,dict): raise ValueError("floors is required")
        for floor in ("18F","19F"):
            value=floors.get(floor,{})
            if not isinstance(value.get("seats",[]),list): raise ValueError(f"{floor} seats must be a list")
            for seat in value.get("seats",[]):
                if not isinstance(seat,dict) or not str(seat.get("seat_id","")).strip(): raise ValueError("Every seat requires seat_id")
        self.path.parent.mkdir(parents=True,exist_ok=True); tmp=self.path.with_suffix(".tmp"); tmp.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding="utf-8"); os.replace(tmp,self.path); return self.load()
    def candidates(self):
        candidates={}
        for endpoint in load_json_list(self.root/"cache/endpoints.json"):
            person=endpoint.get("associatedPerson") if isinstance(endpoint.get("associatedPerson"),dict) else {}; login=str(person.get("viaLogin","")).split("\\")[-1]; name=str(person.get("name","") or ""); host=str(endpoint.get("hostname","") or ""); key=(login or host or name).lower()
            if key: candidates[key]={"name":name,"user_id":login,"hostname":host,"ip":", ".join(endpoint.get("ipv4Addresses",[]) or []),"email":"","dept":"","source":"Endpoint"}
        for user in load_json_list(self.root/"cache/users.json"):
            login=str(user.get("exchangeLogin","") or ""); email=str(user.get("email","") or ""); key=(login or email or str(user.get("name",""))).lower()
            current=candidates.setdefault(key,{"name":"","user_id":"","hostname":"","ip":"","email":"","dept":"","source":""})
            for field,value in (("name",user.get("name")),("user_id",login),("email",email)):
                if value and not current[field]: current[field]=str(value)
            current["source"]=" + ".join(filter(None,[current["source"],"Directory"]))
        return sorted(candidates.values(),key=lambda x:(x["name"],x["hostname"]))
    def image(self,floor):
        data=self.load(); relative=str(data["floors"].get(floor,{}).get("image",f"env/layout/{floor.lower()}.png")); path=Path(relative); return path if path.is_absolute() else self.root/path
