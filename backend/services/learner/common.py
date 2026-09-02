from dataclasses import dataclass, asdict
from typing import Any

SOURCES=("detections","xdr","inbound","outbound","dlp","firewall")
WINDOWS=(1,7,30,90,180)
@dataclass
class Behavior:
    source:str; event_id:str; event_time:str; behavior_type:str; behavior_key:str
    person_key:str=""; endpoint_key:str=""; user_name:str=""; user_id:str=""; email:str=""; hostname:str=""; department:str=""; observed:dict[str,Any]|None=None
    def scopes(self):
        values=[("global","*")]
        if self.person_key: values.append(("user",self.person_key))
        if self.endpoint_key: values.append(("device",self.endpoint_key))
        if self.department: values.append(("department",self.department))
        return values
    def json(self): return asdict(self)
