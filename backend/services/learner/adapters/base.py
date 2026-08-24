import hashlib
from pathlib import Path
from urllib.parse import urlparse
from backend.services.learner.common import Behavior

def text(row,*keys):
    for key in keys:
        value=row.get(key)
        if value not in (None,"","None"): return str(value)
    return ""
def domain(value):
    value=str(value or "").strip().lower()
    if "@" in value: return value.rsplit("@",1)[-1]
    try: return urlparse(value if "://" in value else "//"+value).hostname or ""
    except ValueError: return ""
def extension(value):
    name=Path(str(value or "")).name
    return Path(name).suffix.lower().lstrip(".")
def identity(row):
    user_id=text(row,"userId","username","senderEmail"); email=text(row,"mailbox","email","senderEmail")
    user=text(row,"user","username","senderName"); host=text(row,"hostname","computer","deviceName"); dept=text(row,"dept","department")
    person_raw=user_id or email
    endpoint_raw=text(row,"endpointId")
    return {"person_key":f"person:{person_raw.lower()}" if person_raw else "", "endpoint_key":f"endpoint:{endpoint_raw}" if endpoint_raw else (f"device:{host.lower()}" if host else ""), "user_name":user,"user_id":user_id,"email":email,"hostname":host,"department":dept}
def behaviors(source,event_id,event_time,row,specs):
    ident=identity(row); output=[]
    for behavior_type,value in specs:
        value=str(value or "").strip()
        if not value or value=="None": continue
        key=value.lower()
        output.append(Behavior(source,event_id,event_time,behavior_type,key,**ident,observed={"behaviorType":behavior_type,"value":value,"row":row}))
    return output
