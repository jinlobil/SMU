import json
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.clients.sophos import SophosClient
from backend.services.endpoints import load_json_list

QUERY_COLUMNS = {
    "Process": ["name", "path", "pid"], "Service": ["name", "display_name", "status", "start_type"],
    "Scheduled Task": ["name", "path", "enabled", "state"], "Installed Program": ["name", "version", "install_location"],
    "Network Connection": ["pid", "local_address", "local_port", "remote_address", "remote_port", "state"],
    "File Search": ["path", "filename", "size", "mtime"],
}
TABLES = {"Process": "processes", "Service": "services", "Scheduled Task": "scheduled_tasks", "Installed Program": "programs", "Network Connection": "process_open_sockets"}

class EasyQueryService:
    def __init__(self, root: Path): self.root=root; self.sessions_dir=root/"cache/live_discover"; self.env=root/"env/Sophos_env.txt"; self.queries=root/"Query/Queries.txt"
    def client(self): client=SophosClient(self.env); client.authenticate(); return client
    def request(self, client, path, method="GET", body=None):
        data=json.dumps(body).encode() if body is not None else None
        req=urllib.request.Request(f"{client.base_url}{path}", data=data, headers={**client.headers(), "Content-Type":"application/json"}, method=method)
        return client.request_json(req)
    def sql(self, query_type, keyword):
        if query_type not in QUERY_COLUMNS: raise ValueError("Unsupported query type")
        safe=str(keyword).replace("'", "''").lower(); columns=QUERY_COLUMNS[query_type]
        if query_type=="File Search":
            if not keyword.strip(): raise ValueError("File Search requires a path or filename")
            where=f"lower(filename) LIKE '%{safe}%'"
            return f"SELECT path, filename, size, datetime(mtime, 'unixepoch') as mtime FROM file WHERE {where} LIMIT 200"
        table=TABLES[query_type]; where=""
        if safe:
            fields={"Process":["name"],"Service":["name","display_name"],"Scheduled Task":["name","path"],"Installed Program":["name"],"Network Connection":["local_address","remote_address","local_port","remote_port"]}[query_type]
            where=" WHERE "+" OR ".join(f"lower(cast({field} as varchar)) LIKE '%{safe}%'" for field in fields)
        return f"SELECT {', '.join(columns)} FROM {table}{where} LIMIT 200"
    def wait(self, client, base, run_id, progress):
        for _ in range(20):
            status=self.request(client, f"{base}/{run_id}"); state=str(status.get("status") or status.get("state") or "").lower(); progress(f"Query status: {state or 'waiting'}")
            if state in {"finished","completed","done","success","succeeded"}: return
            if state in {"failed","error","cancelled","canceled","timeout"}: raise RuntimeError(f"Query failed: {status}")
            time.sleep(3)
        raise RuntimeError("Query polling timeout")
    def save(self, mode, query_type, endpoint, keyword, rows):
        session_id=datetime.now().strftime("%Y%m%d_%H%M%S_%f"); self.sessions_dir.mkdir(parents=True,exist_ok=True)
        data={"session_id":session_id,"created_at":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"query_mode":mode,"query_type":query_type,"endpoint_name":endpoint,"program_name":keyword,"display_columns":list(rows[0]) if rows else QUERY_COLUMNS.get(query_type,["name","path","pid"]),"result_count":len(rows),"rows":rows}
        (self.sessions_dir/f"{session_id}.json").write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding="utf-8"); return data
    def run_live(self, endpoint, query_type, keyword, progress):
        if not endpoint.strip(): raise ValueError("Endpoint Name is required")
        client=self.client(); base="/live-discover/v1/queries/runs"; body={"adHocQuery":{"name":f"Live Discover - {endpoint}","template":self.sql(query_type,keyword)},"matchEndpoints":{"all":False,"filters":[{"hostnameContains":endpoint}]}}
        created=self.request(client,base,"POST",body); run_id=str(created.get("id") or created.get("runId") or created.get("queryRunId") or "")
        if not run_id: raise RuntimeError("Query run id missing")
        self.wait(client,base,run_id,progress); result=self.request(client,f"{base}/{run_id}/results"); rows=[row for row in result.get("items",[]) if isinstance(row,dict)]
        return {"session":self.save("Live",query_type,endpoint,keyword,rows)}
    def history_queries(self):
        if not self.queries.exists(): return []
        try: items=json.loads(self.queries.read_text(encoding="utf-8")).get("items",[])
        except Exception: return []
        return [{"id":str(x.get("id","")),"name":str(x.get("name","")),"variables":x.get("variables",[])} for x in items if isinstance(x,dict) and x.get("id")]
    def endpoint_id(self, value):
        value=str(value or "").strip()
        if not value: return ""
        for endpoint in load_json_list(self.root/"cache/endpoints.json"):
            if value.lower() in {str(endpoint.get("id","")).lower(),str(endpoint.get("hostname","")).lower()}:
                return str(endpoint.get("id", ""))
        raise ValueError("Endpoint hostname/id was not found in cache/endpoints.json")
    def run_history(self, query_id, endpoint_id, start, end, variables, progress):
        query=next((x for x in self.history_queries() if x["id"]==query_id),None)
        if not query: raise ValueError("History query not found")
        client=self.client(); base="/xdr-query/v1/queries/runs"; body={"savedQuery":{"queryId":query_id}}
        if variables: body["savedQuery"]["variables"]=variables
        resolved_endpoint_id=self.endpoint_id(endpoint_id)
        if resolved_endpoint_id: body["matchEndpoints"]={"filters":[{"ids":[resolved_endpoint_id]}]}
        if start: body["from"]=start
        if end: body["to"]=end
        created=self.request(client,base,"POST",body); run_id=str(created.get("id") or created.get("runId") or "")
        if not run_id: raise RuntimeError("Query run id missing")
        self.wait(client,base,run_id,progress); result=self.request(client,f"{base}/{run_id}/results?maxSize=1000"); rows=[x for x in result.get("items",[]) if isinstance(x,dict)]
        return {"session":self.save("History",query["name"],endpoint_id,query["name"],rows)}
    def sessions(self):
        if not self.sessions_dir.exists(): return []
        output=[]
        for path in self.sessions_dir.glob("*.json"):
            try:
                data=json.loads(path.read_text(encoding="utf-8")); output.append(data)
            except Exception: pass
        return sorted(output,key=lambda x:x.get("created_at",""),reverse=True)
    def delete(self, session_id):
        path=self.sessions_dir/f"{session_id}.json"
        if path.exists(): path.unlink(); return True
        return False
