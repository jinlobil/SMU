from pathlib import Path
from backend.services.easy_query import EasyQueryService

def test_easy_query_builds_supported_live_sql(tmp_path: Path):
    service=EasyQueryService(tmp_path)
    assert "FROM processes" in service.sql("Process","chrome.exe")
    assert "chrome.exe" in service.sql("Process","chrome.exe")
    assert "FROM process_open_sockets" in service.sql("Network Connection","443")

def test_easy_query_persists_and_deletes_sessions(tmp_path: Path):
    service=EasyQueryService(tmp_path)
    session=service.save("Live","Process","PC-1","chrome",[{"name":"chrome.exe","pid":"1"}])
    assert service.sessions()[0]["result_count"]==1
    assert service.delete(session["session_id"]) is True
    assert service.sessions()==[]
