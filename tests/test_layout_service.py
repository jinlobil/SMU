import json
from pathlib import Path
import pytest
from backend.services.layout import LayoutService

def test_layout_load_save_and_candidates(tmp_path: Path):
    endpoint=tmp_path/"cache/endpoints.json";endpoint.parent.mkdir(parents=True);endpoint.write_text(json.dumps([{"hostname":"PC-1","ipv4Addresses":["10.0.0.1"],"associatedPerson":{"name":"홍길동","viaLogin":"D\\hong"}}]),encoding="utf-8")
    service=LayoutService(tmp_path); data=service.load(); data["floors"]["18F"]["seats"].append({"seat_id":"18F-001","x":1,"y":2})
    assert service.save(data)["floors"]["18F"]["seats"][0]["seat_id"]=="18F-001"
    assert service.candidates()[0]["hostname"]=="PC-1"

def test_layout_rejects_seat_without_id(tmp_path: Path):
    service=LayoutService(tmp_path);data=service.load();data["floors"]["18F"]["seats"]=[{}]
    with pytest.raises(ValueError): service.save(data)
