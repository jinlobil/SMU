from urllib.parse import parse_qs, urlparse

from backend.clients.sophos import SophosClient


def client_with_pages(monkeypatch, pages):
    client = SophosClient.__new__(SophosClient)
    client.base_url = "https://api.example.test"
    client.token = "token"
    client.tenant_id = "tenant"
    requests = []

    def request_json(request):
        requests.append(request.full_url)
        return pages.pop(0)

    monkeypatch.setattr(client, "request_json", request_json)
    return client, requests


def test_cursor_pagination_does_not_fall_through_to_numbered_pages(monkeypatch):
    client, requests = client_with_pages(monkeypatch, [
        {"items": [{"id": "one"}], "pages": {"nextKey": "cursor-2", "total": 5}},
        {"items": [{"id": "two"}], "pages": {"total": 5}},
    ])

    result = client.paged_items("/endpoint/v1/endpoints")

    assert [item["id"] for item in result] == ["one", "two"]
    assert len(requests) == 2
    assert parse_qs(urlparse(requests[1]).query)["pageFromKey"] == ["cursor-2"]
    assert "page" not in parse_qs(urlparse(requests[1]).query)


def test_numbered_pagination_is_used_when_api_does_not_return_cursor(monkeypatch):
    client, requests = client_with_pages(monkeypatch, [
        {"items": [{"id": "one"}], "pages": {"total": 2}},
        {"items": [{"id": "two"}], "pages": {"total": 2}},
    ])

    result = client.paged_items("/common/v1/directory/users")

    assert [item["id"] for item in result] == ["one", "two"]
    assert parse_qs(urlparse(requests[1]).query)["page"] == ["2"]
    assert "pageFromKey" not in parse_qs(urlparse(requests[1]).query)
