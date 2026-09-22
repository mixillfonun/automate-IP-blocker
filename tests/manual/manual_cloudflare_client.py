import requests
import pytest

from app.enforcement.cloudflare import (
    CloudflareAPIError,
    CloudflareClient,
)


ACCOUNT_ID = "test-account"
LIST_ID = "test-list"


def make_client():
    return CloudflareClient(
        api_token="test-token",
        account_id=ACCOUNT_ID,
        list_id=LIST_ID,
        timeout=1,
        max_retries=2,
    )


class FakeResponse:
    def __init__(
        self,
        status_code=200,
        payload=None,
        headers=None,
        text="",
    ):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}
        self.text = text

    @property
    def ok(self):
        return 200 <= self.status_code < 400

    def json(self):
        return self._payload


def test_get_list_items(monkeypatch):
    client = make_client()

    def fake_request(*args, **kwargs):
        return FakeResponse(
            payload={
                "success": True,
                "result": [
                    {
                        "id": "item-1",
                        "ip": "8.8.8.8",
                        "comment": "test comment",
                    },
                    {
                        "id": "item-2",
                        "ip": "1.1.1.1",
                        "comment": None,
                    },
                ],
            }
        )

    monkeypatch.setattr(
        client.session,
        "request",
        fake_request,
    )

    items = client.get_list_items()

    assert len(items) == 2

    assert items[0].item_id == "item-1"
    assert items[0].ip == "8.8.8.8"
    assert items[0].comment == "test comment"

    assert items[1].item_id == "item-2"
    assert items[1].ip == "1.1.1.1"
    assert items[1].comment is None


def test_find_ip_returns_matching_item(monkeypatch):
    client = make_client()

    def fake_get_list_items():
        return [
            type(
                "Item",
                (),
                {
                    "item_id": "item-1",
                    "ip": "8.8.8.8",
                    "comment": "test",
                },
            )(),
        ]

    monkeypatch.setattr(
        client,
        "get_list_items",
        fake_get_list_items,
    )

    item = client.find_ip("8.8.8.8")

    assert item is not None
    assert item.item_id == "item-1"


def test_find_ip_returns_none_when_missing(monkeypatch):
    client = make_client()

    monkeypatch.setattr(
        client,
        "get_list_items",
        lambda: [],
    )

    assert client.find_ip("8.8.8.8") is None


def test_add_ip(monkeypatch):
    client = make_client()

    captured = {}

    def fake_request(method, url, **kwargs):
        captured["method"] = method
        captured["url"] = url
        captured["kwargs"] = kwargs

        return FakeResponse(
            payload={
                "success": True,
                "result": {
                    "operation_id": "operation-add-123",
                },
            }
        )

    monkeypatch.setattr(
        client.session,
        "request",
        fake_request,
    )

    operation_id = client.add_ip(
        ip="8.8.8.8",
        comment="Automated test",
    )

    assert operation_id == "operation-add-123"
    assert captured["method"] == "POST"

    assert captured["url"] == (
        "https://api.cloudflare.com/client/v4"
        f"/accounts/{ACCOUNT_ID}"
        f"/rules/lists/{LIST_ID}/items"
    )

    assert captured["kwargs"]["json"] == [
        {
            "ip": "8.8.8.8",
            "comment": "Automated test",
        }
    ]


def test_delete_item(monkeypatch):
    client = make_client()

    captured = {}

    def fake_request(method, url, **kwargs):
        captured["method"] = method
        captured["url"] = url
        captured["kwargs"] = kwargs

        return FakeResponse(
            payload={
                "success": True,
                "result": {
                    "operation_id": "operation-delete-123",
                },
            }
        )

    monkeypatch.setattr(
        client.session,
        "request",
        fake_request,
    )

    operation_id = client.delete_item(
        "item-123",
    )

    assert operation_id == "operation-delete-123"
    assert captured["method"] == "DELETE"

    assert captured["kwargs"]["json"] == {
        "items": [
            {
                "id": "item-123",
            }
        ]
    }


def test_get_operation(monkeypatch):
    client = make_client()

    def fake_request(*args, **kwargs):
        return FakeResponse(
            payload={
                "success": True,
                "result": {
                    "status": "completed",
                },
            }
        )

    monkeypatch.setattr(
        client.session,
        "request",
        fake_request,
    )

    operation = client.get_operation(
        "operation-123",
    )

    assert operation.operation_id == "operation-123"
    assert operation.status == "completed"
    assert operation.success is True


def test_wait_for_operation(monkeypatch):
    client = make_client()

    responses = iter(
        [
            type(
                "Operation",
                (),
                {
                    "operation_id": "operation-123",
                    "status": "pending",
                    "success": True,
                },
            )(),
            type(
                "Operation",
                (),
                {
                    "operation_id": "operation-123",
                    "status": "completed",
                    "success": True,
                },
            )(),
        ]
    )

    monkeypatch.setattr(
        client,
        "get_operation",
        lambda operation_id: next(responses),
    )

    monkeypatch.setattr(
        "app.enforcement.cloudflare.time.sleep",
        lambda seconds: None,
    )

    operation = client.wait_for_operation(
        "operation-123",
        poll_interval=0,
        timeout_seconds=1,
    )

    assert operation.status == "completed"


def test_wait_for_operation_failed(monkeypatch):
    client = make_client()

    failed_operation = type(
        "Operation",
        (),
        {
            "operation_id": "operation-123",
            "status": "failed",
            "success": False,
        },
    )()

    monkeypatch.setattr(
        client,
        "get_operation",
        lambda operation_id: failed_operation,
    )

    with pytest.raises(CloudflareAPIError):
        client.wait_for_operation(
            "operation-123",
            poll_interval=0,
            timeout_seconds=1,
        )


def test_wait_for_operation_timeout(monkeypatch):
    client = make_client()

    pending_operation = type(
        "Operation",
        (),
        {
            "operation_id": "operation-123",
            "status": "pending",
            "success": True,
        },
    )()

    monkeypatch.setattr(
        client,
        "get_operation",
        lambda operation_id: pending_operation,
    )

    monkeypatch.setattr(
        "app.enforcement.cloudflare.time.monotonic",
        lambda: 100,
    )

    with pytest.raises(TimeoutError):
        client.wait_for_operation(
            "operation-123",
            poll_interval=0,
            timeout_seconds=0,
        )


def test_http_429_is_retried(monkeypatch):
    client = make_client()

    responses = iter(
        [
            FakeResponse(
                status_code=429,
                headers={"Retry-After": "0"},
            ),
            FakeResponse(
                status_code=200,
                payload={
                    "success": True,
                    "result": [],
                },
            ),
        ]
    )

    calls = []

    def fake_request(*args, **kwargs):
        calls.append(1)
        return next(responses)

    monkeypatch.setattr(
        client.session,
        "request",
        fake_request,
    )

    monkeypatch.setattr(
        "app.enforcement.cloudflare.time.sleep",
        lambda seconds: None,
    )

    items = client.get_list_items()

    assert items == []
    assert len(calls) == 2


def test_http_500_is_retried(monkeypatch):
    client = make_client()

    responses = iter(
        [
            FakeResponse(
                status_code=500,
                payload={
                    "success": False,
                },
            ),
            FakeResponse(
                status_code=200,
                payload={
                    "success": True,
                    "result": [],
                },
            ),
        ]
    )

    calls = []

    def fake_request(*args, **kwargs):
        calls.append(1)
        return next(responses)

    monkeypatch.setattr(
        client.session,
        "request",
        fake_request,
    )

    monkeypatch.setattr(
        "app.enforcement.cloudflare.time.sleep",
        lambda seconds: None,
    )

    items = client.get_list_items()

    assert items == []
    assert len(calls) == 2


def test_http_400_raises_without_retry(monkeypatch):
    client = make_client()

    calls = []

    def fake_request(*args, **kwargs):
        calls.append(1)

        return FakeResponse(
            status_code=400,
            payload={
                "success": False,
                "errors": [
                    {
                        "code": 1000,
                        "message": "Bad request",
                    }
                ],
            },
        )

    monkeypatch.setattr(
        client.session,
        "request",
        fake_request,
    )

    with pytest.raises(CloudflareAPIError):
        client.get_list_items()

    assert len(calls) == 1
