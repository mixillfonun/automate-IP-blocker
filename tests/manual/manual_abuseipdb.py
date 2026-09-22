import pytest
import requests

from app.reputation.abuseipdb import (
    ABUSEIPDB_URL,
    AbuseIPDBClient,
)


def make_client():
    return AbuseIPDBClient(
        api_key="test-api-key",
        max_age_days=90,
        timeout=5,
    )


class FakeResponse:
    def __init__(
        self,
        payload=None,
        status_code=200,
    ):
        self._payload = payload or {}
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(
                f"HTTP {self.status_code}"
            )


def test_check_parses_response(monkeypatch):
    client = make_client()

    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs

        return FakeResponse(
            payload={
                "data": {
                    "ipAddress": "8.8.8.8",
                    "abuseConfidenceScore": 95,
                    "isPublic": True,
                    "isWhitelisted": False,
                    "totalReports": 123,
                    "numDistinctUsers": 45,
                    "countryCode": "US",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Google LLC",
                    "domain": "google.com",
                    "lastReportedAt": "2026-09-20T12:00:00+00:00",
                }
            }
        )

    monkeypatch.setattr(
        "app.reputation.abuseipdb.requests.get",
        fake_get,
    )

    result = client.check("8.8.8.8")

    assert result.ip == "8.8.8.8"
    assert result.score == 95
    assert result.is_public is True
    assert result.is_whitelisted is False
    assert result.total_reports == 123
    assert result.num_distinct_users == 45
    assert result.country_code == "US"
    assert result.usage_type == "Data Center/Web Hosting/Transit"
    assert result.isp == "Google LLC"
    assert result.domain == "google.com"
    assert result.last_reported_at == (
        "2026-09-20T12:00:00+00:00"
    )


def test_check_sends_correct_request(monkeypatch):
    client = AbuseIPDBClient(
        api_key="secret-test-key",
        max_age_days=30,
        timeout=7,
    )

    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs

        return FakeResponse(
            payload={
                "data": {
                    "ipAddress": "1.1.1.1",
                    "abuseConfidenceScore": 0,
                    "isPublic": True,
                    "isWhitelisted": False,
                    "totalReports": 0,
                    "numDistinctUsers": 0,
                    "countryCode": None,
                    "usageType": None,
                    "isp": None,
                    "domain": None,
                    "lastReportedAt": None,
                }
            }
        )

    monkeypatch.setattr(
        "app.reputation.abuseipdb.requests.get",
        fake_get,
    )

    client.check("1.1.1.1")

    assert captured["url"] == ABUSEIPDB_URL

    assert captured["kwargs"]["params"] == {
        "ipAddress": "1.1.1.1",
        "maxAgeInDays": 30,
    }

    assert captured["kwargs"]["headers"] == {
        "Key": "secret-test-key",
        "Accept": "application/json",
    }

    assert captured["kwargs"]["timeout"] == 7


def test_optional_fields_can_be_none(monkeypatch):
    client = make_client()

    def fake_get(*args, **kwargs):
        return FakeResponse(
            payload={
                "data": {
                    "ipAddress": "8.8.4.4",
                    "abuseConfidenceScore": 0,
                    "isPublic": True,
                    "isWhitelisted": True,
                    "totalReports": 0,
                    "numDistinctUsers": 0,
                    "countryCode": None,
                    "usageType": None,
                    "isp": None,
                    "domain": None,
                    "lastReportedAt": None,
                }
            }
        )

    monkeypatch.setattr(
        "app.reputation.abuseipdb.requests.get",
        fake_get,
    )

    result = client.check("8.8.4.4")

    assert result.score == 0
    assert result.is_public is True
    assert result.is_whitelisted is True
    assert result.country_code is None
    assert result.usage_type is None
    assert result.isp is None
    assert result.domain is None
    assert result.last_reported_at is None


def test_http_error_is_propagated(monkeypatch):
    client = make_client()

    def fake_get(*args, **kwargs):
        return FakeResponse(
            status_code=429,
            payload={
                "errors": [
                    {
                        "detail": "Rate limit exceeded",
                    }
                ]
            },
        )

    monkeypatch.setattr(
        "app.reputation.abuseipdb.requests.get",
        fake_get,
    )

    with pytest.raises(requests.HTTPError):
        client.check("8.8.8.8")


def test_malformed_response_raises(monkeypatch):
    client = make_client()

    def fake_get(*args, **kwargs):
        return FakeResponse(
            payload={
                "data": {
                    "ipAddress": "8.8.8.8",
                    # abuseConfidenceScore intentionally missing
                }
            }
        )

    monkeypatch.setattr(
        "app.reputation.abuseipdb.requests.get",
        fake_get,
    )

    with pytest.raises(KeyError):
        client.check("8.8.8.8")


def test_network_error_is_propagated(monkeypatch):
    client = make_client()

    def fake_get(*args, **kwargs):
        raise requests.ConnectionError(
            "Connection failed"
        )

    monkeypatch.setattr(
        "app.reputation.abuseipdb.requests.get",
        fake_get,
    )

    with pytest.raises(requests.ConnectionError):
        client.check("8.8.8.8")
