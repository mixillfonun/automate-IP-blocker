from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from app import main as main_module


@dataclass
class FakeReputation:
    ip: str
    score: int
    total_reports: int = 10
    country_code: str = "XX"
    isp: str = "Test ISP"


@dataclass
class FakeItem:
    item_id: str
    ip: str
    comment: str | None = None


@dataclass
class FakeOperation:
    operation_id: str
    status: str
    success: bool = True


class FakeDB:
    def __init__(self, *args, **kwargs):
        self.rows = {}
        self.errors = {}

    def get(self, ip):
        return self.rows.get(ip)

    def needs_reputation_check(self, ip, cache_hours):
        row = self.rows.get(ip)

        if row is None:
            return True

        checked_at = row.get("checked_at")

        if not checked_at:
            return True

        return False

    def update_reputation(self, ip, score, decision, checked_at=None):
        row = self.rows.setdefault(
            ip,
            {
                "ip": ip,
                "blocked_at": None,
                "expire_at": None,
                "next_recheck_at": None,
                "checked_at": None,
                "cloudflare_status": None,
                "cloudflare_item_id": None,
                "cloudflare_operation_id": None,
            },
        )

        row["score"] = score
        row["decision"] = decision
        row["checked_at"] = checked_at or "2026-09-21T00:00:00+00:00"

    def set_error(self, ip, error):
        self.errors[ip] = error

    def mark_blocked(
        self,
        ip,
        blocked_at,
        expire_at,
        next_recheck_at,
    ):
        row = self.rows[ip]
        row["blocked_at"] = blocked_at
        row["expire_at"] = expire_at
        row["next_recheck_at"] = next_recheck_at
        row["decision"] = "BLOCK"

    def update_cloudflare_state(
        self,
        ip,
        status=None,
        item_id=None,
        operation_id=None,
    ):
        row = self.rows[ip]

        if status is not None:
            row["cloudflare_status"] = status

        if item_id is not None:
            row["cloudflare_item_id"] = item_id

        if operation_id is not None:
            row["cloudflare_operation_id"] = operation_id


class FakeCollector:
    ips = []

    def __init__(self, *args, **kwargs):
        pass

    def collect(self):
        return list(self.ips)


class FakeAbuseIPDB:
    reputations = {}
    calls = []
    error_ips = set()

    def __init__(self, *args, **kwargs):
        pass

    def check(self, ip):
        self.calls.append(ip)

        if ip in self.error_ips:
            raise RuntimeError("AbuseIPDB unavailable")

        return self.reputations[ip]


class FakeCloudflare:
    existing = {}
    add_calls = []
    delete_calls = []
    wait_calls = []
    find_calls = []
    fail_add = False

    def __init__(self, *args, **kwargs):
        pass

    def find_ip(self, ip):
        self.find_calls.append(ip)
        return self.existing.get(ip)

    def add_ip(self, ip, comment=None):
        if self.fail_add:
            raise RuntimeError("Cloudflare unavailable")

        operation_id = f"op-{ip}"
        self.add_calls.append(
            {
                "ip": ip,
                "comment": comment,
                "operation_id": operation_id,
            }
        )
        return operation_id

    def wait_for_operation(self, operation_id):
        self.wait_calls.append(operation_id)

        return FakeOperation(
            operation_id=operation_id,
            status="completed",
        )


class FakeLifecycle:
    run_calls = 0

    def __init__(self, *args, **kwargs):
        pass

    def run(self):
        self.run_calls += 1
        return {
            "expired": 0,
            "rechecked": 0,
        }
        return {
            "expired": 0,
            "rechecked": 0,
        }

@pytest.fixture(autouse=True)
def reset_fakes():
    FakeCollector.ips = []

    FakeAbuseIPDB.reputations = {}
    FakeAbuseIPDB.calls = []
    FakeAbuseIPDB.error_ips = set()

    FakeCloudflare.existing = {}
    FakeCloudflare.add_calls = []
    FakeCloudflare.delete_calls = []
    FakeCloudflare.wait_calls = []
    FakeCloudflare.find_calls = []
    FakeCloudflare.fail_add = False

    FakeLifecycle.run_calls = 0


def patch_main(monkeypatch, tmp_path, *, dry_run=False):
    settings = SimpleNamespace(
        abuseipdb_api_key="test",
        abuseipdb_max_age_days=90,
        abuseipdb_cache_hours=24,
        cloudflare_api_token="test",
        cloudflare_account_id="account",
        cloudflare_list_id="list",
        nginx_access_log="/tmp/test-nginx.log",
        sqlite_path=str(tmp_path / "test.db"),
        block_threshold=90,
        monitor_threshold=80,
        block_ttl_days=30,
        recheck_interval_days=7,
        dry_run=dry_run,
    )

    monkeypatch.setattr(
        main_module,
        "load_settings",
        lambda: settings,
    )

    monkeypatch.setattr(
        main_module,
        "ReputationDB",
        FakeDB,
    )

    monkeypatch.setattr(
        main_module,
        "NginxCollector",
        FakeCollector,
    )

    monkeypatch.setattr(
        main_module,
        "AbuseIPDBClient",
        FakeAbuseIPDB,
    )

    monkeypatch.setattr(
        main_module,
        "CloudflareClient",
        FakeCloudflare,
    )

    monkeypatch.setattr(
        main_module,
        "BlockLifecycleProcessor",
        FakeLifecycle,
    )

    return settings


def test_allow_ip_does_not_touch_cloudflare(monkeypatch, tmp_path):
    patch_main(monkeypatch, tmp_path)

    ip = "1.1.1.1"

    FakeCollector.ips = [ip]
    FakeAbuseIPDB.reputations[ip] = FakeReputation(
        ip=ip,
        score=50,
    )

    result = main_module.main()

    assert result == 0
    assert FakeAbuseIPDB.calls == [ip]
    assert FakeCloudflare.add_calls == []
    assert FakeCloudflare.wait_calls == []


def test_monitor_ip_does_not_touch_cloudflare(monkeypatch, tmp_path):
    patch_main(monkeypatch, tmp_path)

    ip = "2.2.2.2"

    FakeCollector.ips = [ip]
    FakeAbuseIPDB.reputations[ip] = FakeReputation(
        ip=ip,
        score=85,
    )

    result = main_module.main()

    assert result == 0
    assert FakeAbuseIPDB.calls == [ip]
    assert FakeCloudflare.add_calls == []


def test_high_score_ip_is_blocked(monkeypatch, tmp_path):
    patch_main(monkeypatch, tmp_path)

    ip = "3.3.3.3"

    FakeCollector.ips = [ip]
    FakeAbuseIPDB.reputations[ip] = FakeReputation(
        ip=ip,
        score=95,
    )

    item = FakeItem(
        item_id="item-123",
        ip=ip,
        comment="Automated AbuseIPDB block | score=95",
    )

    find_calls = []

    def find_ip(self, ip_value):
        FakeCloudflare.find_calls.append(ip_value)
        find_calls.append(ip_value)

        if ip_value in FakeCloudflare.existing:
            return FakeCloudflare.existing[ip_value]

        # First lookup: IP does not exist yet.
        # Second lookup: Cloudflare operation has completed
        # and the item should now be visible.
        if ip_value == ip and len(find_calls) >= 2:
            return item

        return None

    monkeypatch.setattr(
        FakeCloudflare,
        "find_ip",
        find_ip,
    )

    result = main_module.main()

    assert result == 0

    assert FakeAbuseIPDB.calls == [ip]

    assert len(FakeCloudflare.add_calls) == 1
    assert FakeCloudflare.add_calls[0]["ip"] == ip

    assert FakeCloudflare.wait_calls == ["op-3.3.3.3"]

    db = main_module.ReputationDB
    assert db is FakeDB


def test_dry_run_does_not_modify_cloudflare(monkeypatch, tmp_path):
    patch_main(
        monkeypatch,
        tmp_path,
        dry_run=True,
    )

    ip = "4.4.4.4"

    FakeCollector.ips = [ip]
    FakeAbuseIPDB.reputations[ip] = FakeReputation(
        ip=ip,
        score=100,
    )

    result = main_module.main()

    assert result == 0
    assert FakeAbuseIPDB.calls == [ip]
    assert FakeCloudflare.add_calls == []
    assert FakeCloudflare.wait_calls == []


def test_abuseipdb_failure_does_not_block(monkeypatch, tmp_path):
    patch_main(monkeypatch, tmp_path)

    ip = "5.5.5.5"

    FakeCollector.ips = [ip]
    FakeAbuseIPDB.error_ips = {ip}

    result = main_module.main()

    assert result == 2
    assert FakeAbuseIPDB.calls == [ip]
    assert FakeCloudflare.add_calls == []


def test_active_block_skips_abuseipdb(monkeypatch, tmp_path):
    patch_main(monkeypatch, tmp_path)

    ip = "6.6.6.6"

    FakeCollector.ips = [ip]

    class ActiveBlockDB(FakeDB):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

            self.rows[ip] = {
                "ip": ip,
                "score": 100,
                "decision": "BLOCK",
                "blocked_at": "2026-09-21T00:00:00+00:00",
                "expire_at": "2026-10-21T00:00:00+00:00",
                "next_recheck_at": "2026-09-28T00:00:00+00:00",
                "cloudflare_status": "ACTIVE",
                "cloudflare_item_id": "item-active",
                "cloudflare_operation_id": None,
            }

    monkeypatch.setattr(
        main_module,
        "ReputationDB",
        ActiveBlockDB,
    )

    result = main_module.main()

    assert result == 0
    assert FakeAbuseIPDB.calls == []
    assert FakeCloudflare.add_calls == []


def test_cloudflare_failure_is_recorded(monkeypatch, tmp_path):
    patch_main(monkeypatch, tmp_path)

    ip = "7.7.7.7"

    FakeCollector.ips = [ip]
    FakeAbuseIPDB.reputations[ip] = FakeReputation(
        ip=ip,
        score=99,
    )

    FakeCloudflare.fail_add = True

    result = main_module.main()

    assert result == 2
    assert FakeAbuseIPDB.calls == [ip]
    assert FakeCloudflare.add_calls == []
