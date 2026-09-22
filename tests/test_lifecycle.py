from datetime import datetime, timezone, timedelta

from app.lifecycle.processor import BlockLifecycleProcessor
from app.storage.sqlite import ReputationDB


class FakeAbuseIPDB:
    def __init__(self, score):
        self.score = score
        self.calls = []

    def check(self, ip):
        self.calls.append(ip)

        return type(
            "ReputationResult",
            (),
            {
                "ip": ip,
                "score": self.score,
                "total_reports": 100,
            },
        )()


class FakeCloudflare:
    def __init__(self):
        self.deleted_items = []

    def delete_item(self, item_id):
        self.deleted_items.append(item_id)
        return "fake-delete-operation"

    def wait_for_operation(self, operation_id):
        return type(
            "Operation",
            (),
            {
                "operation_id": operation_id,
                "status": "completed",
            },
        )()


def create_blocked_ip(db, ip):
    db.record_seen(ip)

    db.update_reputation(
        ip=ip,
        score=100,
        decision="BLOCK",
    )

    now = datetime.now(timezone.utc)

    db.mark_blocked(
        ip=ip,
        blocked_at=now.isoformat(),
        expire_at=(now + timedelta(days=30)).isoformat(),
        next_recheck_at=(
            now - timedelta(minutes=1)
        ).isoformat(),
    )

    db.update_cloudflare_state(
        ip=ip,
        status="ACTIVE",
        item_id="fake-item-123",
    )


def test_recheck_high_score_keeps_block(tmp_path):
    db = ReputationDB(str(tmp_path / "test.db"))

    ip = "192.0.2.60"

    create_blocked_ip(db, ip)

    abuseipdb = FakeAbuseIPDB(score=95)
    cloudflare = FakeCloudflare()

    processor = BlockLifecycleProcessor(
        db=db,
        abuseipdb=abuseipdb,
        cloudflare=cloudflare,
        block_threshold=90,
        monitor_threshold=80,
        recheck_interval_days=7,
        block_ttl_days=30,
        dry_run=False,
    )

    processor.run()

    row = db.get(ip)

    assert row["decision"] == "BLOCK"
    assert row["cloudflare_status"] == "ACTIVE"
    assert row["next_recheck_at"] is not None

    assert abuseipdb.calls == [ip]
    assert cloudflare.deleted_items == []


def test_recheck_below_block_releases_ip(tmp_path):
    db = ReputationDB(str(tmp_path / "test.db"))

    ip = "192.0.2.61"

    create_blocked_ip(db, ip)

    abuseipdb = FakeAbuseIPDB(score=50)
    cloudflare = FakeCloudflare()

    processor = BlockLifecycleProcessor(
        db=db,
        abuseipdb=abuseipdb,
        cloudflare=cloudflare,
        block_threshold=90,
        monitor_threshold=80,
        recheck_interval_days=7,
        block_ttl_days=30,
        dry_run=False,
    )

    processor.run()

    row = db.get(ip)

    assert row["decision"] == "ALLOW"
    assert row["cloudflare_status"] is None
    assert row["cloudflare_item_id"] is None
    assert row["next_recheck_at"] is None

    assert abuseipdb.calls == [ip]
    assert cloudflare.deleted_items == ["fake-item-123"]


def test_recheck_monitor_score_releases_ip(tmp_path):
    db = ReputationDB(str(tmp_path / "test.db"))

    ip = "192.0.2.62"

    create_blocked_ip(db, ip)

    abuseipdb = FakeAbuseIPDB(score=80)
    cloudflare = FakeCloudflare()

    processor = BlockLifecycleProcessor(
        db=db,
        abuseipdb=abuseipdb,
        cloudflare=cloudflare,
        block_threshold=90,
        monitor_threshold=80,
        recheck_interval_days=7,
        block_ttl_days=30,
        dry_run=False,
    )

    processor.run()

    row = db.get(ip)

    assert row["decision"] == "ALLOW"
    assert row["cloudflare_status"] is None
    assert cloudflare.deleted_items == ["fake-item-123"]


def test_expired_block_is_removed(tmp_path):
    db = ReputationDB(str(tmp_path / "test.db"))

    ip = "192.0.2.63"

    db.record_seen(ip)

    db.update_reputation(
        ip=ip,
        score=100,
        decision="BLOCK",
    )

    now = datetime.now(timezone.utc)

    db.mark_blocked(
        ip=ip,
        blocked_at=(
            now - timedelta(days=31)
        ).isoformat(),
        expire_at=(
            now - timedelta(minutes=1)
        ).isoformat(),
        next_recheck_at=(
            now + timedelta(days=1)
        ).isoformat(),
    )

    db.update_cloudflare_state(
        ip=ip,
        status="ACTIVE",
        item_id="expired-item-123",
    )

    abuseipdb = FakeAbuseIPDB(score=100)
    cloudflare = FakeCloudflare()

    processor = BlockLifecycleProcessor(
        db=db,
        abuseipdb=abuseipdb,
        cloudflare=cloudflare,
        block_threshold=90,
        monitor_threshold=80,
        recheck_interval_days=7,
        block_ttl_days=30,
        dry_run=False,
    )

    processor.run()

    row = db.get(ip)

    assert row["cloudflare_status"] is None
    assert row["cloudflare_item_id"] is None
    assert cloudflare.deleted_items == ["expired-item-123"]


def test_dry_run_does_not_delete_cloudflare_item(tmp_path):
    db = ReputationDB(str(tmp_path / "test.db"))

    ip = "192.0.2.64"

    create_blocked_ip(db, ip)

    abuseipdb = FakeAbuseIPDB(score=50)
    cloudflare = FakeCloudflare()

    processor = BlockLifecycleProcessor(
        db=db,
        abuseipdb=abuseipdb,
        cloudflare=cloudflare,
        block_threshold=90,
        monitor_threshold=80,
        recheck_interval_days=7,
        block_ttl_days=30,
        dry_run=True,
    )

    processor.run()

    assert cloudflare.deleted_items == []
