from datetime import datetime, timezone, timedelta

from app.storage.sqlite import ReputationDB


def test_record_seen_creates_ip(tmp_path):
    db = ReputationDB(str(tmp_path / "test.db"))

    db.record_seen("8.8.8.8")

    row = db.get("8.8.8.8")

    assert row is not None
    assert row["ip"] == "8.8.8.8"
    assert row["decision"] == "UNKNOWN"
    assert row["request_count"] == 1


def test_record_seen_increments_request_count(tmp_path):
    db = ReputationDB(str(tmp_path / "test.db"))

    db.record_seen("8.8.8.8")
    db.record_seen("8.8.8.8")
    db.record_seen("8.8.8.8")

    row = db.get("8.8.8.8")

    assert row["request_count"] == 3


def test_update_reputation(tmp_path):
    db = ReputationDB(str(tmp_path / "test.db"))

    db.record_seen("8.8.8.8")

    db.update_reputation(
        ip="8.8.8.8",
        score=95,
        decision="BLOCK",
    )

    row = db.get("8.8.8.8")

    assert row["score"] == 95
    assert row["decision"] == "BLOCK"
    assert row["checked_at"] is not None
    assert row["last_error"] is None


def test_cache_is_valid_within_24_hours(tmp_path):
    db = ReputationDB(str(tmp_path / "test.db"))

    db.record_seen("8.8.8.8")

    checked_at = datetime.now(timezone.utc).isoformat()

    db.update_reputation(
        ip="8.8.8.8",
        score=10,
        decision="ALLOW",
        checked_at=checked_at,
    )

    assert db.needs_reputation_check(
        "8.8.8.8",
        cache_hours=24,
    ) is False


def test_cache_expires_after_24_hours(tmp_path):
    db = ReputationDB(str(tmp_path / "test.db"))

    db.record_seen("8.8.8.8")

    old_checked_at = (
        datetime.now(timezone.utc)
        - timedelta(hours=25)
    ).isoformat()

    db.update_reputation(
        ip="8.8.8.8",
        score=10,
        decision="ALLOW",
        checked_at=old_checked_at,
    )

    assert db.needs_reputation_check(
        "8.8.8.8",
        cache_hours=24,
    ) is True


def test_new_ip_needs_reputation_check(tmp_path):
    db = ReputationDB(str(tmp_path / "test.db"))

    assert db.needs_reputation_check(
        "8.8.8.8",
        cache_hours=24,
    ) is True


def test_mark_blocked_sets_lifecycle_fields(tmp_path):
    db = ReputationDB(str(tmp_path / "test.db"))

    db.record_seen("8.8.8.8")

    now = datetime.now(timezone.utc)

    db.update_reputation(
        ip="8.8.8.8",
        score=95,
        decision="BLOCK",
    )

    db.mark_blocked(
        ip="8.8.8.8",
        blocked_at=now.isoformat(),
        expire_at=(now + timedelta(days=30)).isoformat(),
        next_recheck_at=(now + timedelta(days=7)).isoformat(),
    )

    row = db.get("8.8.8.8")

    assert row["decision"] == "BLOCK"
    assert row["blocked_at"] is not None
    assert row["expire_at"] is not None
    assert row["next_recheck_at"] is not None


def test_released_ip_clears_block_state(tmp_path):
    db = ReputationDB(str(tmp_path / "test.db"))

    db.record_seen("8.8.8.8")

    now = datetime.now(timezone.utc)

    db.update_reputation(
        ip="8.8.8.8",
        score=95,
        decision="BLOCK",
    )

    db.mark_blocked(
        ip="8.8.8.8",
        blocked_at=now.isoformat(),
        expire_at=(now + timedelta(days=30)).isoformat(),
        next_recheck_at=(now + timedelta(days=7)).isoformat(),
    )

    db.update_cloudflare_state(
        ip="8.8.8.8",
        status="ACTIVE",
        item_id="fake-item-id",
        operation_id="fake-operation-id",
    )

    db.mark_released("8.8.8.8")

    row = db.get("8.8.8.8")

    assert row["decision"] == "ALLOW"
    assert row["blocked_at"] is None
    assert row["expire_at"] is None
    assert row["next_recheck_at"] is None
    assert row["cloudflare_status"] is None
    assert row["cloudflare_item_id"] is None
    assert row["cloudflare_operation_id"] is None
