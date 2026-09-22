import sqlite3
from pathlib import Path
from datetime import datetime, timezone, timedelta


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_utc(value: str) -> datetime:
    """
    Parse ISO-8601 timestamp and ensure it is timezone-aware.
    """
    parsed = datetime.fromisoformat(value)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


class ReputationDB:
    def __init__(self, db_path: str):
        self.db_path = db_path

        Path(db_path).parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:

            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip TEXT PRIMARY KEY,

                    score INTEGER,

                    decision TEXT NOT NULL,

                    first_seen TEXT NOT NULL,

                    last_seen TEXT NOT NULL,

                    checked_at TEXT,

                    blocked_at TEXT,

                    expire_at TEXT,

                    next_recheck_at TEXT,

                    request_count INTEGER NOT NULL DEFAULT 0,

                    cloudflare_status TEXT,

                    cloudflare_item_id TEXT,

                    cloudflare_operation_id TEXT,

                    last_error TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS collector_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),

                    log_path TEXT NOT NULL,

                    file_inode INTEGER,

                    file_offset INTEGER NOT NULL DEFAULT 0,

                    updated_at TEXT NOT NULL
                )
            """)

            conn.commit()

    # ============================================================
    # IP REPUTATION
    # ============================================================

    def record_seen(self, ip: str):
        """
        Record that an IP was observed in the Nginx access log.
        """

        now = utc_now()

        with self._connect() as conn:

            conn.execute("""
                INSERT INTO ip_reputation (
                    ip,
                    decision,
                    first_seen,
                    last_seen,
                    request_count
                )
                VALUES (
                    ?,
                    'UNKNOWN',
                    ?,
                    ?,
                    1
                )

                ON CONFLICT(ip) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    request_count = request_count + 1
            """, (
                ip,
                now,
                now,
            ))

            conn.commit()

    def get(self, ip: str):
        """
        Get one IP reputation record.
        """

        with self._connect() as conn:

            row = conn.execute("""
                SELECT *
                FROM ip_reputation
                WHERE ip = ?
            """, (
                ip,
            )).fetchone()

            return dict(row) if row else None

    def get_all(self):
        """
        Get all tracked IPs.
        """

        with self._connect() as conn:

            rows = conn.execute("""
                SELECT *
                FROM ip_reputation
                ORDER BY last_seen DESC
            """).fetchall()

            return [
                dict(row)
                for row in rows
            ]

    # ============================================================
    # ABUSEIPDB CACHE
    # ============================================================

    def needs_reputation_check(
        self,
        ip: str,
        cache_hours: int,
    ) -> bool:
        """
        Determine whether an IP needs an AbuseIPDB check.
        """

        row = self.get(ip)

        if row is None:
            return True

        checked_at = row.get("checked_at")

        if not checked_at:
            return True

        try:
            checked_time = parse_utc(
                checked_at
            )
        except ValueError:
            return True

        age = (
            datetime.now(timezone.utc)
            - checked_time
        )

        return age >= timedelta(
            hours=cache_hours
        )

    def update_reputation(
        self,
        ip: str,
        score: int,
        decision: str,
        checked_at: str | None = None,
    ):
        """
        Save AbuseIPDB reputation result.
        """

        checked_at = (
            checked_at
            or utc_now()
        )

        with self._connect() as conn:

            conn.execute("""
                UPDATE ip_reputation
                SET
                    score = ?,
                    decision = ?,
                    checked_at = ?,
                    last_error = NULL
                WHERE ip = ?
            """, (
                score,
                decision,
                checked_at,
                ip,
            ))

            conn.commit()

    # ============================================================
    # BLOCK LIFECYCLE
    # ============================================================

    def mark_blocked(
        self,
        ip: str,
        blocked_at: str,
        expire_at: str,
        next_recheck_at: str,
    ):
        """
        Mark an IP as actively blocked.

        blocked_at:
            Timestamp when block became active.

        expire_at:
            Maximum lifetime of block.

        next_recheck_at:
            Next AbuseIPDB reputation recheck.
        """

        with self._connect() as conn:

            conn.execute("""
                UPDATE ip_reputation
                SET
                    decision = 'BLOCK',
                    blocked_at = ?,
                    expire_at = ?,
                    next_recheck_at = ?
                WHERE ip = ?
            """, (
                blocked_at,
                expire_at,
                next_recheck_at,
                ip,
            ))

            conn.commit()

    def get_due_rechecks(
        self,
        now: str | None = None,
    ):
        """
        Return blocked IPs whose next AbuseIPDB recheck
        is due.
        """

        now = now or utc_now()

        with self._connect() as conn:

            rows = conn.execute("""
                SELECT *
                FROM ip_reputation
                WHERE
                    decision = 'BLOCK'
                    AND next_recheck_at IS NOT NULL
                    AND next_recheck_at <= ?
                ORDER BY next_recheck_at ASC
            """, (
                now,
            )).fetchall()

            return [
                dict(row)
                for row in rows
            ]

    def get_expired_blocks(
        self,
        now: str | None = None,
    ):
        """
        Return blocked IPs whose maximum block lifetime
        has expired.
        """

        now = now or utc_now()

        with self._connect() as conn:

            rows = conn.execute("""
                SELECT *
                FROM ip_reputation
                WHERE
                    decision = 'BLOCK'
                    AND expire_at IS NOT NULL
                    AND expire_at <= ?
                ORDER BY expire_at ASC
            """, (
                now,
            )).fetchall()

            return [
                dict(row)
                for row in rows
            ]

    def mark_recheck(
        self,
        ip: str,
        next_recheck_at: str,
    ):
        """
        Schedule the next AbuseIPDB recheck.
        """

        with self._connect() as conn:

            conn.execute("""
                UPDATE ip_reputation
                SET
                    next_recheck_at = ?
                WHERE ip = ?
            """, (
                next_recheck_at,
                ip,
            ))

            conn.commit()

    def mark_released(
        self,
        ip: str,
    ):
        """
        Release an IP from the automated block lifecycle.
        """

        with self._connect() as conn:

            conn.execute("""
                UPDATE ip_reputation
                SET
                    decision = 'ALLOW',

                    blocked_at = NULL,

                    expire_at = NULL,

                    next_recheck_at = NULL,

                    cloudflare_status = NULL,

                    cloudflare_item_id = NULL,

                    cloudflare_operation_id = NULL,

                    last_error = NULL

                WHERE ip = ?
            """, (
                ip,
            ))

            conn.commit()

    # ============================================================
    # CLOUDFLARE STATE
    # ============================================================

    def update_cloudflare_state(
        self,
        ip: str,
        status: str | None = None,
        item_id: str | None = None,
        operation_id: str | None = None,
    ):
        """
        Save Cloudflare enforcement state.
        """

        with self._connect() as conn:

            conn.execute("""
                UPDATE ip_reputation
                SET
                    cloudflare_status =
                        COALESCE(
                            ?,
                            cloudflare_status
                        ),

                    cloudflare_item_id =
                        COALESCE(
                            ?,
                            cloudflare_item_id
                        ),

                    cloudflare_operation_id =
                        COALESCE(
                            ?,
                            cloudflare_operation_id
                        )

                WHERE ip = ?
            """, (
                status,
                item_id,
                operation_id,
                ip,
            ))

            conn.commit()

    # ============================================================
    # ERROR STATE
    # ============================================================

    def set_error(
        self,
        ip: str,
        error: str,
    ):
        """
        Store the latest processing error.
        """

        with self._connect() as conn:

            conn.execute("""
                UPDATE ip_reputation
                SET
                    last_error = ?
                WHERE ip = ?
            """, (
                error,
                ip,
            ))

            conn.commit()

    # ============================================================
    # NGINX COLLECTOR STATE
    # ============================================================

    def get_collector_state(
        self,
        log_path: str,
    ):
        """
        Get incremental Nginx collector state.
        """

        with self._connect() as conn:

            row = conn.execute("""
                SELECT
                    id,
                    log_path,
                    file_inode,
                    file_offset,
                    updated_at
                FROM collector_state
                WHERE
                    id = 1
                    AND log_path = ?
            """, (
                log_path,
            )).fetchone()

            return dict(row) if row else None

    def save_collector_state(
        self,
        log_path: str,
        file_inode: int,
        file_offset: int,
    ):
        """
        Save current Nginx log position.
        """

        now = utc_now()

        with self._connect() as conn:

            conn.execute("""
                INSERT INTO collector_state (
                    id,
                    log_path,
                    file_inode,
                    file_offset,
                    updated_at
                )
                VALUES (
                    1,
                    ?,
                    ?,
                    ?,
                    ?
                )

                ON CONFLICT(id) DO UPDATE SET
                    log_path = excluded.log_path,
                    file_inode = excluded.file_inode,
                    file_offset = excluded.file_offset,
                    updated_at = excluded.updated_at
            """, (
                log_path,
                file_inode,
                file_offset,
                now,
            ))

            conn.commit()

    def reset_collector_state(
        self,
        log_path: str,
    ):
        """
        Reset incremental collector state.
        """

        with self._connect() as conn:

            conn.execute("""
                DELETE FROM collector_state
                WHERE
                    id = 1
                    AND log_path = ?
            """, (
                log_path,
            ))

            conn.commit()
