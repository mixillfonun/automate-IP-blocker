import logging
from datetime import datetime, timezone, timedelta

from app.decision.engine import decide
from app.enforcement.cloudflare import CloudflareClient
from app.reputation.abuseipdb import AbuseIPDBClient
from app.storage.sqlite import ReputationDB


logger = logging.getLogger(
    "ip-reputation-worker.lifecycle"
)


class BlockLifecycleProcessor:
    """
    Manage the lifecycle of IPs that are actively blocked
    through Cloudflare.

    Lifecycle:

        ACTIVE
          |
          +--> expired
          |       |
          |       +--> DELETE -> RELEASE
          |
          +--> recheck due
                  |
                  +--> score < block threshold
                  |       |
                  |       +--> DELETE -> RELEASE
                  |
                  +--> score >= block threshold
                          |
                          +--> KEEP
                               |
                               +--> next recheck

    An IP is considered an active automated block only when:

        decision == BLOCK
        AND blocked_at IS NOT NULL
        AND cloudflare_status == ACTIVE
    """

    def __init__(
        self,
        db: ReputationDB,
        abuseipdb: AbuseIPDBClient,
        cloudflare: CloudflareClient,
        monitor_threshold: int = 80,
        block_threshold: int = 90,
        recheck_interval_days: int = 7,
        block_ttl_days: int = 30,
        dry_run: bool = True,
    ):
        self.db = db
        self.abuseipdb = abuseipdb
        self.cloudflare = cloudflare

        self.monitor_threshold = monitor_threshold
        self.block_threshold = block_threshold
        self.recheck_interval_days = recheck_interval_days
        self.block_ttl_days = block_ttl_days
        self.dry_run = dry_run

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    # ========================================================
    # EXPIRED BLOCKS
    # ========================================================

    def process_expired_blocks(self) -> int:

        now = self._now()

        expired = self.db.get_expired_blocks(
            now=now.isoformat()
        )

        if not expired:

            logger.info(
                "No expired active blocks"
            )

            return 0

        logger.info(
            "Expired active blocks found: %d",
            len(expired),
        )

        processed = 0

        for row in expired:

            ip = row["ip"]

            logger.warning(
                "Block TTL expired | "
                "IP=%s | "
                "blocked_at=%s | "
                "expire_at=%s",
                ip,
                row["blocked_at"],
                row["expire_at"],
            )

            # =================================================
            # Safety check
            # =================================================

            if (
                row["cloudflare_status"] != "ACTIVE"
                or not row["cloudflare_item_id"]
            ):

                logger.warning(
                    "Skipping expired IP because it does not "
                    "have an ACTIVE Cloudflare item | "
                    "IP=%s | status=%s",
                    ip,
                    row["cloudflare_status"],
                )

                continue

            # =================================================
            # DRY RUN
            # =================================================

            if self.dry_run:

                logger.warning(
                    "DRY-RUN RELEASE | "
                    "IP=%s | "
                    "Cloudflare DELETE will NOT be executed",
                    ip,
                )

                processed += 1

                continue

            # =================================================
            # REAL DELETE
            # =================================================

            try:

                operation_id = self.cloudflare.delete_item(
                    row["cloudflare_item_id"]
                )

                self.db.update_cloudflare_state(
                    ip=ip,
                    status="PENDING_DELETE",
                    operation_id=operation_id,
                )

                operation = (
                    self.cloudflare.wait_for_operation(
                        operation_id
                    )
                )

                logger.info(
                    "Cloudflare delete completed | "
                    "IP=%s | "
                    "operation_id=%s | "
                    "status=%s",
                    ip,
                    operation.operation_id,
                    operation.status,
                )

                self.db.mark_released(ip)

                logger.info(
                    "Block released after TTL expiry | "
                    "IP=%s",
                    ip,
                )

                processed += 1

            except Exception as exc:

                logger.error(
                    "Failed to release expired block | "
                    "IP=%s | error=%s",
                    ip,
                    exc,
                )

                self.db.set_error(
                    ip,
                    str(exc),
                )

        return processed

    # ========================================================
    # RECHECK BLOCKED IPs
    # ========================================================

    def process_due_rechecks(self) -> int:

        now = self._now()

        due = self.db.get_due_rechecks(
            now=now.isoformat()
        )

        if not due:

            logger.info(
                "No active blocks due for recheck"
            )

            return 0

        logger.info(
            "Active blocks due for recheck: %d",
            len(due),
        )

        processed = 0

        for row in due:

            ip = row["ip"]

            # =================================================
            # Safety check
            # =================================================

            if (
                row["decision"] != "BLOCK"
                or row["blocked_at"] is None
                or row["cloudflare_status"] != "ACTIVE"
            ):

                logger.warning(
                    "Skipping lifecycle recheck for IP=%s "
                    "because it is not an ACTIVE automated block",
                    ip,
                )

                continue

            logger.info(
                "Rechecking blocked IP | "
                "IP=%s | "
                "previous_score=%s",
                ip,
                row["score"],
            )

            # =================================================
            # AbuseIPDB
            # =================================================

            try:

                reputation = self.abuseipdb.check(ip)

            except Exception as exc:

                logger.error(
                    "AbuseIPDB recheck failed | "
                    "IP=%s | error=%s",
                    ip,
                    exc,
                )

                self.db.set_error(
                    ip,
                    str(exc),
                )

                continue

            # =================================================
            # Decision
            # =================================================

            decision = decide(
                score=reputation.score,
                monitor_threshold=self.monitor_threshold,
                block_threshold=self.block_threshold,
            )

            # =================================================
            # Save latest reputation
            # =================================================

            self.db.update_reputation(
                ip=ip,
                score=reputation.score,
                decision=decision.value,
            )

            logger.info(
                "Recheck result | "
                "IP=%s | "
                "score=%s | "
                "decision=%s | "
                "reports=%s",
                ip,
                reputation.score,
                decision.value,
                reputation.total_reports,
            )

            # =================================================
            # RELEASE
            # =================================================

            if reputation.score < self.block_threshold:

                logger.warning(
                    "IP no longer meets block threshold | "
                    "IP=%s | score=%s",
                    ip,
                    reputation.score,
                )

                # ---------------------------------------------
                # DRY RUN
                # ---------------------------------------------

                if self.dry_run:

                    logger.warning(
                        "DRY-RUN RELEASE | "
                        "IP=%s | "
                        "Cloudflare DELETE will NOT be executed",
                        ip,
                    )

                    processed += 1

                    continue

                # ---------------------------------------------
                # REAL DELETE
                # ---------------------------------------------

                try:

                    operation_id = self.cloudflare.delete_item(
                        row["cloudflare_item_id"]
                    )

                    self.db.update_cloudflare_state(
                        ip=ip,
                        status="PENDING_DELETE",
                        operation_id=operation_id,
                    )

                    operation = (
                        self.cloudflare.wait_for_operation(
                            operation_id
                        )
                    )

                    logger.info(
                        "Cloudflare delete completed | "
                        "IP=%s | "
                        "operation_id=%s | "
                        "status=%s",
                        ip,
                        operation.operation_id,
                        operation.status,
                    )

                    self.db.mark_released(ip)

                    logger.warning(
                        "IP RELEASED | "
                        "IP=%s | "
                        "new_score=%s",
                        ip,
                        reputation.score,
                    )

                    processed += 1

                except Exception as exc:

                    logger.error(
                        "Failed to release IP after "
                        "reputation recheck | "
                        "IP=%s | error=%s",
                        ip,
                        exc,
                    )

                    self.db.set_error(
                        ip,
                        str(exc),
                    )

                continue

            # =================================================
            # KEEP BLOCK
            # =================================================

            logger.warning(
                "IP remains above block threshold | "
                "IP=%s | score=%s",
                ip,
                reputation.score,
            )

            next_recheck = (
                now
                + timedelta(
                    days=self.recheck_interval_days
                )
            ).isoformat()

            self.db.mark_recheck(
                ip=ip,
                next_recheck_at=next_recheck,
            )

            logger.info(
                "Next recheck scheduled | "
                "IP=%s | "
                "next_recheck_at=%s",
                ip,
                next_recheck,
            )

            processed += 1

        return processed

    # ========================================================
    # RUN
    # ========================================================

    def run(self) -> dict:

        logger.info(
            "Starting block lifecycle processing"
        )

        expired_count = (
            self.process_expired_blocks()
        )

        recheck_count = (
            self.process_due_rechecks()
        )

        logger.info(
            "Block lifecycle completed | "
            "expired=%d | "
            "rechecked=%d",
            expired_count,
            recheck_count,
        )

        return {
            "expired": expired_count,
            "rechecked": recheck_count,
        }
