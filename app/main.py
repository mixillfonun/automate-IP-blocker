import logging
import sys
from datetime import datetime, timezone, timedelta

from app.config import load_settings
from app.collector.nginx import NginxCollector
from app.decision.engine import decide
from app.enforcement.cloudflare import CloudflareClient
from app.lifecycle.processor import BlockLifecycleProcessor
from app.reputation.abuseipdb import AbuseIPDBClient
from app.storage.sqlite import ReputationDB


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(
    "ip-reputation-worker"
)


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    logger.info(
        "Starting IP Reputation Worker"
    )

    # ========================================================
    # LOAD CONFIGURATION
    # ========================================================

    try:

        settings = load_settings()

    except Exception as exc:

        logger.error(
            "Failed to load configuration: %s",
            exc,
        )

        return 1

    logger.info(
        "Configuration loaded | "
        "cache=%sh | "
        "monitor>=%s | "
        "block>=%s | "
        "block_ttl=%sd | "
        "recheck=%sd | "
        "dry_run=%s",
        settings.abuseipdb_cache_hours,
        settings.monitor_threshold,
        settings.block_threshold,
        settings.block_ttl_days,
        settings.recheck_interval_days,
        settings.dry_run,
    )

    # ========================================================
    # DATABASE
    # ========================================================

    try:

        db = ReputationDB(
            settings.sqlite_path
        )

    except Exception as exc:

        logger.error(
            "Failed to initialize SQLite: %s",
            exc,
        )

        return 1

    # ========================================================
    # COLLECTOR
    # ========================================================

    collector = NginxCollector(
        log_path=settings.nginx_access_log,
        db=db,
    )

    # ========================================================
    # ABUSEIPDB
    # ========================================================

    abuseipdb = AbuseIPDBClient(
        api_key=settings.abuseipdb_api_key,
        max_age_days=settings.abuseipdb_max_age_days,
    )

    # ========================================================
    # CLOUDFLARE
    # ========================================================

    cloudflare = CloudflareClient(
        api_token=settings.cloudflare_api_token,
        account_id=settings.cloudflare_account_id,
        list_id=settings.cloudflare_list_id,
    )

    # ========================================================
    # LIFECYCLE PROCESSOR
    # ========================================================

    lifecycle = BlockLifecycleProcessor(
        db=db,
        abuseipdb=abuseipdb,
        cloudflare=cloudflare,
        monitor_threshold=settings.monitor_threshold,
        block_threshold=settings.block_threshold,
        recheck_interval_days=settings.recheck_interval_days,
        block_ttl_days=settings.block_ttl_days,
        dry_run=settings.dry_run,
    )

    # ========================================================
    # EXISTING BLOCK LIFECYCLE
    # ========================================================

    try:

        lifecycle_result = lifecycle.run()

        logger.info(
            "Lifecycle summary | "
            "expired=%d | "
            "rechecked=%d",
            lifecycle_result["expired"],
            lifecycle_result["rechecked"],
        )

    except Exception as exc:

        logger.error(
            "Block lifecycle processing failed: %s",
            exc,
        )

        return 2

    # ========================================================
    # COLLECT NEW NGINX IPs
    # ========================================================

    try:

        ips = collector.collect()

    except Exception as exc:

        logger.error(
            "Failed to collect Nginx access log: %s",
            exc,
        )

        return 1

    logger.info(
        "New unique public IPv4 addresses detected: %d",
        len(ips),
    )

    if not ips:

        logger.info(
            "No new IP addresses to process"
        )

        logger.info(
            "Worker completed"
        )

        return 0

    # ========================================================
    # COUNTERS
    # ========================================================

    checked_count = 0
    skipped_count = 0
    failed_count = 0

    allow_count = 0
    monitor_count = 0
    block_count = 0

    # ========================================================
    # PROCESS NEW IPs
    # ========================================================

    for ip in ips:

        logger.info(
            "Processing IP: %s",
            ip,
        )

        # ====================================================
        # GET EXISTING DB STATE
        # ====================================================

        row = db.get(ip)

        # ====================================================
        # ACTIVE BLOCK
        # ====================================================
        #
        # An IP that is already actively blocked by Cloudflare
        # is managed by the lifecycle processor.
        #
        # Do not perform the normal 24h reputation pipeline.
        #
        # Lifecycle will recheck it every N days.

        if (
            row
            and row["decision"] == "BLOCK"
            and row["cloudflare_status"] == "ACTIVE"
            and row["blocked_at"] is not None
        ):

            logger.info(
                "Active Cloudflare block | "
                "IP=%s | "
                "score=%s | "
                "next_recheck_at=%s | "
                "skipping normal reputation check",
                ip,
                row["score"],
                row["next_recheck_at"],
            )

            skipped_count += 1

            continue

        # ====================================================
        # CACHE CHECK
        # ====================================================

        try:

            needs_check = db.needs_reputation_check(
                ip=ip,
                cache_hours=settings.abuseipdb_cache_hours,
            )

        except Exception as exc:

            logger.error(
                "Failed to check reputation cache | "
                "IP=%s | error=%s",
                ip,
                exc,
            )

            db.set_error(
                ip,
                str(exc),
            )

            failed_count += 1

            continue

        # ====================================================
        # CACHE HIT
        # ====================================================

        if not needs_check:

            row = db.get(ip)

            logger.info(
                "Cache hit | "
                "IP=%s | "
                "score=%s | "
                "decision=%s",
                ip,
                row["score"] if row else None,
                row["decision"] if row else None,
            )

            skipped_count += 1

            continue

        # ====================================================
        # ABUSEIPDB CHECK
        # ====================================================

        logger.info(
            "Checking AbuseIPDB | IP=%s",
            ip,
        )

        try:

            reputation = abuseipdb.check(
                ip
            )

        except Exception as exc:

            logger.error(
                "AbuseIPDB check failed | "
                "IP=%s | error=%s",
                ip,
                exc,
            )

            db.set_error(
                ip,
                str(exc),
            )

            failed_count += 1

            # IMPORTANT:
            #
            # External reputation failure must NEVER
            # automatically create a block.

            continue

        # ====================================================
        # DECISION
        # ====================================================

        decision = decide(
            score=reputation.score,
            monitor_threshold=settings.monitor_threshold,
            block_threshold=settings.block_threshold,
        )

        # ====================================================
        # SAVE REPUTATION
        # ====================================================

        try:

            db.update_reputation(
                ip=ip,
                score=reputation.score,
                decision=decision.value,
            )

        except Exception as exc:

            logger.error(
                "Failed to save reputation result | "
                "IP=%s | error=%s",
                ip,
                exc,
            )

            db.set_error(
                ip,
                str(exc),
            )

            failed_count += 1

            continue

        checked_count += 1

        # ====================================================
        # RESULT
        # ====================================================

        logger.info(
            "Reputation result | "
            "IP=%s | "
            "score=%s | "
            "decision=%s | "
            "reports=%s | "
            "country=%s | "
            "isp=%s",
            reputation.ip,
            reputation.score,
            decision.value,
            reputation.total_reports,
            reputation.country_code,
            reputation.isp,
        )

        # ====================================================
        # ALLOW
        # ====================================================

        if decision.value == "ALLOW":

            allow_count += 1

            logger.info(
                "ALLOW | "
                "IP=%s | score=%s",
                ip,
                reputation.score,
            )

            continue

        # ====================================================
        # MONITOR
        # ====================================================

        if decision.value == "MONITOR":

            monitor_count += 1

            logger.info(
                "MONITOR | "
                "IP=%s | score=%s",
                ip,
                reputation.score,
            )

            continue

        # ====================================================
        # BLOCK
        # ====================================================

        if decision.value == "BLOCK":

            block_count += 1

            # =================================================
            # DRY RUN
            # =================================================

            if settings.dry_run:

                logger.warning(
                    "DRY-RUN BLOCK | "
                    "IP=%s | "
                    "score=%s | "
                    "Cloudflare API will NOT be modified",
                    ip,
                    reputation.score,
                )

                continue

            # =================================================
            # REAL CLOUDFLARE ENFORCEMENT
            # =================================================

            logger.warning(
                "BLOCK enforcement starting | "
                "IP=%s | score=%s",
                ip,
                reputation.score,
            )

            try:

                # --------------------------------------------
                # Check existing Cloudflare item
                # --------------------------------------------

                existing = cloudflare.find_ip(
                    ip
                )

                if existing:

                    logger.info(
                        "IP already exists in Cloudflare list | "
                        "IP=%s | item_id=%s",
                        ip,
                        existing.item_id,
                    )

                    row = db.get(ip)

                    # ----------------------------------------
                    # Initialize lifecycle if needed
                    # ----------------------------------------

                    if (
                        row
                        and row["blocked_at"] is None
                    ):

                        now = datetime.now(
                            timezone.utc
                        )

                        blocked_at = (
                            now.isoformat()
                        )

                        expire_at = (
                            now
                            + timedelta(
                                days=settings.block_ttl_days
                            )
                        ).isoformat()

                        next_recheck_at = (
                            now
                            + timedelta(
                                days=settings.recheck_interval_days
                            )
                        ).isoformat()

                        db.mark_blocked(
                            ip=ip,
                            blocked_at=blocked_at,
                            expire_at=expire_at,
                            next_recheck_at=next_recheck_at,
                        )

                    db.update_cloudflare_state(
                        ip=ip,
                        status="ACTIVE",
                        item_id=existing.item_id,
                    )

                    continue

                # --------------------------------------------
                # Add IP to Cloudflare list
                # --------------------------------------------

                operation_id = cloudflare.add_ip(
                    ip=ip,
                    comment=(
                        "Automated AbuseIPDB block | "
                        f"score={reputation.score}"
                    ),
                )

                db.update_cloudflare_state(
                    ip=ip,
                    status="PENDING",
                    operation_id=operation_id,
                )

                # --------------------------------------------
                # Wait for asynchronous operation
                # --------------------------------------------

                operation = (
                    cloudflare.wait_for_operation(
                        operation_id
                    )
                )

                logger.info(
                    "Cloudflare add completed | "
                    "IP=%s | "
                    "operation_id=%s | "
                    "status=%s",
                    ip,
                    operation.operation_id,
                    operation.status,
                )

                # --------------------------------------------
                # Find resulting item
                # --------------------------------------------

                item = cloudflare.find_ip(
                    ip
                )

                if not item:

                    raise RuntimeError(
                        "Cloudflare operation completed "
                        "but IP was not found in list"
                    )

                # --------------------------------------------
                # Initialize block lifecycle
                # --------------------------------------------

                now = datetime.now(
                    timezone.utc
                )

                blocked_at = (
                    now.isoformat()
                )

                expire_at = (
                    now
                    + timedelta(
                        days=settings.block_ttl_days
                    )
                ).isoformat()

                next_recheck_at = (
                    now
                    + timedelta(
                        days=settings.recheck_interval_days
                    )
                ).isoformat()

                db.mark_blocked(
                    ip=ip,
                    blocked_at=blocked_at,
                    expire_at=expire_at,
                    next_recheck_at=next_recheck_at,
                )

                db.update_cloudflare_state(
                    ip=ip,
                    status="ACTIVE",
                    item_id=item.item_id,
                    operation_id=operation.operation_id,
                )

                logger.warning(
                    "BLOCK ACTIVE | "
                    "IP=%s | "
                    "item_id=%s | "
                    "expire_at=%s | "
                    "next_recheck_at=%s",
                    ip,
                    item.item_id,
                    expire_at,
                    next_recheck_at,
                )

            except Exception as exc:

                logger.error(
                    "Cloudflare enforcement failed | "
                    "IP=%s | error=%s",
                    ip,
                    exc,
                )

                db.update_cloudflare_state(
                    ip=ip,
                    status="FAILED",
                )

                db.set_error(
                    ip,
                    str(exc),
                )

                failed_count += 1

    # ========================================================
    # SUMMARY
    # ========================================================

    logger.info(
        "Worker summary | "
        "new_ips=%d | "
        "checked=%d | "
        "skipped=%d | "
        "failed=%d | "
        "allow=%d | "
        "monitor=%d | "
        "block=%d",
        len(ips),
        checked_count,
        skipped_count,
        failed_count,
        allow_count,
        monitor_count,
        block_count,
    )

    logger.info(
        "Worker completed"
    )

    # ========================================================
    # EXIT
    # ========================================================

    if failed_count > 0:
        return 2

    return 0


# ============================================================
# ENTRYPOINT
# ============================================================

if __name__ == "__main__":
    sys.exit(main())
