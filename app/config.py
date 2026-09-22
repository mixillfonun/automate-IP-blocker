import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


def get_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    abuseipdb_api_key: str
    abuseipdb_max_age_days: int
    abuseipdb_cache_hours: int

    cloudflare_api_token: str
    cloudflare_account_id: str
    cloudflare_list_id: str

    nginx_access_log: str
    sqlite_path: str

    block_threshold: int
    monitor_threshold: int

    block_ttl_days: int
    recheck_interval_days: int

    dry_run: bool


def load_settings() -> Settings:
    return Settings(
        abuseipdb_api_key=os.environ["ABUSEIPDB_API_KEY"],
        abuseipdb_max_age_days=int(
            os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90")
        ),
        abuseipdb_cache_hours=int(
            os.getenv("ABUSEIPDB_CACHE_HOURS", "24")
        ),

        cloudflare_api_token=os.environ["CLOUDFLARE_API_TOKEN"],
        cloudflare_account_id=os.environ["CLOUDFLARE_ACCOUNT_ID"],
        cloudflare_list_id=os.environ["CLOUDFLARE_LIST_ID"],

        nginx_access_log=os.getenv(
            "NGINX_ACCESS_LOG",
            "/var/log/nginx/roxell.access.log",
        ),

        sqlite_path=os.getenv(
            "SQLITE_PATH",
            "/opt/cloudflare-abuseipdb-blocker/data/reputation.db",
        ),

        block_threshold=int(
            os.getenv("BLOCK_THRESHOLD", "90")
        ),
        monitor_threshold=int(
            os.getenv("MONITOR_THRESHOLD", "80")
        ),

        block_ttl_days=int(
            os.getenv("BLOCK_TTL_DAYS", "30")
        ),
        recheck_interval_days=int(
            os.getenv("RECHECK_INTERVAL_DAYS", "7")
        ),

        dry_run=get_bool("DRY_RUN", True),
    )
