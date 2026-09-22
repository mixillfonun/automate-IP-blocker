from dataclasses import dataclass

import requests


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


@dataclass(frozen=True)
class ReputationResult:
    ip: str
    score: int
    is_public: bool
    is_whitelisted: bool
    total_reports: int
    num_distinct_users: int
    country_code: str | None
    usage_type: str | None
    isp: str | None
    domain: str | None
    last_reported_at: str | None


class AbuseIPDBClient:
    def __init__(
        self,
        api_key: str,
        max_age_days: int = 90,
        timeout: int = 15,
    ):
        self.api_key = api_key
        self.max_age_days = max_age_days
        self.timeout = timeout

    def check(self, ip: str) -> ReputationResult:
        response = requests.get(
            ABUSEIPDB_URL,
            params={
                "ipAddress": ip,
                "maxAgeInDays": self.max_age_days,
            },
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
            },
            timeout=self.timeout,
        )

        response.raise_for_status()

        payload = response.json()
        data = payload["data"]

        return ReputationResult(
            ip=data["ipAddress"],
            score=int(data["abuseConfidenceScore"]),
            is_public=bool(data["isPublic"]),
            is_whitelisted=bool(data["isWhitelisted"]),
            total_reports=int(data["totalReports"]),
            num_distinct_users=int(data["numDistinctUsers"]),
            country_code=data.get("countryCode"),
            usage_type=data.get("usageType"),
            isp=data.get("isp"),
            domain=data.get("domain"),
            last_reported_at=data.get("lastReportedAt"),
        )
