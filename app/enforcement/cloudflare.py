import logging
import time
from dataclasses import dataclass

import requests


logger = logging.getLogger("ip-reputation-worker.cloudflare")

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareAPIError(Exception):
    """Raised when Cloudflare API returns an unsuccessful response."""


@dataclass(frozen=True)
class CloudflareOperation:
    operation_id: str
    status: str
    success: bool


@dataclass(frozen=True)
class CloudflareListItem:
    item_id: str
    ip: str
    comment: str | None


class CloudflareClient:
    def __init__(
        self,
        api_token: str,
        account_id: str,
        list_id: str,
        timeout: int = 15,
        max_retries: int = 4,
    ):
        self.account_id = account_id
        self.list_id = list_id
        self.timeout = timeout
        self.max_retries = max_retries

        self.session = requests.Session()

        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    # =========================================================
    # INTERNAL REQUEST
    # =========================================================

    def _request(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> requests.Response:

        url = f"{CLOUDFLARE_API_BASE}{path}"

        last_response = None

        for attempt in range(self.max_retries + 1):

            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.timeout,
                    **kwargs,
                )

                last_response = response

            except requests.RequestException as exc:

                if attempt >= self.max_retries:
                    raise CloudflareAPIError(
                        f"Cloudflare request failed: {exc}"
                    ) from exc

                delay = 2 ** attempt

                logger.warning(
                    "Cloudflare request error | "
                    "attempt=%s/%s | retry_in=%ss | error=%s",
                    attempt + 1,
                    self.max_retries + 1,
                    delay,
                    exc,
                )

                time.sleep(delay)
                continue

            # -------------------------------------------------
            # Success
            # -------------------------------------------------

            if response.ok:
                return response

            # -------------------------------------------------
            # Rate limit
            # -------------------------------------------------

            if response.status_code == 429:

                if attempt >= self.max_retries:
                    break

                retry_after = response.headers.get("Retry-After")

                try:
                    delay = int(retry_after)
                except (TypeError, ValueError):
                    delay = 2 ** attempt

                logger.warning(
                    "Cloudflare rate limited | "
                    "attempt=%s/%s | retry_in=%ss",
                    attempt + 1,
                    self.max_retries + 1,
                    delay,
                )

                time.sleep(delay)
                continue

            # -------------------------------------------------
            # Server error
            # -------------------------------------------------

            if 500 <= response.status_code <= 599:

                if attempt >= self.max_retries:
                    break

                delay = 2 ** attempt

                logger.warning(
                    "Cloudflare server error | "
                    "status=%s | attempt=%s/%s | retry_in=%ss",
                    response.status_code,
                    attempt + 1,
                    self.max_retries + 1,
                    delay,
                )

                time.sleep(delay)
                continue

            # -------------------------------------------------
            # Normal 4xx error
            # -------------------------------------------------

            break

        if last_response is not None:

            try:
                payload = last_response.json()
            except ValueError:
                payload = last_response.text

            raise CloudflareAPIError(
                "Cloudflare API error | "
                f"status={last_response.status_code} | "
                f"response={payload}"
            )

        raise CloudflareAPIError(
            "Cloudflare API request failed without response"
        )

    # =========================================================
    # GET LIST ITEMS
    # =========================================================

    def get_list_items(self) -> list[CloudflareListItem]:
        """
        Get all items currently present in the Cloudflare IP list.

        Endpoint:
            GET /accounts/{account_id}/rules/lists/{list_id}/items
        """

        path = (
            f"/accounts/{self.account_id}"
            f"/rules/lists/{self.list_id}/items"
        )

        response = self._request(
            "GET",
            path,
            params={
                "per_page": 500,
            },
        )

        payload = response.json()

        if not payload.get("success"):
            raise CloudflareAPIError(
                f"Cloudflare list items API unsuccessful: {payload}"
            )

        result = payload.get("result") or []

        items = []

        for item in result:

            # Cloudflare IP list item:
            #
            # {
            #   "id": "...",
            #   "ip": "192.0.2.10",
            #   "comment": "..."
            # }

            if not isinstance(item, dict):
                raise CloudflareAPIError(
                    "Unexpected Cloudflare list item format: "
                    f"{item!r}"
                )

            if "id" not in item or "ip" not in item:
                raise CloudflareAPIError(
                    f"Invalid Cloudflare IP list item: {item}"
                )

            items.append(
                CloudflareListItem(
                    item_id=item["id"],
                    ip=item["ip"],
                    comment=item.get("comment"),
                )
            )

        return items

    # =========================================================
    # ADD IP
    # =========================================================

    def add_ip(
        self,
        ip: str,
        comment: str | None = None,
    ) -> str:
        """
        Add an IP to the Cloudflare list.

        Returns:
            operation_id
        """

        path = (
            f"/accounts/{self.account_id}"
            f"/rules/lists/{self.list_id}/items"
        )

        item = {
            "ip": ip,
        }

        if comment:
            item["comment"] = comment

        response = self._request(
            "POST",
            path,
            json=[item],
        )

        payload = response.json()

        if not payload.get("success"):
            raise CloudflareAPIError(
                f"Cloudflare add IP unsuccessful: {payload}"
            )

        operation_id = (
            payload.get("result", {})
            .get("operation_id")
        )

        if not operation_id:
            raise CloudflareAPIError(
                "Cloudflare add IP did not return "
                f"operation_id: {payload}"
            )

        logger.info(
            "Cloudflare add submitted | "
            "IP=%s | operation_id=%s",
            ip,
            operation_id,
        )

        return operation_id

    # =========================================================
    # DELETE IP
    # =========================================================

    def delete_item(
        self,
        item_id: str,
    ) -> str:
        """
        Delete a Cloudflare list item by item ID.

        Returns:
            operation_id
        """

        path = (
            f"/accounts/{self.account_id}"
            f"/rules/lists/{self.list_id}/items"
        )

        payload = {
            "items": [
                {
                    "id": item_id,
                }
            ]
        }

        response = self._request(
            "DELETE",
            path,
            json=payload,
        )

        result = response.json()

        if not result.get("success"):
            raise CloudflareAPIError(
                f"Cloudflare delete unsuccessful: {result}"
            )

        operation_id = (
            result.get("result", {})
            .get("operation_id")
        )

        if not operation_id:
            raise CloudflareAPIError(
                "Cloudflare delete did not return "
                f"operation_id: {result}"
            )

        logger.info(
            "Cloudflare delete submitted | "
            "item_id=%s | operation_id=%s",
            item_id,
            operation_id,
        )

        return operation_id

    # =========================================================
    # OPERATION STATUS
    # =========================================================

    def get_operation(
        self,
        operation_id: str,
    ) -> CloudflareOperation:
        """
        Get status of a Cloudflare bulk operation.
        """

        path = (
            f"/accounts/{self.account_id}"
            f"/rules/lists/bulk_operations/{operation_id}"
        )

        response = self._request(
            "GET",
            path,
        )

        payload = response.json()

        if not payload.get("success"):
            raise CloudflareAPIError(
                "Cloudflare operation API unsuccessful: "
                f"{payload}"
            )

        result = payload.get("result") or {}

        status = result.get("status", "unknown")

        return CloudflareOperation(
            operation_id=operation_id,
            status=status,
            success=bool(payload.get("success")),
        )

    # =========================================================
    # WAIT FOR OPERATION
    # =========================================================

    def wait_for_operation(
        self,
        operation_id: str,
        poll_interval: int = 2,
        timeout_seconds: int = 60,
    ) -> CloudflareOperation:
        """
        Poll Cloudflare bulk operation until completion.
        """

        start_time = time.monotonic()

        while True:

            operation = self.get_operation(
                operation_id
            )

            logger.info(
                "Cloudflare operation | "
                "operation_id=%s | status=%s",
                operation_id,
                operation.status,
            )

            status = operation.status.lower()

            if status in {
                "completed",
                "complete",
                "success",
            }:
                return operation

            if status in {
                "failed",
                "error",
            }:
                raise CloudflareAPIError(
                    "Cloudflare bulk operation failed | "
                    f"operation_id={operation_id} | "
                    f"status={operation.status}"
                )

            elapsed = time.monotonic() - start_time

            if elapsed >= timeout_seconds:
                raise TimeoutError(
                    "Cloudflare operation timeout | "
                    f"operation_id={operation_id} | "
                    f"timeout={timeout_seconds}s"
                )

            time.sleep(poll_interval)

    # =========================================================
    # FIND IP
    # =========================================================

    def find_ip(
        self,
        ip: str,
    ) -> CloudflareListItem | None:
        """
        Find an IP in the Cloudflare list.
        """

        items = self.get_list_items()

        for item in items:
            if item.ip == ip:
                return item

        return None
