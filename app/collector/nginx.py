import ipaddress
import re
from pathlib import Path

from app.storage.sqlite import ReputationDB


IPV4_PATTERN = re.compile(r"^(?P<ip>\S+)\s")


def is_valid_ipv4(value: str) -> bool:
    """
    Return True only for globally routable IPv4 addresses.

    Private, loopback, link-local, multicast, reserved,
    unspecified, and other non-global IPv4 addresses are ignored.
    """
    try:
        address = ipaddress.ip_address(value)

        return (
            address.version == 4
            and address.is_global
        )

    except ValueError:
        return False


def extract_ip_from_line(line: str) -> str | None:
    """
    Extract the client IPv4 address from the beginning
    of an Nginx access-log line.

    Expected format:

        1.2.3.4 - - [date] "GET / HTTP/1.1" ...

    Only globally routable IPv4 addresses are returned.
    """

    match = IPV4_PATTERN.match(line)

    if not match:
        return None

    ip = match.group("ip")

    if not is_valid_ipv4(ip):
        return None

    return ip


def collect_ips(log_path: str) -> list[str]:
    """
    Compatibility helper for the original collector tests.

    Read an Nginx access log and return unique globally
    routable IPv4 addresses.

    NOTE:
    This helper does NOT maintain SQLite collector state.
    The production worker should use NginxCollector instead.
    """

    path = Path(log_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Nginx access log not found: {path}"
        )

    ips: set[str] = set()

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as log_file:

        for line in log_file:

            ip = extract_ip_from_line(line)

            if ip:
                ips.add(ip)

    return sorted(ips)


class NginxCollector:

    def __init__(
        self,
        log_path: str,
        db: ReputationDB,
    ):
        self.log_path = Path(log_path)
        self.db = db

    def collect(self) -> list[str]:
        """
        Incrementally collect new globally routable IPv4
        addresses from the Nginx access log.

        Collector state is persisted in SQLite using:

        - inode
        - byte offset

        This allows the collector to survive:

        - worker restarts
        - normal log growth
        - log rotation
        - truncated logs
        """

        if not self.log_path.exists():
            raise FileNotFoundError(
                f"Nginx access log not found: {self.log_path}"
            )

        stat = self.log_path.stat()

        current_inode = stat.st_ino
        current_size = stat.st_size

        state = self.db.get_collector_state(
            str(self.log_path)
        )

        # ====================================================
        # Determine starting offset
        # ====================================================

        if state is None:

            # First run:
            #
            # Do NOT process historical log entries.
            # Start from current end of file.

            start_offset = current_size

        elif state["file_inode"] != current_inode:

            # Log rotated/recreated.

            start_offset = 0

        elif current_size < state["file_offset"]:

            # File was truncated.

            start_offset = 0

        else:

            # Normal incremental processing.

            start_offset = state["file_offset"]

        ips: set[str] = set()

        # ====================================================
        # Read new log data
        # ====================================================

        with self.log_path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as log_file:

            log_file.seek(start_offset)

            while True:

                line = log_file.readline()

                if not line:
                    break

                ip = extract_ip_from_line(line)

                if not ip:
                    continue

                ips.add(ip)

                # Record request activity in SQLite.
                self.db.record_seen(ip)

            final_offset = log_file.tell()

        # ====================================================
        # Persist collector state
        # ====================================================

        self.db.save_collector_state(
            log_path=str(self.log_path),
            file_inode=current_inode,
            file_offset=final_offset,
        )

        return sorted(ips)
