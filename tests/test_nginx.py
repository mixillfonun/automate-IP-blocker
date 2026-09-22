from pathlib import Path

from app.collector.nginx import (
    collect_ips,
    extract_ip_from_line,
    is_valid_ipv4,
)


def test_is_valid_ipv4_accepts_public_ipv4():
    assert is_valid_ipv4("8.8.8.8") is True
    assert is_valid_ipv4("1.1.1.1") is True


def test_is_valid_ipv4_rejects_private_ipv4():
    assert is_valid_ipv4("10.0.0.1") is False
    assert is_valid_ipv4("172.16.0.1") is False
    assert is_valid_ipv4("192.168.1.1") is False


def test_is_valid_ipv4_rejects_special_ipv4():
    assert is_valid_ipv4("127.0.0.1") is False
    assert is_valid_ipv4("0.0.0.0") is False


def test_is_valid_ipv4_rejects_invalid_value():
    assert is_valid_ipv4("not-an-ip") is False
    assert is_valid_ipv4("999.999.999.999") is False


def test_extract_ip_from_nginx_line():
    line = (
        '8.8.8.8 - - [21/Sep/2026:10:00:00 +0700] '
        '"GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
    )

    assert extract_ip_from_line(line) == "8.8.8.8"


def test_extract_ip_rejects_private_ip():
    line = (
        '192.168.1.10 - - [21/Sep/2026:10:00:00 +0700] '
        '"GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
    )

    assert extract_ip_from_line(line) is None


def test_extract_ip_rejects_invalid_line():
    assert extract_ip_from_line("invalid nginx line") is None


def test_collect_ips_returns_unique_global_ipv4(tmp_path: Path):
    log_file = tmp_path / "access.log"

    log_file.write_text(
        "\n".join(
            [
                '8.8.8.8 - - [21/Sep/2026:10:00:00 +0700] "GET / HTTP/1.1" 200 123',
                '8.8.8.8 - - [21/Sep/2026:10:00:01 +0700] "GET /foo HTTP/1.1" 200 123',
                '1.1.1.1 - - [21/Sep/2026:10:00:02 +0700] "GET / HTTP/1.1" 200 123',
                '192.168.1.10 - - [21/Sep/2026:10:00:03 +0700] "GET / HTTP/1.1" 200 123',
                '127.0.0.1 - - [21/Sep/2026:10:00:04 +0700] "GET / HTTP/1.1" 200 123',
            ]
        )
        + "\n"
    )

    ips = collect_ips(str(log_file))

    assert ips == [
        "1.1.1.1",
        "8.8.8.8",
    ]
