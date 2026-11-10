"""Detection rules: turn raw log lines into classified attack events.

Every parser receives a single log line and returns a :class:`ParsedLine` or
``None``. ``parse_line`` auto-detects the format, so a single log file or the
syslog receiver can carry mixed content (sshd, nginx, UFW, fail2ban...).
"""

from __future__ import annotations

from collections.abc import Callable
import re
from urllib.parse import unquote_plus

from .models import SEVERITY_RANK, AttackType, ParsedLine, Severity

# ---------------------------------------------------------------------------
# Home Assistant authentication (logger: homeassistant.components.http.ban)
# ---------------------------------------------------------------------------

# HA >= 2023: "Login attempt or request with invalid authentication from
#   <host> (<ip>). Requested URL: '<url>'. (<user agent>)"
# Older versions only log "... invalid authentication from <ip>".
# The URL and User-Agent are attacker-controlled and may contain quotes or
# parentheses, so they are anchored on the fixed separators of the message.
_HA_INVALID_AUTH = re.compile(
    r"invalid authentication from (?P<host>[^\s()]+)"
    r"(?: \((?P<ip>[^)\s]+)\))?\.?"
    r"(?: Requested URL: '(?P<url>.*?)'\.(?: \((?P<ua>.*)\))?\s*$)?"
)
_HA_BANNED = re.compile(r"Banned IP (?P<ip>\S+) for too many login attempts")


def parse_ha_auth_message(message: str) -> ParsedLine | None:
    """Parse a message emitted by Home Assistant's ``http.ban`` logger."""
    if m := _HA_BANNED.search(message):
        return ParsedLine(
            AttackType.BANNED_IP,
            m["ip"],
            details="Home Assistant baniu o IP após excesso de tentativas",
        )
    if m := _HA_INVALID_AUTH.search(message):
        ip = m["ip"] or m["host"]
        ua = m["ua"] if m["ua"] not in (None, "", "None") else None
        details = f"User-Agent: {ua}" if ua else None
        parsed = ParsedLine(
            AttackType.FAILED_LOGIN,
            ip,
            severity=Severity.MEDIUM,
            target=m["url"],
            details=details,
        )
        # A failed login that also carries an exploit pattern is escalated.
        if m["url"] or ua:
            exploit = classify_http_request(m["url"] or "", ua or "")
            if exploit and SEVERITY_RANK[exploit.severity or Severity.LOW] > 2:
                exploit.ip = ip
                exploit.target = m["url"]
                return exploit
        return parsed
    return None


# ---------------------------------------------------------------------------
# OpenSSH
# ---------------------------------------------------------------------------

_SSH_FAILED = re.compile(
    r"Failed (?:password|publickey|none|keyboard-interactive/pam) for "
    r"(?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_INVALID_USER = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
_SSH_MAX_AUTH = re.compile(
    r"maximum authentication attempts exceeded for (?:invalid user )?"
    r"(?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)
_SSH_NO_IDENT = re.compile(r"Did not receive identification string from (?P<ip>\S+)")
_SSH_BAD_PROTO = re.compile(
    r"(?:Bad protocol version identification|Unable to negotiate with|"
    r"banner exchange: Connection from) .*?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})"
)
_SSH_BREAKIN = re.compile(r"POSSIBLE BREAK-IN ATTEMPT.*?\[(?P<ip>[^\]]+)\]")


def parse_ssh_line(line: str) -> ParsedLine | None:
    """Parse OpenSSH (sshd) authentication messages."""
    if "sshd" not in line and "ssh" not in line.lower():
        return None
    if m := _SSH_FAILED.search(line):
        # "Failed password for invalid user X" is always preceded by an
        # "Invalid user X" line; count the attempt only once.
        if m["invalid"]:
            return None
        return ParsedLine(
            AttackType.FAILED_LOGIN,
            m["ip"],
            port=22,
            username=m["user"],
            target="ssh",
            details="Falha de autenticação SSH",
        )
    if m := _SSH_INVALID_USER.search(line):
        return ParsedLine(
            AttackType.FAILED_LOGIN,
            m["ip"],
            port=22,
            username=m["user"],
            target="ssh",
            details="Usuário SSH inexistente",
        )
    if m := _SSH_MAX_AUTH.search(line):
        return ParsedLine(
            AttackType.BRUTE_FORCE,
            m["ip"],
            severity=Severity.MEDIUM,
            port=22,
            username=m["user"],
            target="ssh",
            details="Máximo de tentativas de autenticação SSH excedido",
        )
    if m := _SSH_BREAKIN.search(line):
        return ParsedLine(
            AttackType.SUSPICIOUS_REQUEST,
            m["ip"],
            severity=Severity.MEDIUM,
            port=22,
            target="ssh",
            details="POSSIBLE BREAK-IN ATTEMPT (DNS reverso inconsistente)",
        )
    if m := _SSH_NO_IDENT.search(line) or _SSH_BAD_PROTO.search(line):
        return ParsedLine(
            AttackType.SCANNER,
            m["ip"],
            severity=Severity.LOW,
            port=22,
            target="ssh",
            details="Sondagem do serviço SSH",
        )
    return None


# ---------------------------------------------------------------------------
# fail2ban
# ---------------------------------------------------------------------------

_FAIL2BAN_BAN = re.compile(r"\[(?P<jail>[^\]]+)\]\s+Ban\s+(?P<ip>\S+)")


def parse_fail2ban_line(line: str) -> ParsedLine | None:
    """Parse fail2ban ``Ban`` actions."""
    if "fail2ban" not in line:
        return None
    if m := _FAIL2BAN_BAN.search(line):
        return ParsedLine(
            AttackType.BANNED_IP,
            m["ip"],
            target=m["jail"],
            details=f"fail2ban baniu o IP (jail {m['jail']})",
        )
    return None


# ---------------------------------------------------------------------------
# Firewalls: UFW / iptables LOG / pfSense-OPNsense filterlog
# ---------------------------------------------------------------------------

_KV_SRC = re.compile(r"\bSRC=(?P<ip>[0-9a-fA-F.:]+)")
_KV_DPT = re.compile(r"\bDPT=(?P<port>\d+)")
_KV_PROTO = re.compile(r"\bPROTO=(?P<proto>\w+)")


def parse_firewall_line(line: str) -> ParsedLine | None:
    """Parse blocked-packet logs from common firewalls."""
    if "filterlog" in line:
        return _parse_pf_filterlog(line)
    if " IN=" not in line or "SRC=" not in line:
        return None
    lowered = line.lower()
    if "ufw" in lowered and not any(k in line for k in ("BLOCK", "DENY", "LIMIT")):
        return None  # "[UFW ALLOW]" and similar are not attacks
    if not (src := _KV_SRC.search(line)):
        return None
    dpt = _KV_DPT.search(line)
    proto = _KV_PROTO.search(line)
    port = int(dpt["port"]) if dpt else None
    proto_name = proto["proto"] if proto else "?"
    return ParsedLine(
        AttackType.FIREWALL_BLOCK,
        src["ip"],
        port=port,
        target=f"{proto_name}/{port}" if port else proto_name,
        details="Pacote bloqueado pelo firewall",
    )


def _parse_pf_filterlog(line: str) -> ParsedLine | None:
    # filterlog CSV: rule,sub,anchor,tracker,iface,reason,action,dir,ipver,...
    payload = line.split("filterlog", 1)[1]
    payload = payload.split(":", 1)[1] if ":" in payload else payload
    fields = [f.strip() for f in payload.strip().split(",")]
    if len(fields) < 9 or fields[6] != "block":
        return None
    try:
        if fields[8] == "4":
            proto, src, dport = fields[16], fields[18], fields[21]
        elif fields[8] == "6":
            proto, src, dport = fields[12], fields[15], fields[18]
        else:
            return None
    except IndexError:
        return None
    port = int(dport) if dport.isdigit() else None
    return ParsedLine(
        AttackType.FIREWALL_BLOCK,
        src,
        port=port,
        target=f"{proto}/{port}" if port else proto,
        details=f"Pacote bloqueado pelo firewall ({fields[4]})",
    )


# ---------------------------------------------------------------------------
# HTTP access logs (nginx / Apache / Caddy / Traefik "combined" format)
# ---------------------------------------------------------------------------

_ACCESS_LOG = re.compile(
    r"^(?:\S+\s+)?(?P<ip>[0-9a-fA-F.:\[\]]+) \S+ (?P<user>\S+) \[[^\]]+\] "
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) \S+'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)

_Rule = tuple[AttackType, Severity, re.Pattern[str]]


def _rx(*patterns: str) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


# Order matters only for readability; the most severe match wins.
_HTTP_RULES: list[_Rule] = [
    (
        AttackType.LOG4SHELL,
        Severity.CRITICAL,
        _rx(r"\$\{\s*(?:jndi|lower|upper|env|sys|::-|date)"),
    ),
    (
        AttackType.SHELLSHOCK,
        Severity.CRITICAL,
        _rx(r"\(\s*\)\s*\{\s*:?\s*;\s*\}"),
    ),
    (
        AttackType.COMMAND_INJECTION,
        Severity.CRITICAL,
        _rx(
            r"[;|`&]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python\d?|perl|chmod|busybox|tftp)\b",
            r"\$\(\s*[a-z]",
            r"\b(?:wget|curl)\s+(?:-\S+\s+)*https?://",
            r"/bin/(?:ba)?sh\b",
            r"\bcmd(?:\.exe)?\s*/c\b",
            r"\bpowershell\b",
        ),
    ),
    (
        AttackType.SQL_INJECTION,
        Severity.HIGH,
        _rx(
            r"\bunion\b(?:\s|/\*.*?\*/)+(?:all\s+)?select\b",
            r"\bselect\b.{1,200}?\bfrom\b",
            r"(?:'|\")\s*(?:or|and)\s+(?:'|\"|\d)",
            r"\b(?:or|and)\s+\d+\s*=\s*\d+",
            r"\bsleep\s*\(\s*\d+\s*\)",
            r"\bbenchmark\s*\(",
            r"\binformation_schema\b",
            r"\bwaitfor\s+delay\b",
            r"\bxp_cmdshell\b",
            r"\bload_file\s*\(",
            r"\binto\s+(?:out|dump)file\b",
            r"\bpg_sleep\s*\(",
        ),
    ),
    (
        AttackType.PATH_TRAVERSAL,
        Severity.HIGH,
        _rx(
            r"\.\.[/\\]",
            r"/etc/(?:passwd|shadow|hosts|group)\b",
            r"\b(?:boot|win)\.ini\b",
            r"/proc/self/",
            r"c:\\windows\\",
        ),
    ),
    (
        AttackType.XSS,
        Severity.MEDIUM,
        _rx(
            r"<\s*script",
            r"javascript\s*:",
            r"<[^>]*\bon(?:error|load|mouseover|focus|click|toggle)\s*=",
            r"document\.(?:cookie|location|domain)",
            r"\balert\s*\(",
            r"<\s*(?:iframe|svg|embed|object)\b",
        ),
    ),
    (
        AttackType.SENSITIVE_FILE_PROBE,
        Severity.MEDIUM,
        _rx(
            r"/\.(?:env|git|svn|hg|aws|ssh|docker|htpasswd|htaccess|ds_store|vscode)\b",
            r"/wp-(?:login|admin|content|includes)",
            r"/xmlrpc\.php",
            r"phpmyadmin|/pma/|/myadmin",
            r"/(?:server-status|server-info)\b",
            r"/actuator\b",
            r"/(?:backup|dump|db|database|site)\.(?:sql|zip|tar|gz|tgz|bak|7z)\b",
            r"/cgi-bin/",
            r"/(?:boaform|hnap1|goform|setup\.cgi|shell)\b",
            r"/vendor/phpunit",
            r"/(?:owa|autodiscover|ecp|remote/login|global-protect|dana-na)\b",
            r"/(?:solr|jenkins|manager/html|console|druid)\b",
            r"/secrets\.yaml",
            r"\.(?:php\d?|asp|aspx|jsp|cgi|pl)(?:\?|$|/)",
        ),
    ),
]

_SCANNER_UA = _rx(
    r"sqlmap",
    r"nikto",
    r"nmap",
    r"masscan",
    r"zgrab",
    r"nuclei",
    r"gobuster",
    r"dirbuster",
    r"\bdirb\b",
    r"wpscan",
    r"acunetix",
    r"nessus",
    r"openvas",
    r"fuzz faster u fool|\bffuf\b",
    r"wfuzz",
    r"hydra",
    r"censysinspect",
    r"expanse",
    r"l9explore|l9tcpid",
    r"projectdiscovery",
    r"internet-measurement",
    r"netsystemsresearch",
    r"\bwhatweb\b",
    r"\bferoxbuster\b",
    r"\bjaeles\b",
)


def _decode(value: str) -> str:
    """URL-decode twice to catch double-encoded payloads."""
    try:
        return unquote_plus(unquote_plus(value))
    except Exception:
        return value


def classify_http_request(path: str, user_agent: str = "") -> ParsedLine | None:
    """Classify an HTTP request path/User-Agent; return the most severe match."""
    decoded = _decode(path)
    haystacks = (decoded, user_agent)
    best: ParsedLine | None = None
    matched: list[str] = []
    for attack_type, severity, pattern in _HTTP_RULES:
        if any(pattern.search(h) for h in haystacks if h):
            matched.append(str(attack_type))
            if best is None or SEVERITY_RANK[severity] > SEVERITY_RANK[best.severity]:  # type: ignore[index]
                best = ParsedLine(attack_type, None, severity=severity)
    if user_agent and _SCANNER_UA.search(user_agent):
        matched.append(str(AttackType.SCANNER))
        if best is None:
            best = ParsedLine(AttackType.SCANNER, None, severity=Severity.MEDIUM)
    if best is not None:
        best.matches = matched
        best.target = path
        extra = f"; também: {', '.join(m for m in matched if m != best.attack_type)}"
        best.details = (
            f"Padrão {best.attack_type} detectado"
            + (extra if len(matched) > 1 else "")
            + (f" | UA: {user_agent}" if user_agent else "")
        )
    return best


def parse_access_log_line(line: str) -> ParsedLine | None:
    """Parse a web server access log line in (common/combined) format."""
    m = _ACCESS_LOG.search(line)
    if not m:
        return None
    request = m["request"]
    ua = m["ua"] or ""
    parts = request.split(" ")
    if len(parts) >= 2 and parts[0].isalpha() and parts[0].isupper():
        method, path = parts[0], parts[1]
    else:
        # Binary/garbage request line: TLS on plain HTTP, protocol probes...
        if request in ("", "-"):
            return None
        return ParsedLine(
            AttackType.SUSPICIOUS_REQUEST,
            m["ip"],
            target=request[:120],
            details=f"Requisição HTTP malformada (status {m['status']})",
        )
    parsed = classify_http_request(path, ua)
    if parsed is None and method in ("CONNECT", "PROPFIND", "TRACE", "TRACK"):
        parsed = ParsedLine(
            AttackType.SUSPICIOUS_REQUEST,
            None,
            target=path,
            details=f"Método HTTP incomum: {method}",
        )
    if parsed is None:
        return None
    parsed.ip = m["ip"]
    parsed.target = f"{method} {path}"[:512]
    parsed.details = f"{parsed.details} (HTTP {m['status']})"
    return parsed


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------

_PARSERS: tuple[Callable[[str], ParsedLine | None], ...] = (
    parse_fail2ban_line,
    parse_firewall_line,
    parse_ssh_line,
    parse_access_log_line,
    parse_ha_auth_message,
)


def parse_line(line: str) -> ParsedLine | None:
    """Try every known format and return the first match."""
    line = line.strip()
    if not line:
        return None
    for parser in _PARSERS:
        if (result := parser(line)) is not None:
            return result
    return None


_SYSLOG_PRI = re.compile(r"^<\d{1,3}>(?:1 )?")


def strip_syslog_header(message: str) -> str:
    """Remove the ``<PRI>`` prefix of RFC3164/RFC5424 syslog messages."""
    return _SYSLOG_PRI.sub("", message.strip())
