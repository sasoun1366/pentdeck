"""The checks.

Each check takes a shared context (the host, its open ports, the banners already
read) and returns findings. The context is mutated on purpose: reading a banner
once and letting every later check look at it is the difference between a scan
that finishes in seconds and one that reconnects for every question.

The registry is also the pricing boundary: `TIERS` in license.py lists the check
names each licence unlocks, so adding a check adds it to the product rather than
to the code only.
"""

from __future__ import annotations

import base64
import dataclasses
import http.client
import random
import socket
import ssl
import struct
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import certs
from .findings import Finding, Severity

#: Ports that usually answer with TLS. Used to decide where to handshake.
TLS_PORTS: Tuple[int, ...] = (443, 465, 636, 990, 993, 995, 5986, 8443, 8729, 9243, 9443)

#: Ports that usually answer with HTTP.
HTTP_PORTS: Tuple[int, ...] = (80, 443, 3000, 5000, 8000, 8006, 8080, 8081, 8443, 8888, 9090)

#: Ports that are certainly not web servers. Probing them with an HTTP request
#: only makes noise, so the http check skips them when it looks further afield.
NON_HTTP_PORTS = frozenset({
    22, 23, 25, 53, 110, 111, 135, 139, 143, 161, 389, 445, 465, 512, 513, 514,
    636, 990, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379,
    8728, 8729, 11211, 27017,
})

#: Cleartext services. An open one of these is a finding in its own right.
PLAINTEXT_PORTS: Dict[int, Tuple[str, Severity, str]] = {
    21: ("FTP", Severity.HIGH,
         "FTP sends everything, including the password, in the clear. Move the file "
         "transfer to SFTP or FTPS and close port 21."),
    23: ("Telnet", Severity.HIGH,
         "Telnet is a plaintext shell. Replace it with SSH and close port 23 — this is "
         "one of the first things an attacker looks for."),
    25: ("SMTP without TLS", Severity.MEDIUM,
         "Mail submission on port 25 with no forced TLS can leak credentials. Require "
         "STARTTLS or move clients to port 587/465."),
    110: ("POP3 without TLS", Severity.MEDIUM,
          "Use POP3S (995) or require STLS on 110."),
    143: ("IMAP without TLS", Severity.MEDIUM,
          "Use IMAPS (993) or require STARTTLS on 143."),
    111: ("rpcbind", Severity.MEDIUM,
          "rpcbind on port 111 exposes RPC services; if it is not needed, stop it and "
          "restrict access with the firewall."),
    161: ("SNMP", Severity.MEDIUM,
          "SNMP answers on this host — check that it is v3 with a real community string, "
          "and that it is not reachable from outside the management network."),
    512: ("rexec", Severity.HIGH, "rexec is obsolete and unauthenticated in practice. Disable it."),
    513: ("rlogin", Severity.HIGH, "rlogin trusts the source host, not the user. Disable it."),
    514: ("rsh", Severity.HIGH, "rsh is unauthenticated. Disable it."),
    5900: ("VNC", Severity.HIGH,
           "VNC on 5900 is often password-only and sometimes has no password at all. "
           "Tunnel it over SSH or a VPN, and restrict it to management addresses."),
    3389: ("RDP", Severity.LOW,
           "RDP is fine to use, but it must not be reachable from outside the company "
           "network, and Network Level Authentication should be enforced."),
}

HTTP_METHODS = "GET"

#: How much of a banner to keep. Long banners are noise; the version is in the first line.
BANNER_LIMIT = 200


class CheckContext:
    """Everything the checks share about one host."""

    def __init__(self, host: str, ports: Sequence[int], timeout: float = 5.0,
                 intrusive: bool = False, http_ports: Sequence[int] = HTTP_PORTS,
                 tls_ports: Sequence[int] = TLS_PORTS, port_workers: int = 64,
                 probe_unknown_ports: bool = True):
        self.host = host
        self.candidate_ports = list(ports)
        self.timeout = timeout
        self.intrusive = intrusive
        self.this_http_ports = list(http_ports)
        self.this_tls_ports = list(tls_ports)
        self.port_workers = port_workers
        #: A web panel on 8082 is exactly what a scan is for, so one port that is
        #: not a known web port still gets a single HTTP probe. --no-service-probe
        #: turns that off for a scan that must stay as quiet as possible.
        self.probe_unknown_ports = probe_unknown_ports
        self.open_ports: List[int] = []
        self.banners: Dict[int, str] = {}
        #: Ports where a TLS handshake actually succeeded, whatever the port number.
        self.tls_confirmed: List[int] = []

    # ── helpers used by more than one check ──────────────────────────────────
    def is_open(self, port: int) -> bool:
        return port in self.open_ports

    def open_in(self, ports: Sequence[int]) -> List[int]:
        return [port for port in ports if port in self.open_ports]

    def http_like(self) -> List[int]:
        """Open ports worth asking for a page: known web ports, ports whose banner
        looks like HTTP, and — unless that was turned off — one probe per port that
        is not known to be something else."""
        out = set(self.open_in(self.this_http_ports))
        for port, banner in self.banners.items():
            head = banner.split("\r\n", 1)[0].upper()
            if head.startswith("HTTP/") or "HTTP/1." in head:
                out.add(port)
        if self.probe_unknown_ports:
            for port in self.open_ports:
                if port in out or port in NON_HTTP_PORTS or port in self.this_tls_ports:
                    continue
                banner = self.banners.get(port, "")
                if banner and "HTTP" not in banner.upper() and "TLS" not in banner.upper():
                    continue                              # it already told us what it is
                out.add(port)
        return sorted(out)

    def tls_like(self) -> List[int]:
        """Open ports that look like TLS, by port number or by handshake success."""
        return sorted(set(self.open_in(self.this_tls_ports) + self.tls_confirmed))


def _connect(host: str, port: int, timeout: float):
    return socket.create_connection((host, port), timeout=timeout)


# ---------------------------------------------------------------------------
# stage 1 — what is there
# ---------------------------------------------------------------------------
def check_ports(context: CheckContext) -> List[Finding]:
    """TCP connect scan. No root, no raw sockets, and it never sends a packet to a closed port twice."""
    import concurrent.futures

    def probe(port: int) -> Optional[int]:
        try:
            with _connect(context.host, port, context.timeout):
                return port
        except (OSError, socket.timeout):
            return None

    open_ports: List[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, context.port_workers)) as pool:
        for result in pool.map(probe, context.candidate_ports):
            if result is not None:
                open_ports.append(result)
    context.open_ports = sorted(open_ports)
    if not context.open_ports:
        return []
    return [Finding(
        check="ports",
        host=context.host,
        severity=Severity.INFO,
        title=f"{len(context.open_ports)} open TCP port(s)",
        detail="Ports answering a TCP connection: " + ", ".join(str(p) for p in context.open_ports),
        remediation="Confirm every one of these is meant to be reachable from this network.",
        evidence=f"connect scan of {len(context.candidate_ports)} port(s)",
    )]


# ---------------------------------------------------------------------------
# stage 2 — what is listening
# ---------------------------------------------------------------------------
def read_banner(context: CheckContext, port: int) -> str:
    """Read a service banner, nudging protocols that wait for the client to speak first."""
    # 1. some services greet on connect
    try:
        with _connect(context.host, port, min(context.timeout, 3.0)) as sock:
            sock.settimeout(min(context.timeout, 3.0))
            try:
                raw = sock.recv(BANNER_LIMIT)
            except (socket.timeout, OSError):
                raw = b""
            if not raw and port in context.this_http_ports:
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {context.host}\r\nUser-Agent: pentdeck\r\n\r\n".encode())
                try:
                    raw = sock.recv(BANNER_LIMIT)
                except (socket.timeout, OSError):
                    raw = b""
            if raw:
                return raw.decode("utf-8", "replace").strip()[:BANNER_LIMIT]
    except (OSError, socket.timeout):
        pass
    # 2. maybe it is TLS and stays silent until ClientHello
    try:
        certificate = certs.fetch(context.host, port, context.timeout)
        if port not in context.tls_confirmed:
            context.tls_confirmed.append(port)
        return f"TLS {certificate.tls_version} {certificate.subject}".strip()
    except certs.CertError:
        return ""


def check_banner(context: CheckContext) -> List[Finding]:
    """Identify the services behind the open ports, and complain about version leaks."""
    findings: List[Finding] = []
    for port in context.open_ports:
        banner = read_banner(context, port)
        if not banner:
            continue
        context.banners[port] = banner
        first_line = banner.splitlines()[0].strip()[:120]
        leaks_version = any(char.isdigit() for char in first_line) and any(
            marker in first_line.lower()
            for marker in ("server", "openssh", "apache", "nginx", "lighttpd", "vsftpd",
                           "proftpd", "iis", "microsoft", "routeros", "cisco", "exim",
                           "postfix", "dovecot", "proftp", "php", "tomcat", "jetty")
        )
        if leaks_version:
            findings.append(Finding(
                check="banner",
                host=context.host,
                port=port,
                severity=Severity.LOW,
                title="Service advertises its version",
                detail=f"Banner: {first_line}",
                remediation=(
                    "Version banners tell an attacker which exploits to try first. Where the "
                    "software allows it, hide the version (for example `server_tokens off` in "
                    "nginx) — and in any case patch this version."
                ),
                evidence=first_line,
            ))
    return findings


# ---------------------------------------------------------------------------
# stage 3 — how it is configured
# ---------------------------------------------------------------------------
def check_tls(context: CheckContext) -> List[Finding]:
    """Certificate validity and the protocol it was negotiated with."""
    findings: List[Finding] = []
    for port in context.tls_like():
        try:
            certificate = certs.fetch(context.host, port, context.timeout)
        except certs.CertError as exc:
            findings.append(Finding(
                check="tls", host=context.host, port=port, severity=Severity.LOW,
                title="TLS handshake failed",
                detail=str(exc),
                remediation="If this port is supposed to speak TLS, check the certificate and protocol settings.",
            ))
            continue

        days = certificate.days_left
        if days is not None and days < 0:
            findings.append(Finding(
                check="tls", host=context.host, port=port, severity=Severity.CRITICAL,
                title=f"TLS certificate expired {abs(days)} day(s) ago",
                detail=f"notAfter {certificate.not_after.date().isoformat()} — subject {certificate.subject}",
                remediation="Renew the certificate and add expiry monitoring so this cannot repeat silently.",
                evidence=certificate.subject,
            ))
        elif days is not None and days <= 7:
            findings.append(Finding(
                check="tls", host=context.host, port=port, severity=Severity.HIGH,
                title=f"TLS certificate expires in {days} day(s)",
                detail=f"notAfter {certificate.not_after.date().isoformat()}",
                remediation="Renew now; a certificate that expires during business hours takes a service with it.",
            ))
        elif days is not None and days <= 21:
            findings.append(Finding(
                check="tls", host=context.host, port=port, severity=Severity.MEDIUM,
                title=f"TLS certificate expires in {days} day(s)",
                detail=f"notAfter {certificate.not_after.date().isoformat()}",
                remediation="Schedule the renewal, or automate it.",
            ))

        if not certificate.verified:
            findings.append(Finding(
                check="tls", host=context.host, port=port, severity=Severity.HIGH,
                title="TLS certificate does not verify",
                detail=(certificate.error or "the chain did not validate")
                + f" — subject {certificate.subject or '?'}",
                remediation=(
                    "A browser shows a warning here, and users learn to click through it. "
                    "Install a proper certificate (an internal CA is fine) or fix the host name "
                    "and the intermediate chain."
                ),
                evidence=certificate.subject,
            ))
        if certificate.weak_protocol:
            findings.append(Finding(
                check="tls", host=context.host, port=port, severity=Severity.MEDIUM,
                title=f"Weak TLS version offered ({certificate.tls_version})",
                detail="TLS 1.0/1.1 are deprecated and no longer considered secure.",
                remediation="Require TLS 1.2 or newer in the server configuration.",
            ))
        if certificate.verified and not certificate.weak_protocol and (days is None or days > 21):
            findings.append(Finding(
                check="tls", host=context.host, port=port, severity=Severity.INFO,
                title=f"TLS looks healthy ({certificate.tls_version}, {days} day(s) left)",
                detail=f"subject {certificate.subject}",
            ))
    return findings


SENSITIVE_HEADERS = {
    "strict-transport-security": ("medium", "HSTS is missing",
                                  "Add `Strict-Transport-Security: max-age=31536000` so browsers refuse "
                                  "to fall back to plain HTTP."),
    "x-content-type-options": ("low", "X-Content-Type-Options is missing",
                               "Add `X-Content-Type-Options: nosniff` to stop MIME sniffing."),
}

FRAME_HEADERS = ("x-frame-options", "content-security-policy")


def fetch_http(context: CheckContext, port: int) -> Optional[dict]:
    """One GET / (or HEAD on failure). Returns status, headers, body head, and the TLS state."""
    scheme = "https" if port in context.this_tls_ports or port in context.tls_confirmed else "http"
    try:
        if scheme == "https":
            connection = http.client.HTTPSConnection(
                context.host, port, timeout=context.timeout,
                context=ssl._create_unverified_context(),  # noqa: SLF001 - the TLS check already reports trust
            )
        else:
            connection = http.client.HTTPConnection(context.host, port, timeout=context.timeout)
        connection.request(HTTP_METHODS, "/", headers={"Host": context.host,
                                                       "User-Agent": "pentdeck",
                                                       "Accept": "*/*"})
        response = connection.getresponse()
        body = response.read(4096).decode("utf-8", "replace")
        return {
            "status": response.status,
            "reason": response.reason,
            "headers": {key.lower(): value for key, value in response.getheaders()},
            "location": response.getheader("Location") or "",
            "body": body,
            "scheme": scheme,
        }
    except (OSError, ssl.SSLError, http.client.HTTPException):
        return None


def check_http(context: CheckContext) -> List[Finding]:
    """Headers, cookies, redirects and the odd exposed listing — all from one GET."""
    findings: List[Finding] = []
    for port in context.http_like():
        answer = fetch_http(context, port)
        if answer is None:
            continue
        status = answer["status"]
        headers = answer["headers"]
        secure_port = answer["scheme"] == "https"

        findings.append(Finding(
            check="http", host=context.host, port=port, severity=Severity.INFO,
            title=f"HTTP {status} {answer['reason']}".strip(),
            detail=f"server: {headers.get('server', '?')}",
        ))

        if not secure_port and status in (200, 301, 302, 401, 403):
            location = answer["location"].lower()
            if not location.startswith("https://"):
                findings.append(Finding(
                    check="http", host=context.host, port=port, severity=Severity.MEDIUM,
                    title="Plain HTTP is served without redirecting to HTTPS",
                    detail=f"GET / answered {status} over http://{context.host}:{port}",
                    remediation=(
                        "Redirect all HTTP to HTTPS on this port (301), and make sure the "
                        "credentials and session cookies never travel unencrypted."
                    ),
                ))

        for header, (level, title, remediation) in SENSITIVE_HEADERS.items():
            if header not in headers:
                if header == "strict-transport-security" and not secure_port:
                    continue                                   # meaningless on a plain HTTP port
                findings.append(Finding(
                    check="http", host=context.host, port=port,
                    severity=Severity(level), title=title,
                    detail=f"the response has no {header} header",
                    remediation=remediation,
                ))

        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
            findings.append(Finding(
                check="http", host=context.host, port=port, severity=Severity.LOW,
                title="Clickjacking protection is missing",
                detail="neither X-Frame-Options nor a CSP frame-ancestors directive is set",
                remediation="Add `X-Frame-Options: DENY` (or a CSP frame-ancestors rule).",
            ))

        server = headers.get("server", "")
        if server and any(char.isdigit() for char in server):
            findings.append(Finding(
                check="http", host=context.host, port=port, severity=Severity.LOW,
                title="Server header discloses its version",
                detail=f"Server: {server}",
                remediation="Hide the version in the server configuration and patch the version itself.",
            ))

        cookie = headers.get("set-cookie", "")
        if cookie:
            problems = []
            if "secure" not in cookie.lower():
                problems.append("no Secure flag")
            if "httponly" not in cookie.lower():
                problems.append("no HttpOnly flag")
            if problems:
                findings.append(Finding(
                    check="http", host=context.host, port=port, severity=Severity.MEDIUM,
                    title=f"Session cookie is missing flags ({', '.join(problems)})",
                    detail=f"Set-Cookie: {cookie[:120]}",
                    remediation=(
                        "Set Secure (so it never travels over plain HTTP) and HttpOnly (so a "
                        "cross-site scripting bug cannot read it) on session cookies."
                    ),
                    evidence=cookie[:120],
                ))

        head = answer["body"][:400].lower()
        if "<title>index of /" in head or "directory listing for" in head:
            findings.append(Finding(
                check="http", host=context.host, port=port, severity=Severity.MEDIUM,
                title="Directory listing is enabled",
                detail="the index page looks like a generated file listing",
                remediation="Turn off automatic indexes (`autoindex off`, `Options -Indexes`) — they map the server for free.",
            ))
    return findings


def check_plaintext(context: CheckContext) -> List[Finding]:
    """Cleartext services that are open at all are worth reporting."""
    findings: List[Finding] = []
    for port in context.open_in(PLAINTEXT_PORTS):
        name, severity, remediation = PLAINTEXT_PORTS[port]
        banner = context.banners.get(port, "")
        findings.append(Finding(
            check="plaintext",
            host=context.host,
            port=port,
            severity=severity,
            title=f"{name} is reachable",
            detail=(f"port {port} answered" + (f" — {banner.splitlines()[0][:80]}" if banner else "")),
            remediation=remediation,
            evidence=banner.splitlines()[0][:120] if banner else "",
        ))
    return findings


# ---------------------------------------------------------------------------
# intrusive — only with --intrusive and a licence that allows it
# ---------------------------------------------------------------------------
def _dns_question(name: str, qtype: int = 252) -> bytes:      # 252 = AXFR
    ident = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", ident, 0x0000, 1, 0, 0, 0)
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".") if part)
    return header + question + b"\x00" + struct.pack(">HH", qtype, 1)


def check_dns_zone_transfer(context: CheckContext) -> List[Finding]:
    """Ask the name server for the whole zone. Most refuse; the ones that answer are the finding."""
    host = context.host
    if host.replace(".", "").isdigit():
        return []
    if context.is_open(53) is False and not any(port == 53 for port in context.open_ports):
        # A zone transfer goes to the name server, which is often also the target.
        pass
    query = _dns_question(host)
    try:
        with _connect(host, 53, context.timeout) as sock:
            sock.settimeout(context.timeout)
            sock.sendall(struct.pack(">H", len(query)) + query)
            raw = sock.recv(4096)
    except (OSError, socket.timeout):
        return []
    if len(raw) < 14:
        return []
    question_length = 12 + 1 + len(host.encode()) + 4          # header + qname + qtype/qclass
    body = raw[2:]                                             # the length prefix is only on the wire
    if len(body) < question_length:
        return []
    flags = struct.unpack(">H", body[2:4])[0]
    rcode = flags & 0x000F
    answers = struct.unpack(">H", body[6:8])[0]
    if rcode == 0 and answers > 0:
        return [Finding(
            check="dns-zone-transfer",
            host=host,
            port=53,
            severity=Severity.HIGH,
            title="The name server allows a full zone transfer",
            detail=f"AXFR for {host} returned {answers} record(s) without authentication",
            remediation=(
                "Restrict zone transfers to the secondary name servers: in BIND, "
                "`allow-transfer { <secondary>; };`. An open transfer hands an attacker "
                "your complete list of hosts."
            ),
            evidence=f"rcode=0 answers={answers}",
        )]
    return []


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class Check:
    name: str
    title: str
    description: str
    stage: int
    run: Callable[[CheckContext], List[Finding]]
    intrusive: bool = False
    needs_open_port: bool = True


CHECKS: Dict[str, Check] = {
    item.name: item
    for item in (
        Check("ports", "Port scan", "Find out which TCP ports answer.", 1, check_ports, needs_open_port=False),
        Check("banner", "Service identification", "Read banners and name the services.", 2, check_banner),
        Check("tls", "TLS certificates", "Expiry, trust and protocol version.", 3, check_tls),
        Check("http", "HTTP configuration", "Security headers, cookies, redirects, listing.", 3, check_http),
        Check("plaintext", "Cleartext services", "FTP, Telnet, rlogin and friends.", 3, check_plaintext),
        Check("dns-zone-transfer", "DNS zone transfer", "Ask the name server for the whole zone.",
              3, check_dns_zone_transfer, intrusive=True, needs_open_port=False),
    )
}

ORDER: Tuple[str, ...] = tuple(sorted(CHECKS, key=lambda name: (CHECKS[name].stage, name)))


def check_titles() -> List[Tuple[str, str, str, bool]]:
    """(name, title, description, intrusive) for --tools."""
    return [(name, CHECKS[name].title, CHECKS[name].description, CHECKS[name].intrusive) for name in ORDER]
