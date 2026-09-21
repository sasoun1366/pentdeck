"""Checks, the engine and the reports — against servers started by this file.

Nothing here leaves the machine: the "client network" is a few local sockets.
"""

import json
import pathlib
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pentdeck import checks, engine, report                     # noqa: E402
from pentdeck.findings import Finding, ScanResult, Severity     # noqa: E402
from pentdeck.license import License, issue_token               # noqa: E402
from pentdeck.scope import DEFAULT_PORTS, AuditLog, Authorization, Scope, ScopeError  # noqa: E402

CERTS = ROOT / "tests" / "certs"
SECRET = "engine-test-secret-long-enough"


# ---------------------------------------------------------------------------
# fixtures: local services that behave like the ones pentdeck audits
# ---------------------------------------------------------------------------
class BannerServer:
    """A TCP service that greets the client, like SSH or FTP does."""

    def __init__(self, greeting: bytes = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu\r\n"):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.3)
        self.port = self.sock.getsockname()[1]
        self.greeting = greeting
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.sendall(self.greeting)
                conn.close()
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.running = False
        self.thread.join(timeout=2)
        self.sock.close()
        return False


class TLSServer:
    def __init__(self, cert: pathlib.Path, key: pathlib.Path):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(cert), str(key))
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.3)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with self.context.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(2)
                    try:
                        tls.recv(1)
                    except Exception:                    # noqa: BLE001
                        pass
            except Exception:                            # noqa: BLE001 - the client may give up
                try:
                    conn.close()
                except Exception:                        # noqa: BLE001
                    pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.running = False
        self.thread.join(timeout=2)
        self.sock.close()
        return False


class WebServer:
    """An HTTP server with every mistake the http check knows about."""

    def __init__(self, handler_body: str = "<html><body>hi</body></html>",
                 headers: dict = None, status: int = 200, listing: bool = False):
        outer = self
        self.headers = headers if headers is not None else {
            "Server": "nginx/1.18.0",
            "Set-Cookie": "session=abc123; Path=/",
            "Content-Type": "text/html",
        }
        self.body = "<html><head><title>Index of /</title></head><body></body></html>" if listing else handler_body
        self.status = status

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):                            # noqa: N802
                payload = outer.body.encode()
                self.send_response(outer.status)
                for key, value in outer.headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        return False


def context_for(port=None, open_ports=None, banner=None, http_ports=(), tls_ports=()):
    """A CheckContext wired for one local service, without a port scan."""
    ctx = checks.CheckContext(
        host="127.0.0.1",
        ports=[port] if port else [],
        timeout=4.0,
        http_ports=list(http_ports),
        tls_ports=list(tls_ports),
    )
    if open_ports is not None:
        ctx.open_ports = list(open_ports)
    elif port:
        ctx.open_ports = [port]
    if banner is not None and port:
        ctx.banners[port] = banner
    return ctx


# ---------------------------------------------------------------------------
# the checks themselves
# ---------------------------------------------------------------------------
def test_port_scan_finds_the_open_one():
    with BannerServer() as server:
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        closed_port = closed.getsockname()[1]
        closed.close()
        ctx = checks.CheckContext("127.0.0.1", [server.port, closed_port], timeout=2.0)
        result = checks.check_ports(ctx)
        assert ctx.open_ports == [server.port]
        assert result and result[0].severity is Severity.INFO
        assert str(server.port) in result[0].detail


def test_banner_check_reads_the_greeting_and_flags_the_version():
    with BannerServer(b"220 ProFTPD 1.3.5 Server ready\r\n") as server:
        ctx = context_for(port=server.port)
        findings = checks.check_banner(ctx)
        assert ctx.banners[server.port].startswith("220 ProFTPD")
        assert any(item.severity is Severity.LOW and "version" in item.title.lower()
                   for item in findings)


def test_a_connection_the_server_aborts_is_a_cert_error_not_a_crash(monkeypatch):
    """The Windows-only crash that a Linux CI run never sees.

    A service that is not TLS closes the connection in the middle of the handshake. Linux
    reports a reset or a clean EOF; Windows raises ConnectionAbortedError (WinError 10053).
    Both have to leave `fetch` as a CertError, because the callers treat CertError as
    "this port does not speak TLS" — an OSError escaping here is one port killing a scan.
    """
    import ssl

    from pentdeck import certs

    def aborted(*args, **kwargs):
        raise ConnectionAbortedError(
            10053, "An established connection was aborted by the software in your host machine"
        )

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", aborted)
    with pytest.raises(certs.CertError) as caught:
        certs.fetch("127.0.0.1", 80, timeout=0.5)
    assert "no TLS handshake could be completed" in str(caught.value)


def test_banner_check_is_silent_on_a_service_that_says_nothing():
    with BannerServer(b"") as server:
        ctx = context_for(port=server.port)
        assert checks.check_banner(ctx) in ([], [])
        assert ctx.banners.get(server.port, "") == ""


def test_tls_check_flags_an_untrusted_certificate():
    with TLSServer(CERTS / "server.pem", CERTS / "server-key.pem") as server:
        ctx = context_for(port=server.port, tls_ports=[server.port])
        findings = checks.check_tls(ctx)
        untrusted = [item for item in findings if item.severity is Severity.HIGH]
        assert untrusted, [(item.title, item.severity) for item in findings]
        assert "does not verify" in untrusted[0].title
        assert "CN=localhost" in untrusted[0].detail


def test_tls_check_flags_an_expired_certificate_as_critical():
    with TLSServer(CERTS / "expired.pem", CERTS / "expired-key.pem") as server:
        ctx = context_for(port=server.port, tls_ports=[server.port])
        findings = checks.check_tls(ctx)
        expired = [item for item in findings if item.severity is Severity.CRITICAL]
        assert expired
        assert "expired" in expired[0].title
        assert expired[0].remediation


def test_tls_check_reports_a_clean_port_as_info(monkeypatch):
    """A verified, long-lived certificate is still worth a line in the report."""
    class FakeCertificate:
        not_before = not_after = None
        days_left = 200
        subject = "CN=good.test"
        verified = True
        tls_version = "TLSv1.3"
        cipher = "TLS_AES_256_GCM_SHA384"
        weak_protocol = False

    monkeypatch.setattr(checks.certs, "fetch", lambda *a, **k: FakeCertificate())
    findings = checks.check_tls(context_for(port=8443, tls_ports=[8443]))
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "healthy" in findings[0].title


def test_http_check_finds_the_usual_mistakes():
    with WebServer() as server:
        ctx = context_for(port=server.port, http_ports=[server.port])
        findings = checks.check_http(ctx)
        titles = {item.title for item in findings}
        assert "Plain HTTP is served without redirecting to HTTPS" in titles
        assert "Clickjacking protection is missing" in titles
        assert "Server header discloses its version" in titles
        assert any("cookie" in title.lower() for title in titles)
        cookie = [item for item in findings if "cookie" in item.title.lower()][0]
        assert cookie.severity is Severity.MEDIUM
        assert "no Secure flag" in cookie.title and "no HttpOnly flag" in cookie.title
        assert all(item.remediation for item in findings if item.severity.rank >= Severity.MEDIUM.rank)


def test_http_check_is_quiet_on_a_well_configured_site():
    headers = {
        "Server": "nginx",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Set-Cookie": "session=abc; Secure; HttpOnly",
        "Location": "https://127.0.0.1/",        # the redirect that makes plain HTTP acceptable
        "Content-Type": "text/html",
    }
    with WebServer(headers=headers, status=301) as server:
        ctx = context_for(port=server.port, http_ports=[server.port])
        findings = checks.check_http(ctx)
    assert [item for item in findings if item.severity.rank >= Severity.MEDIUM.rank] == []
    assert any(item.severity is Severity.INFO for item in findings)


def test_http_check_flags_a_directory_listing():
    with WebServer(listing=True) as server:
        ctx = context_for(port=server.port, http_ports=[server.port])
        findings = checks.check_http(ctx)
    assert any("Directory listing" in item.title for item in findings)


def test_http_check_flags_a_redirect_that_goes_nowhere():
    with WebServer(headers={"Location": "http://example.test/", "Content-Type": "text/html"},
                   status=302) as server:
        ctx = context_for(port=server.port, http_ports=[server.port])
        findings = checks.check_http(ctx)
    assert any("without redirecting to HTTPS" in item.title for item in findings)


def test_plaintext_check_targets_the_classic_services():
    ctx = context_for(open_ports=[21, 23, 3306, 3389])
    ctx.banners[21] = "220 ProFTPD 1.3.5 ready"
    findings = checks.check_plaintext(ctx)
    by_port = {item.port: item for item in findings}
    assert by_port[21].severity is Severity.HIGH and "FTP" in by_port[21].title
    assert by_port[23].severity is Severity.HIGH
    assert by_port[3389].severity is Severity.LOW
    assert 3306 not in by_port                                   # MySQL is not a cleartext-service finding
    assert all(item.remediation for item in findings)


def _dns_context(host: str = "ns.example.test") -> checks.CheckContext:
    ctx = checks.CheckContext(host=host, ports=[53], timeout=3.0)
    ctx.open_ports = [53]
    return ctx


def test_zone_transfer_check_ignores_an_address(monkeypatch):
    """AXFR is a question you ask a name, not an IP — an address is skipped."""
    monkeypatch.setattr(checks, "_connect", lambda *a, **k: _FakeSocket(b""))
    assert checks.check_dns_zone_transfer(context_for(open_ports=[53])) == []


def test_zone_transfer_check_handles_a_refusal(monkeypatch):
    """A name server that refuses (the normal case) produces no finding."""
    refused = b"\x00\x1c" + b"\x12\x34\x81\x85\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x00" * 20
    monkeypatch.setattr(checks, "_connect", lambda *a, **k: _FakeSocket(refused))
    assert checks.check_dns_zone_transfer(_dns_context()) == []


def test_zone_transfer_check_reports_an_open_server(monkeypatch):
    allowed = b"\x00\x2a" + b"\x12\x34\x84\x00\x00\x01\x00\x03\x00\x00\x00\x00" + b"\x00" * 40
    monkeypatch.setattr(checks, "_connect", lambda *a, **k: _FakeSocket(allowed))
    findings = checks.check_dns_zone_transfer(_dns_context())
    assert findings and findings[0].severity is Severity.HIGH
    assert "allows a full zone transfer" in findings[0].title


class _FakeSocket:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, _value):
        pass

    def sendall(self, _data):
        pass

    def recv(self, _size):
        return self.payload


def test_the_check_registry_is_stage_ordered():
    stages = [checks.CHECKS[name].stage for name in checks.ORDER]
    assert stages == sorted(stages)
    assert checks.ORDER[0] == "ports"
    assert checks.CHECKS["dns-zone-transfer"].intrusive is True
    assert checks.CHECKS["ports"].needs_open_port is False


# ---------------------------------------------------------------------------
# planning and gating
# ---------------------------------------------------------------------------
def test_free_licence_runs_only_the_free_checks():
    options = engine.ScanOptions()
    run, skipped = engine.plan_checks(License(tier="free"), options)
    assert [check.name for check in run] == ["ports", "banner"]
    reasons = dict(skipped)
    assert "free" in reasons["tls"]


def test_pro_licence_runs_everything_except_intrusive():
    options = engine.ScanOptions()
    run, skipped = engine.plan_checks(License(tier="pro"), options)
    names = [check.name for check in run]
    assert names == ["ports", "banner", "http", "plaintext", "tls"]   # stage order, then name
    assert "dns-zone-transfer" not in names
    assert "--intrusive" in dict(skipped)["dns-zone-transfer"]


def test_intrusive_checks_need_both_the_flag_and_the_licence():
    with_flag = engine.ScanOptions(intrusive=True)
    run, _ = engine.plan_checks(License(tier="pro"), with_flag)
    assert "dns-zone-transfer" in [check.name for check in run]

    free_with_flag = engine.plan_checks(License(tier="free"), with_flag)
    assert "dns-zone-transfer" not in [check.name for check in free_with_flag[0]]
    assert "paid licence" in dict(free_with_flag[1])["dns-zone-transfer"]


def test_only_and_skip_narrow_the_run():
    options = engine.ScanOptions(only=("ports",))
    run, _ = engine.plan_checks(License(tier="pro"), options)
    assert [check.name for check in run] == ["ports"]

    options = engine.ScanOptions(skip=("ports", "banner"))
    run, _ = engine.plan_checks(License(tier="pro"), options)
    assert "ports" not in [check.name for check in run]


# ---------------------------------------------------------------------------
# the engine
# ---------------------------------------------------------------------------
def test_engine_refuses_an_empty_scope(tmp_path):
    scope = Scope(name="empty", entries=[],
                  authorization=Authorization(operator="Ana", reference="ticket 1"))
    with pytest.raises(ScopeError) as excinfo:
        engine.run_scan(scope, License(tier="pro"), engine.ScanOptions(ports=[80]), tmp_path)
    assert "no targets" in str(excinfo.value)


def test_engine_refuses_without_authorization(tmp_path):
    scope = Scope(name="lab", entries=["127.0.0.1"])
    with pytest.raises(ScopeError) as excinfo:
        engine.run_scan(scope, License(tier="pro"), engine.ScanOptions(ports=[80]), tmp_path)
    assert "authorization" in str(excinfo.value)


def test_engine_applies_the_free_host_limit(tmp_path):
    scope = Scope(
        name="big", entries=[f"10.0.0.{index}" for index in range(1, 21)],
        authorization=Authorization(operator="Ana", reference="ticket 1"),
    )
    with pytest.raises(ScopeError) as excinfo:
        engine.run_scan(scope, License(tier="free"), engine.ScanOptions(ports=[80]), tmp_path)
    assert "16" in str(excinfo.value)


def test_engine_scans_a_local_host_end_to_end(tmp_path):
    with WebServer() as web:
        scope = Scope(name="lab", entries=[f"127.0.0.1:{web.port}"],
                      authorization=Authorization(operator="Ana", reference="ticket 1"))
        options = engine.ScanOptions(ports=[web.port], timeout=3.0,
                                     only=("ports", "banner", "http"))
        result = engine.run_scan(scope, License(tier="pro"), options, tmp_path)

    assert result.hosts_total == 1
    # hosts_up names the scope entry that answered, port included — that is the
    # identity the operator typed, and the report repeats it verbatim.
    assert result.hosts_up == [f"127.0.0.1:{web.port}"]
    assert set(result.checks_run) == {"ports", "banner", "http"}
    assert any(item.check == "http" for item in result.findings)
    assert any(item.severity.rank >= Severity.MEDIUM.rank for item in result.findings)
    assert result.authorization.startswith("Ana")
    assert result.exit_code(Severity.MEDIUM) == 1
    assert result.exit_code(Severity.CRITICAL) == 0


def test_engine_records_what_it_did_in_the_audit_log(tmp_path):
    with WebServer() as web:
        scope = Scope(name="lab", entries=[f"127.0.0.1:{web.port}"],
                      authorization=Authorization(operator="Ana", reference="ticket 1"))
        engine.run_scan(scope, License(tier="pro"),
                        engine.ScanOptions(ports=[web.port], timeout=3.0, only=("ports", "banner")),
                        tmp_path)
    records = AuditLog(tmp_path).tail(50)
    events = [record["event"] for record in records]
    assert "scan-start" in events and "scan-end" in events and "check" in events
    start = [record for record in records if record["event"] == "scan-start"][0]
    assert start["operator"] == "Ana"
    assert start["reference"] == "ticket 1"
    assert start["hosts"] == 1


def test_engine_notes_the_checks_it_did_not_run(tmp_path):
    with WebServer() as web:
        scope = Scope(name="lab", entries=[f"127.0.0.1:{web.port}"],
                      authorization=Authorization(operator="Ana", reference="ticket 1"))
        result = engine.run_scan(scope, License(tier="free"),
                                 engine.ScanOptions(ports=[web.port], timeout=3.0), tmp_path)
    assert result.license_tier == "free"
    reasons = dict(result.checks_skipped)
    assert "tls" in reasons and "free" in reasons["tls"]
    assert "http" not in result.checks_run


def test_engine_counts_a_closed_port_as_down(tmp_path):
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    closed = probe.getsockname()[1]
    probe.close()
    scope = Scope(name="lab", entries=[f"127.0.0.1:{closed}"],
                  authorization=Authorization(operator="Ana", reference="ticket 1"))
    result = engine.run_scan(scope, License(tier="free"),
                             engine.ScanOptions(ports=[closed], timeout=1.5), tmp_path)
    assert result.hosts_up == []
    assert result.findings == []
    assert result.errors == []


def test_a_broken_check_does_not_kill_the_scan(tmp_path, monkeypatch):
    def explode(_context):
        raise RuntimeError("this check is broken")

    # A check that is in the paid list but blows up must be reported, not fatal.
    monkeypatch.setitem(checks.CHECKS, "http", checks.Check("http", "Broken", "always raises", 3, explode))

    with WebServer() as web:
        scope = Scope(name="lab", entries=[f"127.0.0.1:{web.port}"],
                      authorization=Authorization(operator="Ana", reference="ticket 1"))
        result = engine.run_scan(scope, License(tier="pro"),
                                 engine.ScanOptions(ports=[web.port], timeout=3.0,
                                                    only=("ports", "http")), tmp_path)
    assert any("this check is broken" in error for error in result.errors), result.errors
    assert result.hosts_up == [f"127.0.0.1:{web.port}"]   # the scan carried on


# ---------------------------------------------------------------------------
# reports
# ---------------------------------------------------------------------------
def sample_result() -> ScanResult:
    result = ScanResult(scope_name="lab", authorization="Ana — authority: ticket 1",
                        started="2026-09-21T10:00:00+00:00", finished="2026-09-21T10:02:00+00:00",
                        hosts_total=2, hosts_up=["127.0.0.1"], hosts_scanned=["127.0.0.1", "127.0.0.2"],
                        checks_run=["ports", "banner", "http"], license_tier="pro", tool_version="0.1.0")
    result.add([
        Finding(check="http", host="127.0.0.1", port=8080, severity=Severity.MEDIUM,
                title="Plain HTTP is served without redirecting to HTTPS",
                detail="GET / answered 200", remediation="Redirect to HTTPS."),
        Finding(check="tls", host="127.0.0.1", port=8443, severity=Severity.CRITICAL,
                title="TLS certificate expired 3 day(s) ago", detail="notAfter 2026-09-18",
                remediation="Renew it.", evidence="CN=old.test"),
        Finding(check="ports", host="127.0.0.1", port=None, severity=Severity.INFO,
                title="2 open TCP port(s)", detail="8080, 8443"),
    ])
    result.checks_skipped = [("dns-zone-transfer", "intrusive check — add --intrusive")]
    result.errors = ["127.0.0.2: 1 check(s) could not run"]
    return result


def test_text_report_reads_well():
    text = report.format_text(sample_result())
    assert "pentdeck 0.1.0" in text
    assert "authorized  : Ana" in text
    assert "CRITICAL" in text and "MEDIUM" in text and "INFO" in text
    assert text.index("CRITICAL") < text.index("MEDIUM")
    assert "fix:" in text
    assert "checks not run:" in text and "dns-zone-transfer" in text
    assert "errors:" in text


def test_text_report_can_hide_low_severity():
    text = report.format_text(sample_result(), minimum=Severity.HIGH)
    assert "expired" in text
    assert "Plain HTTP" not in text


def test_json_report_is_machine_readable():
    payload = json.loads(report.format_json(sample_result()))
    assert payload["scope"] == "lab"
    assert payload["counts"]["critical"] == 1
    assert payload["counts"]["total"] == 3
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["target"] == "127.0.0.1:8443"
    assert payload["checks_skipped"][0][0] == "dns-zone-transfer"
    assert payload["generator"] == "pentdeck"


def test_markdown_report_is_a_client_document():
    text = report.format_markdown(sample_result())
    assert "# pentdeck" in text
    assert "| severity | count |" in text
    assert "### CRITICAL —" in text
    assert "**Remediation:**" in text
    assert "## Checks not run" in text


def test_html_report_is_self_contained():
    html = report.format_html(sample_result())
    assert "<!doctype html>" in html
    assert "CRITICAL" in html and "Renew it." in html
    assert "<script" not in html.lower()
    assert "@import" not in html
    assert "<link" not in html.lower()                       # no external stylesheets or fonts
    assert "<img" not in html.lower()
    assert "http://" not in html.replace("https://github.com/sasoun1366/pentdeck", "")
    assert "not exploited" in html                           # the report says what it did not do


def test_every_format_is_available_by_name():
    result = sample_result()
    for name, function in report.FORMATS.items():
        assert function(result), name
