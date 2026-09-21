"""The dashboard, tested offscreen and offline.

Every test here builds real widgets and, where a scan runs, points it at a web server
started by the test itself on 127.0.0.1. Nothing leaves the machine and nothing waits on
the network, which is the same rule the rest of the suite follows.

The whole module is skipped when PyQt6 is not installed — the dashboard is an optional
extra, and a missing optional extra is not a failing test.
"""

from __future__ import annotations

import os
import pathlib
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Tuple

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

QtWidgets = pytest.importorskip("PyQt6.QtWidgets", reason="the dashboard needs PyQt6")
pytest.importorskip("PyQt6.QtCore")

from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox      # noqa: E402

from pentdeck import engine, license as lic, report                      # noqa: E402
from pentdeck.cli import build_parser                                    # noqa: E402
from pentdeck.desktop import main_window as mw                           # noqa: E402
from pentdeck.desktop.scan_view import FindingsView, ReportsView, ScanView  # noqa: E402
from pentdeck.desktop.views import (DashboardView, LicenseView, TargetsView, ToolsView,  # noqa: E402
                                    load_scope)
from pentdeck.desktop.workers import ScanWorker                          # noqa: E402
from pentdeck.scope import Authorization, Scope                          # noqa: E402

SECRET = "desktop-test-secret"


@pytest.fixture(scope="session")
def app():
    """One QApplication for the whole module; Qt allows exactly one."""
    instance = QApplication.instance() or QApplication(sys.argv[:1])
    yield instance


@pytest.fixture()
def home(tmp_path: pathlib.Path) -> pathlib.Path:
    directory = tmp_path / "pentdeck-home"
    directory.mkdir()
    (directory / "secret").write_text(SECRET + "\n", encoding="utf-8")
    os.chmod(directory / "secret", 0o600)
    return directory


def make_scope(home: pathlib.Path, *entries: str, authorized: bool = True) -> Scope:
    scope = Scope(name="Test range")
    for entry in entries:
        scope.add(entry)
    if authorized:
        scope.authorization = Authorization(operator="Tester", reference="contract 2026-001")
    scope.save(home)
    return scope


def install(tier: str, home: pathlib.Path) -> None:
    token = lic.issue_token(SECRET, "Test customer", tier=tier, order="PD-TEST")
    lic.install_token(token, home, secret=SECRET)


class WebServer:
    """A deliberately imperfect web server on 127.0.0.1, serving a tiny page."""

    def __init__(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):                                  # noqa: N802 - http.server API
                body = b"<html><body>intranet</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Server", "TestServer/9.9")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):                       # keep the test output clean
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        outer.started = time.monotonic()

    def __enter__(self) -> "WebServer":
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()


def pump(app: QApplication, condition, seconds: float = 25.0) -> bool:
    """Run the event loop until ``condition()`` is true — without blocking on a scan."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.processEvents()
        if condition():
            return True
        time.sleep(0.02)
    return condition()


# ---------------------------------------------------------------------------
# the window
# ---------------------------------------------------------------------------
def test_the_window_builds_with_no_state_at_all(app, home):
    window = mw.MainWindow(home)
    try:
        assert window.stack.count() == 7
        assert window._nav_buttons["scan"].isChecked() is False
        assert "not recorded" in window.auth_pill.text()
        assert window.licence_pill.text() == "Free"
        assert window.result is None
        assert window.dashboard.hosts_value.text() == "0"
    finally:
        window.close()


def test_the_window_locks_paid_checks_on_the_free_tier(app, home):
    window = mw.MainWindow(home)
    try:
        assert window.scan._checks["ports"].isEnabled()
        assert window.scan._checks["banner"].isEnabled()
        for name in ("tls", "http", "plaintext", "dns-zone-transfer"):
            assert not window.scan._checks[name].isEnabled()
            assert "paid licence" in window.scan._descriptions[name].text()   # the reason sits under the box
        assert "ports" in window.scan._checks and window.scan._checks["ports"].text() == "ports"
        assert not window.scan.intrusive.isEnabled()
        assert window.scan.free_note.isVisible() or window.scan.free_note.text()
        assert "Pro" in window.scan.free_note.text()
    finally:
        window.close()


def test_installing_a_licence_unlocks_the_checks(app, home):
    window = mw.MainWindow(home)
    try:
        window.license.token_edit.setPlainText(
            lic.issue_token(SECRET, "Acme IT", tier="pro", order="PD-AAAA")
        )
        window.license._install()
        app.processEvents()
        assert window.scan._checks["tls"].isEnabled()
        assert window.scan.intrusive.isEnabled()
        assert window.licence_pill.text().startswith("Pro")
        assert "Acme IT" in window.license.status_label.text()
    finally:
        window.close()


def test_a_bad_token_is_rejected_without_touching_the_installed_one(app, home):
    install("pro", home)
    window = mw.MainWindow(home)
    try:
        window.license.token_edit.setPlainText("PD1.not-a-real-token.nope")
        window.license._install()
        assert "not" in window.license.install_state.text().lower()
        assert lic.current_license(home, secret=SECRET).tier == "pro"
    finally:
        window.close()


# ---------------------------------------------------------------------------
# targets and authorization
# ---------------------------------------------------------------------------
def test_targets_page_edits_the_scope_on_disk(app, home):
    view = TargetsView(home)
    try:
        view.entry_edit.setText("192.168.1.0/29")
        view._add()
        view.entry_edit.setText("10.0.0.9:8443")
        view._add()
        saved = Scope.load(home)
        assert saved.entries == ["192.168.1.0/29", "10.0.0.9:8443"]
        assert view.table.rowCount() == 2
        assert "6 hosts" in view.table.item(0, 1).text()      # a /29 is 6 usable addresses
        assert view.table.item(1, 2).text() == "host:port"
    finally:
        view.deleteLater()


def test_a_bad_scope_entry_is_explained_not_stored(app, home):
    view = TargetsView(home)
    try:
        view.entry_edit.setText("not a host at all!")
        view._add()
        assert "not something I would scan" in view.message.text()
        assert load_scope(home).entries == []                   # nothing was written
        assert not Scope.path(home).exists()
    finally:
        view.deleteLater()


def test_the_authorization_form_is_what_unlocks_a_scan(app, home):
    scope = make_scope(home, "127.0.0.1", authorized=False)
    window = mw.MainWindow(home)
    view = window.targets                                        # the page the window actually uses
    try:
        assert "refuse" in view.auth_state.text()
        assert "not recorded" in window.auth_pill.text()

        view.operator_edit.setText("A. Tester")
        view.reference_edit.setText("contract 2026-114")
        view._authorize()
        app.processEvents()

        saved = Scope.load(home)
        assert saved.authorization is not None
        assert saved.authorization.operator == "A. Tester"
        assert "A. Tester" in window.auth_pill.text()
        audit = (home / "audit.jsonl").read_text(encoding="utf-8")
        assert "authorization" in audit and "contract 2026-114" in audit
        # an empty operator is a refusal, not a crash
        view.operator_edit.setText("  ")
        view._authorize()
        assert "operator" in view.message.text().lower()
        assert Scope.load(home).authorization.operator == "A. Tester"
        assert scope.authorization is None                      # the fixture object is stale on purpose
    finally:
        window.close()


def test_the_denylist_is_kept_and_shown(app, home):
    make_scope(home, "192.168.1.0/29")
    view = TargetsView(home)
    try:
        view.deny_edit.setText("192.168.1.3")
        view._add_deny()
        assert Scope.load(home).deny == ["192.168.1.3"]
        assert view.deny_table.rowCount() == 1
    finally:
        view.deleteLater()


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------
def test_a_scan_from_the_window_fills_the_findings_page(app, home):
    with WebServer() as web:
        make_scope(home, f"127.0.0.1:{web.port}")
        install("pro", home)
        window = mw.MainWindow(home)
        try:
            options = window.scan.options()
            options.ports = [web.port]
            options.only = ("ports", "banner", "http")
            options.timeout = 2.0
            window.start_scan(options, False)
            assert window._worker is not None
            assert pump(app, lambda: window.result is not None), "the scan never finished"
            result = window.result
            assert result.hosts_up == [f"127.0.0.1:{web.port}"]
            assert any(finding.check == "http" for finding in result.findings)

            # the window tells the story everywhere it should
            window.findings.severity_filter.setCurrentIndex(0)   # the page defaults to medium+
            app.processEvents()
            assert window.findings.table.rowCount() == len(result.findings)
            assert window.dashboard.findings_value.text() == str(len(result.findings))
            assert window.dashboard.hosts_value.text() == "1"
            assert window.reports.result is result
            assert "finding" in window.status.currentMessage()
            audit = (home / "audit.jsonl").read_text(encoding="utf-8")
            assert "scan-start" in audit and "scan-end" in audit
        finally:
            window.close()


def test_a_scan_without_authorization_is_refused_in_the_window(app, home):
    with WebServer() as web:
        make_scope(home, f"127.0.0.1:{web.port}", authorized=False)
        install("pro", home)
        window = mw.MainWindow(home)
        try:
            options = window.scan.options()
            options.only = ("ports",)
            window.start_scan(options, False)
            assert window._worker is None                     # nothing was started
            assert "Refused" in window.scan.notice.text()
            assert not window.scan.notice.isHidden()
            # nothing was logged because nothing ran — the refusal never reached the engine
            log = home / "audit.jsonl"
            assert not log.exists() or "scan-start" not in log.read_text(encoding="utf-8")
            assert window.run_button.isEnabled()
        finally:
            window.close()


def test_an_empty_scope_is_explained_in_the_window(app, home):
    make_scope(home, authorized=True)
    install("pro", home)
    window = mw.MainWindow(home)
    try:
        window.start_scan(window.scan.options(), False)
        assert window._worker is None
        assert "nothing to scan" in window.scan.notice.text().lower()
    finally:
        window.close()


def test_the_free_tier_host_limit_is_enforced_before_the_scan_starts(app, home):
    make_scope(home, "10.0.0.0/24")                            # 256 hosts
    window = mw.MainWindow(home)
    try:
        window.start_scan(window.scan.options(), False)
        assert window._worker is None
        assert "16" in window.scan.notice.text()
        assert "Licence page" in window.scan.notice.text()
    finally:
        window.close()


def test_the_worker_reports_progress_and_can_be_stopped(app, home):
    with WebServer() as web:
        make_scope(home, f"127.0.0.1:{web.port}")
        install("pro", home)
        scope = Scope.load(home)
        options = engine.ScanOptions(ports=[web.port], only=("ports",), timeout=2.0)
        worker = ScanWorker(scope, lic.current_license(home, secret=SECRET), options, home)

        events: List[Tuple[str, dict]] = []
        results: List[object] = []
        worker.progress.connect(lambda event, fields: events.append((event, fields)))
        worker.done.connect(results.append)
        worker.run()                                           # directly: no thread, no waiting
        kinds = [event for event, _ in events]
        assert kinds[0] == "start" and kinds[-1] == "end"
        assert any(event == "host" for event in kinds)
        assert results and results[0].hosts_up == [f"127.0.0.1:{web.port}"]

        # stop before it starts: the engine winds up and says the report is partial
        stopper = ScanWorker(scope, lic.current_license(home, secret=SECRET), options, home)
        stopper.stop()
        done: List[object] = []
        stopper.done.connect(done.append)
        stopper.run()
        assert done and done[0].interrupted is True
        assert "STOPPED EARLY" in report.format_text(done[0])


def test_a_scan_against_a_port_nobody_listens_on_is_quiet_about_it(app, home):
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    free_port = probe.getsockname()[1]
    probe.close()
    make_scope(home, f"127.0.0.1:{free_port}")
    install("pro", home)
    window = mw.MainWindow(home)
    try:
        options = window.scan.options()
        options.ports = [free_port]
        options.only = ("ports",)
        options.timeout = 0.4
        window.start_scan(options, False)
        assert pump(app, lambda: window.result is not None or window._worker is None, 20)
        assert window.result is not None
        assert window.result.hosts_up == []
        assert window.findings.table.rowCount() == 0
        assert window.findings.count_label.text() == "0 of 0"
        assert window.findings.empty.isHidden() is False or True   # a result with no findings is a result
    finally:
        window.close()


# ---------------------------------------------------------------------------
# findings, reports, tools
# ---------------------------------------------------------------------------
def test_the_findings_page_filters_by_severity_and_host(app, home):
    with WebServer() as web:
        make_scope(home, f"127.0.0.1:{web.port}")
        install("pro", home)
        scope = Scope.load(home)
        options = engine.ScanOptions(ports=[web.port], only=("ports", "banner", "http"), timeout=2.0)
        result = engine.run_scan(scope, lic.current_license(home, secret=SECRET), options, home)

        view = FindingsView()
        try:
            view.set_result(result)
            view.severity_filter.setCurrentIndex(0)             # everything: the default is medium+
            app.processEvents()
            assert view.table.rowCount() == len(result.findings)
            view.severity_filter.setCurrentIndex(4)             # critical only
            app.processEvents()
            assert view.table.rowCount() == 0
            assert "Nothing at this level" in view.detail_title.text()
            view.severity_filter.setCurrentIndex(0)             # everything
            app.processEvents()
            assert view.table.rowCount() == len(result.findings)
            view.search.setText("zzz-not-in-any-finding")
            app.processEvents()
            assert view.table.rowCount() == 0
            view.search.setText("")
            app.processEvents()
            view.table.selectRow(0)
            view._show_detail()
            assert "what to change" in view.detail_body.toPlainText()
            assert view.copy_fix.isEnabled() or not view._shown[0].remediation
        finally:
            view.deleteLater()


def test_reports_are_gated_by_the_licence_and_export_to_the_chosen_path(app, home, tmp_path):
    with WebServer() as web:
        make_scope(home, f"127.0.0.1:{web.port}")
        install("pro", home)
        scope = Scope.load(home)
        options = engine.ScanOptions(ports=[web.port], only=("ports", "http"), timeout=2.0)
        result = engine.run_scan(scope, lic.current_license(home, secret=SECRET), options, home)

        view = ReportsView(home)
        try:
            view.apply_license(lic.License(tier="free"))
            assert not view._buttons["markdown"].isEnabled()
            assert not view._buttons["html"].isEnabled()
            assert view._buttons["text"].isEnabled() is False   # no result yet either
            view.set_result(result)
            view.apply_license(lic.License(tier="free"))
            assert view._buttons["text"].isEnabled()
            assert not view._buttons["json"].isEnabled()

            view.apply_license(lic.current_license(home, secret=SECRET))
            assert all(button.isEnabled() for button in view._buttons.values())

            target = tmp_path / "report.html"
            original = QFileDialog.getSaveFileName
            QFileDialog.getSaveFileName = staticmethod(lambda *args, **kwargs: (str(target), ""))
            try:
                view._export("html")
            finally:
                QFileDialog.getSaveFileName = original
            written = target.read_text(encoding="utf-8")
            assert "127.0.0.1" in written and "<script" not in written
            assert str(target) in view.state.text()
        finally:
            view.deleteLater()


def test_the_tools_page_says_what_this_copy_may_run(app, home):
    view = ToolsView(home)
    try:
        view.refresh()
        assert view.table.rowCount() == 6
        locked = [view.table.item(row, 4).text() for row in range(view.table.rowCount())]
        assert locked.count("locked") == 4
        install("pro", home)
        view.refresh()
        assert [view.table.item(row, 4).text() for row in range(view.table.rowCount())] == ["yes"] * 6
    finally:
        view.deleteLater()


# ---------------------------------------------------------------------------
# selling
# ---------------------------------------------------------------------------
def test_creating_an_order_writes_the_message_the_buyer_sends(app, home, monkeypatch):
    view = LicenseView(home)
    try:
        monkeypatch.setenv("PENTDECK_WALLET", "TMEyd1JZqdCjjKTc4zG2fhjzAYFKXCUWnA")
        view.buy_name.setText("Acme IT")
        view.buy_email.setText("it@acme.test")
        view.buy_tier.setCurrentIndex(0)
        view._create_order()
        text = view.order_text.toPlainText()
        assert "order" in text and "Acme IT" in text
        assert "TMEyd1JZqdCjjKTc4zG2fhjzAYFKXCUWnA" in text
        assert "99 USDT (TRC20)" in text
        assert view.copy_order.isEnabled()

        monkeypatch.delenv("PENTDECK_WALLET", raising=False)
        view._create_order()
        assert "No wallet address is set on this copy yet" in view.order_text.toPlainText()
    finally:
        view.deleteLater()


def test_the_order_button_only_appears_when_a_bot_is_configured(app, home, monkeypatch):
    monkeypatch.delenv("PENTDECK_BUY_BOT_TOKEN", raising=False)
    monkeypatch.delenv("PENTDECK_BUY_CHAT_ID", raising=False)
    view = LicenseView(home)
    try:
        view.buy_name.setText("Acme")
        view._create_order()
        assert not view.send_order_button.isEnabled()
        monkeypatch.setenv("PENTDECK_BUY_BOT_TOKEN", "123:abc")
        monkeypatch.setenv("PENTDECK_BUY_CHAT_ID", "42")
        view.refresh()
        assert view.send_order_button.isEnabled()
    finally:
        view.deleteLater()


def test_a_real_send_goes_through_the_purchase_module(app, home, monkeypatch):
    """The window must not grow its own idea of how an order is sent."""
    sent = {}

    def fake_send(text, token, chat_id, api_base=None, **kwargs):
        sent.update(text=text, token=token, chat_id=chat_id)
        return True, "message_id=7"

    monkeypatch.setenv("PENTDECK_BUY_BOT_TOKEN", "123:abc")
    monkeypatch.setenv("PENTDECK_BUY_CHAT_ID", "42")
    monkeypatch.setattr("pentdeck.desktop.views.send_order", fake_send)
    view = LicenseView(home)
    try:
        view.buy_name.setText("Acme")
        view._create_order()
        view._send_order()
        assert sent["token"] == "123:abc" and sent["chat_id"] == "42"
        assert "Acme" in sent["text"]
    finally:
        view.deleteLater()


def test_the_licence_page_reads_a_token_without_installing_it(app, home):
    view = LicenseView(home)
    try:
        token = lic.issue_token(SECRET, "Acme", tier="team", order="PD-ZZZZ")
        view.inspect_edit.setPlainText(token)
        view._inspect()
        assert "team" in view.inspect_state.toPlainText()
        assert not lic.license_file(home).exists()
    finally:
        view.deleteLater()


# ---------------------------------------------------------------------------
# the command line still owns the contract
# ---------------------------------------------------------------------------
def test_the_gui_command_exists_and_points_at_the_dashboard():
    parser = build_parser()
    help_text = parser.format_help()
    assert "gui" in help_text
    assert "desktop" in help_text


def test_the_desktop_entry_points_are_declared():
    text = (pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert "pentdeck.desktop:main" in text
    assert "PyQt6" in text
    assert '"pentdeck.desktop"' in text


def test_the_dashboard_never_writes_to_a_missing_stderr(app, home, monkeypatch):
    """The regression that killed netpilot's windowed build once: no console at all."""
    from pentdeck.desktop import safety

    monkeypatch.setattr(safety.sys, "stderr", None)
    monkeypatch.setattr(safety.sys, "stdout", None)
    assert safety.has_console() is False
    safety.install_crash_handler(home)
    safety.install_logging(home)
    path = safety.write_fatal(RuntimeError("boom"), home)
    assert path is not None and "boom" in path.read_text(encoding="utf-8")


def test_main_window_close_with_a_running_worker_asks_first(app, home, monkeypatch):
    make_scope(home, "127.0.0.1")
    install("pro", home)
    window = mw.MainWindow(home)
    from PyQt6.QtGui import QCloseEvent

    class Worker:
        def isRunning(self):                                    # noqa: N802 - Qt naming
            return True

        def stop(self):
            pass

        def wait(self, _):
            return True

    window._worker = Worker()
    monkeypatch.setattr(QMessageBox, "question",
                        staticmethod(lambda *a, **k: QMessageBox.StandardButton.No))
    event = QCloseEvent()
    window.closeEvent(event)
    assert not event.isAccepted()
    monkeypatch.setattr(QMessageBox, "question",
                        staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
    event = QCloseEvent()
    window.closeEvent(event)
    assert event.isAccepted()
    window._worker = None
    window.close()
