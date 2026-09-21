"""The window: navigation, the two lines of state that matter, and the scan lifecycle."""

from __future__ import annotations

import logging
import pathlib
from typing import Dict, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QButtonGroup, QHBoxLayout, QLabel, QMainWindow, QMessageBox,
                             QPushButton, QStackedWidget, QStatusBar, QVBoxLayout, QWidget)

from .. import __version__
from ..engine import ScanOptions
from ..findings import ScanResult
from ..license import TIERS, current_license
from ..scope import Scope, ScopeError, require_authorization
from .theme import GOOD, SEVERITY_COLOUR, TEXT_DIM, WARN
from .widgets import pill, set_pill
from .views import (PAGES, DashboardView, LicenseView, OrdersView, TargetsView, ToolsView,
                    load_scope)
from .scan_view import FindingsView, ReportsView, ScanView
from .safety import safe_slot
from .workers import ScanWorker

log = logging.getLogger("pentdeck.desktop")


class MainWindow(QMainWindow):
    """One window, seven pages, and a scan that runs without freezing any of them."""

    def __init__(self, home: pathlib.Path, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._home = pathlib.Path(home)
        self.result: Optional[ScanResult] = None
        self._worker: Optional[ScanWorker] = None
        self._pending = 0
        self._done = 0

        self.setWindowTitle(f"pentdeck {__version__} — authorised network assessment")
        self.resize(1280, 820)
        self.setMinimumSize(1080, 680)

        root = QWidget()
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._sidebar())

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        right_layout.addWidget(self._header())

        self.stack = QStackedWidget()
        self.dashboard = DashboardView(self._home)
        self.targets = TargetsView(self._home)
        self.scan = ScanView(self._home)
        self.findings = FindingsView()
        self.reports = ReportsView(self._home)
        self.orders = OrdersView(self._home)
        self.tools = ToolsView(self._home)
        self.license = LicenseView(self._home)
        for widget in (self.dashboard, self.targets, self.scan, self.findings,
                       self.reports, self.orders, self.tools, self.license):
            self.stack.addWidget(widget)
        right_layout.addWidget(self.stack, 1)
        layout.addWidget(right, 1)
        self.setCentralWidget(root)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage(
            f"state directory: {self._home} · the desktop app uses the same scope, licence "
            f"and audit log as the command line"
        )

        self._wire()
        self.refresh_all()
        self._show("dashboard")

    # ── chrome ───────────────────────────────────────────────────────────────
    def _sidebar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("Sidebar")
        bar.setFixedWidth(214)
        layout = QVBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 12)
        layout.setSpacing(2)

        brand = QLabel("pentdeck")
        brand.setObjectName("Brand")
        tag = QLabel("authorised assessment workbench")
        tag.setObjectName("BrandTag")
        layout.addWidget(brand)
        layout.addWidget(tag)

        self._nav_buttons: Dict[str, QPushButton] = {}
        group = QButtonGroup(self)
        group.setExclusive(True)
        for key, label in PAGES:
            button = QPushButton(f"  {label}")
            button.setObjectName("Nav")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            group.addButton(button)
            layout.addWidget(button)
            self._nav_buttons[key] = button
            button.clicked.connect(lambda _=False, page=key: self._show(page))
        layout.addStretch(1)

        self.sidebar_scope = QLabel("")
        self.sidebar_scope.setObjectName("Hint")
        self.sidebar_scope.setWordWrap(True)
        self.sidebar_scope.setContentsMargins(16, 0, 16, 0)
        layout.addWidget(self.sidebar_scope)

        version = QLabel(f"version {__version__} · MIT")
        version.setObjectName("Hint")
        version.setContentsMargins(16, 6, 16, 0)
        layout.addWidget(version)
        return bar

    def _header(self) -> QWidget:
        bar = QWidget()
        bar.setStyleSheet("border-bottom: 1px solid #263041;")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(20, 12, 20, 12)
        layout.setSpacing(8)
        self.scope_pill = pill("scope: —")
        self.auth_pill = pill("authorization not recorded", SEVERITY_COLOUR["high"])
        self.licence_pill = pill("free")
        layout.addWidget(self.scope_pill)
        layout.addWidget(self.auth_pill)
        layout.addWidget(self.licence_pill)
        layout.addStretch(1)

        self.run_button = QPushButton("Run a scan")
        self.run_button.setObjectName("Primary")
        self.run_button.clicked.connect(self._run_from_header)
        layout.addWidget(self.run_button)
        return bar

    def _wire(self) -> None:
        self.dashboard.navigate.connect(self._show)
        self.targets.changed.connect(self.refresh_all)
        self.license.changed.connect(self.refresh_all)
        self.orders.changed.connect(self.refresh_all)
        self.scan.start_requested.connect(self.start_scan)
        self.scan.stop_requested.connect(self.stop_scan)
        self.scan.show_findings.connect(lambda: self._show("findings"))
        self.scan.show_reports.connect(lambda: self._show("reports"))

    # ── navigation ───────────────────────────────────────────────────────────
    def _show(self, page: str) -> None:
        index = [key for key, _ in PAGES].index(page) if page in dict(PAGES) else 0
        self.stack.setCurrentIndex(index)
        if page in self._nav_buttons:
            self._nav_buttons[page].setChecked(True)
        widget = self.stack.currentWidget()
        refresh = getattr(widget, "refresh", None)
        if callable(refresh):
            refresh()

    @safe_slot
    def refresh_all(self) -> None:
        scope = load_scope(self._home)
        license_ = current_license(self._home)
        self.scan.apply_license(license_)
        self.reports.apply_license(license_)
        if self.result is not None:
            self.findings.set_result(self.result)
            self.reports.set_result(self.result)
            self.dashboard.set_result(self.result)

        set_pill(self.scope_pill, f"scope: {scope.name}")
        if scope.authorization:
            set_pill(self.auth_pill, "authorised: " + scope.authorization.operator, GOOD)
            self.auth_pill.setToolTip(scope.authorization.summary())
        else:
            set_pill(self.auth_pill, "authorization not recorded", SEVERITY_COLOUR["high"])
            self.auth_pill.setToolTip("A scan will refuse to run until this is filled in on the Targets page.")
        label = TIERS[license_.tier]["label"]
        if license_.is_paid and license_.days_left is not None:
            label += f" · {license_.days_left}d"
        set_pill(self.licence_pill, label, GOOD if license_.is_paid else TEXT_DIM)
        self.licence_pill.setToolTip(license_.summary())

        try:
            hosts = scope.hosts()
        except ScopeError:
            hosts = []
        self.sidebar_scope.setText(
            f"{len(hosts)} host(s) in scope\nin {len(scope.entries)} entr(y/ies)"
            if hosts else "no targets declared yet"
        )
        self.dashboard.refresh()
        self.tools.refresh()
        self.license.refresh()

    # ── the scan ─────────────────────────────────────────────────────────────
    def _run_from_header(self) -> None:
        self._show("scan")
        self.scan.start_button.click()

    @safe_slot
    def start_scan(self, options: ScanOptions, intrusive: bool) -> None:
        """Pre-flight here so the refusal is explained in the window, not in a log."""
        scope = load_scope(self._home)
        license_ = current_license(self._home)
        self.scan.clear_notice()

        try:
            hosts = scope.hosts()
        except ScopeError as exc:
            self.scan.show_notice(f"This scope cannot be expanded: {exc}", 
                                  SEVERITY_COLOUR["critical"])
            return
        if not hosts:
            self.scan.show_notice(
                "There is nothing to scan. Add at least one target on the Targets page "
                "(`scope init` on the command line does the same thing).", WARN,
            )
            return
        try:
            authorization = require_authorization(scope, options.operator or None,
                                                  options.reference or None)
        except ScopeError as exc:
            self.scan.show_notice(
                f"Refused: {exc}. The authorization form is on the Targets page — it is "
                f"deliberately not a checkbox.", SEVERITY_COLOUR["critical"],
            )
            return
        limit = license_.host_limit()
        if limit and len(hosts) > limit:
            self.scan.show_notice(
                f"Refused: {len(hosts)} hosts in scope and the {license_.tier} licence allows "
                f"{limit}. Narrow the scope, or open the Licence page.", WARN,
            )
            return

        options.operator = authorization.operator
        options.reference = authorization.reference
        self.scan.set_running(True)
        self.scan.set_state("scanning…")
        self.scan.log.clear()
        self.scan.progress.setRange(0, max(1, len(hosts)))
        self.scan.progress.setValue(0)
        self._done = 0
        self._pending = len(hosts)
        self.run_button.setEnabled(False)

        self._worker = ScanWorker(scope, license_, options, self._home, parent=self)
        self._worker.progress.connect(self._on_progress)
        self._worker.done.connect(self._on_done)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()
        self.status.showMessage(
            f"scanning {len(hosts)} host(s) in {scope.name!r} · {len(options.ports)} port(s) each"
        )

    def stop_scan(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self.scan.set_state("winding up…")
            self.scan.log_line("stop requested — finishing the host in flight, then reporting")

    @safe_slot
    def _on_progress(self, event: str, fields: dict) -> None:
        if event == "start":
            checks = list(fields.get("checks", []))
            self.scan.set_plan(int(fields.get("hosts", 0)), checks, int(fields.get("ports", 0)))
            for name in fields.get("skipped", []) or []:
                self.scan.log_line(f"skipped: {name}")
        elif event == "host":
            host = str(fields.get("host", ""))
            self._done += 1
            self.scan.set_progress(self._done, self._pending)
            if fields.get("error"):
                self.scan.log_line(f"!  {host} — {fields['error']}")
            elif fields.get("up"):
                self.scan.log_line(
                    f"✓  {host} — {fields.get('ports', 0)} open port(s), "
                    f"{fields.get('findings', 0)} finding(s)"
                )
            else:
                self.scan.log_line(f"·  {host} — nothing answered")
        elif event == "stopped":
            self.scan.log_line(f"stopped after {fields.get('scanned', 0)} host(s)")
        elif event == "end":
            self.scan.log_line("")
            self.scan.log_line(
                f"finished in {fields.get('seconds')} s — {fields.get('findings')} finding(s), "
                f"worst {fields.get('worst')}"
            )

    @safe_slot
    def _on_done(self, result: ScanResult) -> None:
        self.result = result
        self.scan.set_running(False)
        self.run_button.setEnabled(True)
        self.scan.finish(result)
        self.scan.set_state("done" if not result.interrupted else "stopped early")
        self.findings.set_result(result)
        self.reports.set_result(result)
        self.dashboard.set_result(result)
        self.refresh_all()

        counts = result.counts()
        high = counts["critical"] + counts["high"]
        message = (f"scan finished — {len(result.findings)} finding(s), "
                   f"{len(result.hosts_up)} host(s) answered"
                   + (f", {high} at high or above" if high else ""))
        self.status.showMessage(message, 20000)
        self._worker = None
        if result.findings:
            self._show("findings")

    @safe_slot
    def _on_failed(self, message: str) -> None:
        self.scan.set_running(False)
        self.run_button.setEnabled(True)
        self.scan.set_state("failed")
        self.scan.failed(message)
        self.status.showMessage("the scan failed — see the log on the Scan page", 15000)
        self._worker = None

    # ── window behaviour ─────────────────────────────────────────────────────
    def closeEvent(self, event) -> None:                      # noqa: N802 - Qt naming
        if self._worker is not None and self._worker.isRunning():
            answer = QMessageBox.question(
                self, "A scan is running",
                "A scan is still running. Stop it and quit?\n\nThe report for a stopped "
                "scan is marked as partial.",
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self._worker.stop()
            self._worker.wait(5000)
        event.accept()
