"""Scan, findings and reports — the three screens the work actually happens on."""

from __future__ import annotations

import datetime
import pathlib
from typing import Dict, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog, QGridLayout,
                             QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                             QPlainTextEdit, QPushButton, QScrollArea, QSpinBox, QSplitter,
                             QVBoxLayout, QWidget)

from ..checks import CHECKS, ORDER
from ..engine import ScanOptions, plan_checks
from ..findings import Finding, ScanResult, Severity, severity_from
from ..license import License, REPORT_EXTENSIONS
from ..report import FORMATS
from ..scope import DEFAULT_PORTS, TOP_PORTS
from .theme import SEVERITY_COLOUR, TEXT_DIM, WARN
from .widgets import (banner, button, cell, fill_table, hint, log_box, make_table, page_title,
                      severity_colour, severity_strip)

PORT_PROFILES = [
    ("Top 12 ports — quick reconnaissance", "top"),
    ("Default 41 ports — the usual services", "default"),
    ("1–1024 — the well-known range", "well-known"),
    ("Full 1–65535 — slow, thorough", "full"),
    ("Custom…", "custom"),
]


class ScanView(QWidget):
    """Everything about one run: what will be checked, and what happened while it ran."""

    start_requested = pyqtSignal(object, object)          # ScanOptions, intrusive flag
    stop_requested = pyqtSignal()
    show_findings = pyqtSignal()
    show_reports = pyqtSignal()

    def __init__(self, home: pathlib.Path, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.home = pathlib.Path(home)
        self.result: Optional[ScanResult] = None
        self._checks: Dict[str, QCheckBox] = {}
        self._descriptions: Dict[str, QLabel] = {}
        self._build()

    # ── construction ─────────────────────────────────────────────────────────
    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 16, 20, 16)
        outer.setSpacing(12)
        outer.addWidget(page_title(
            "Scan",
            "The scope, the authorization and the licence decide what runs. Nothing on "
            "this page can widen them.",
        ))

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._options_panel())
        splitter.addWidget(self._run_panel())
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([470, 690])
        outer.addWidget(splitter, 1)

    def _options_panel(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        inner = QWidget()
        column = QVBoxLayout(inner)
        column.setContentsMargins(0, 0, 8, 0)
        column.setSpacing(12)

        # checks
        checks_box = QGroupBox("Checks")
        checks_layout = QVBoxLayout(checks_box)
        checks_layout.setSpacing(4)
        for name in ORDER:
            check = CHECKS[name]
            line = QCheckBox(name)
            line.setChecked(True)
            line.setToolTip(check.description)
            self._checks[name] = line
            checks_layout.addWidget(line)
            # The description on its own line: a QCheckBox cannot wrap, and a clipped
            # sentence is worse than no sentence.
            self._descriptions[name] = hint("     " + check.description)
            checks_layout.addWidget(self._descriptions[name])
        self.free_note = hint("")
        checks_layout.addWidget(self.free_note)
        column.addWidget(checks_box)

        # intrusive
        intrusive_box = QGroupBox("Intrusive")
        intrusive_layout = QVBoxLayout(intrusive_box)
        self.intrusive = QCheckBox("Run intrusive checks")
        self.intrusive.toggled.connect(self.refresh_plan)
        intrusive_layout.addWidget(self.intrusive)
        self.intrusive_note = hint(
            "A zone transfer asks a name server to hand over the whole zone. It is "
            "logged, and on some servers it is the loudest thing a scan can do: it stays "
            "off unless you tick it."
        )
        intrusive_layout.addWidget(self.intrusive_note)
        column.addWidget(intrusive_box)

        # ports and timing
        network_box = QGroupBox("Ports and timing")
        grid = QGridLayout(network_box)
        grid.setSpacing(6)
        self.ports_combo = QComboBox()
        for label, key in PORT_PROFILES:
            self.ports_combo.addItem(label, key)
        self.ports_combo.currentIndexChanged.connect(self._ports_changed)
        grid.addWidget(QLabel("Ports"), 0, 0)
        grid.addWidget(self.ports_combo, 0, 1)
        self.custom_ports = QLineEdit()
        self.custom_ports.setPlaceholderText("e.g. 22,80,443,8000-8100")
        self.custom_ports.setVisible(False)
        self.custom_ports.editingFinished.connect(self.refresh_plan)
        grid.addWidget(self.custom_ports, 1, 0, 1, 2)

        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(0.2, 30.0)
        self.timeout.setSingleStep(0.5)
        self.timeout.setValue(5.0)
        self.timeout.setSuffix(" s")
        grid.addWidget(QLabel("Timeout per port"), 2, 0)
        grid.addWidget(self.timeout, 2, 1)

        self.host_delay = QDoubleSpinBox()
        self.host_delay.setRange(0.0, 30.0)
        self.host_delay.setSingleStep(0.5)
        self.host_delay.setSuffix(" s")
        self.host_delay.setToolTip(
            "A pause between hosts. A slower scan is a scan that does not trip an "
            "intrusion detection system or knock a small router over."
        )
        grid.addWidget(QLabel("Delay between hosts"), 3, 0)
        grid.addWidget(self.host_delay, 3, 1)

        self.host_workers = QSpinBox()
        self.host_workers.setRange(1, 64)
        self.host_workers.setValue(8)
        grid.addWidget(QLabel("Hosts at a time"), 4, 0)
        grid.addWidget(self.host_workers, 4, 1)

        self.probe_unknown = QCheckBox("Ask unknown ports for a web page")
        self.probe_unknown.setChecked(True)
        self.probe_unknown.setToolTip(
            "An admin panel on 8082 is exactly what a scan is for. Untick it if the "
            "engagement says the scan must stay as quiet as possible."
        )
        grid.addWidget(self.probe_unknown, 5, 0, 1, 2)
        column.addWidget(network_box)

        self.plan_label = QLabel("")
        self.plan_label.setWordWrap(True)
        self.plan_label.setObjectName("Hint")
        column.addWidget(self.plan_label)
        column.addStretch(1)

        scroll.setWidget(inner)
        layout.addWidget(scroll, 1)
        return holder

    def _run_panel(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        layout.setContentsMargins(8, 0, 0, 0)
        layout.setSpacing(10)

        self.notice = banner(
            "Fill in the targets and the authorization on the Targets page — a scan "
            "without them is refused, and the refusal is recorded."
        )
        self.notice.setVisible(False)
        layout.addWidget(self.notice)

        controls = QWidget()
        controls_layout = QHBoxLayout(controls)
        controls_layout.setContentsMargins(0, 0, 0, 0)
        self.start_button = button("Start the scan", primary=True)
        self.start_button.clicked.connect(self._start_clicked)
        self.stop_button = button("Stop")
        self.stop_button.clicked.connect(self.stop_requested.emit)
        self.stop_button.setEnabled(False)
        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)
        self.state_label = QLabel("ready")
        self.state_label.setObjectName("Hint")
        controls_layout.addWidget(self.state_label, 1)
        layout.addWidget(controls)

        from PyQt6.QtWidgets import QProgressBar

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.log = log_box("The scan writes here as it goes: every host, every check, "
                           "every error.")
        layout.addWidget(self.log, 1)

        self.summary = QWidget()
        summary_layout = QVBoxLayout(self.summary)
        summary_layout.setContentsMargins(0, 0, 0, 0)
        summary_layout.setSpacing(8)
        self.summary_text = QLabel("")
        self.summary_text.setWordWrap(True)
        summary_layout.addWidget(self.summary_text)
        self.strip_holder = QWidget()
        self.strip_layout = QVBoxLayout(self.strip_holder)
        self.strip_layout.setContentsMargins(0, 0, 0, 0)
        self.strip_layout.addWidget(severity_strip({}))
        summary_layout.addWidget(self.strip_holder)
        actions = QWidget()
        actions_layout = QHBoxLayout(actions)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        self.findings_button = button("Open the findings")
        self.findings_button.clicked.connect(self.show_findings.emit)
        self.findings_button.setEnabled(False)
        self.reports_button = button("Export a report")
        self.reports_button.clicked.connect(self.show_reports.emit)
        self.reports_button.setEnabled(False)
        actions_layout.addWidget(self.findings_button)
        actions_layout.addWidget(self.reports_button)
        actions_layout.addStretch(1)
        summary_layout.addWidget(actions)
        self.summary.setVisible(False)
        layout.addWidget(self.summary)
        return holder

    # ── state ────────────────────────────────────────────────────────────────
    def apply_license(self, license_: License) -> None:
        """Grey out the checks this licence does not include, and say why."""
        self._license = license_
        locked: List[str] = []
        for name, box in self._checks.items():
            allowed = license_.allows_check(name)
            box.setEnabled(allowed)
            if not allowed:
                box.setChecked(False)
                locked.append(name)
            self._descriptions[name].setText(
                "     " + CHECKS[name].description if allowed
                else "     needs a paid licence — this one is part of Pro"
            )
            self._descriptions[name].setStyleSheet("" if allowed else "color: #8b949e;")
        if locked:
            self.free_note.setText(
                f"{len(locked)} check(s) are part of Pro: {', '.join(locked)}. "
                f"The free version still finds every open port and names the service behind it."
            )
            self.free_note.setVisible(True)
        else:
            self.free_note.setVisible(False)

        can_intrude = license_.allows_intrusive()
        self.intrusive.setEnabled(can_intrude)
        if not can_intrude:
            self.intrusive.setChecked(False)
            self.intrusive_note.setText(
                "Intrusive checks are part of Pro. The rest of the scan is unaffected."
            )
        else:
            self.intrusive_note.setText(
                "A zone transfer asks a name server to hand over the whole zone. It is "
                "logged, and on some servers it is the loudest thing a scan can do: it "
                "stays off unless you tick it."
            )
        self.refresh_plan()

    def ports(self) -> List[int]:
        key = self.ports_combo.currentData()
        if key == "top":
            return list(TOP_PORTS)
        if key == "default":
            return list(DEFAULT_PORTS)
        if key == "well-known":
            return list(range(1, 1025))
        if key == "full":
            return list(range(1, 65536))
        try:
            from ..cli import parse_ports

            ports = parse_ports(self.custom_ports.text())
        except Exception:                                    # noqa: BLE001 - bad typing is not a crash
            return list(DEFAULT_PORTS)
        return ports or list(DEFAULT_PORTS)

    def options(self) -> ScanOptions:
        only = tuple(name for name, box in self._checks.items() if box.isChecked())
        return ScanOptions(
            ports=self.ports(),
            intrusive=self.intrusive.isChecked(),
            timeout=float(self.timeout.value()),
            host_workers=int(self.host_workers.value()),
            host_delay=float(self.host_delay.value()),
            only=only,
        )

    def _ports_changed(self) -> None:
        self.custom_ports.setVisible(self.ports_combo.currentData() == "custom")
        self.refresh_plan()

    def refresh_plan(self) -> None:
        """Say out loud what will and will not run, before it runs."""
        license_ = getattr(self, "_license", None)
        if license_ is None:
            return
        options = self.options()
        will_run, skipped = plan_checks(license_, options)
        ports = len(options.ports)
        lines = [f"{len(will_run)} check(s) against {ports} port(s)."]
        for name, reason in skipped:
            lines.append(f"not this time: {name} — {self._plain(reason)}")
        self.plan_label.setText("\n".join(lines))

    @staticmethod
    def _plain(reason: str) -> str:
        """The engine explains itself in command-line terms; the window should not."""
        if "--intrusive" in reason:
            return "tick “Run intrusive checks” to include it"
        if reason == "not requested for this run":
            return "unticked on this page"
        return reason

    def set_running(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        for widget in (self.intrusive, self.ports_combo, self.timeout, self.host_delay,
                       self.host_workers, self.probe_unknown):
            widget.setEnabled(not running)
        license_ = getattr(self, "_license", None)
        if license_ is not None:
            for name, box in self._checks.items():
                box.setEnabled(not running and license_.allows_check(name))

    # ── scanning ─────────────────────────────────────────────────────────────
    def _start_clicked(self) -> None:
        self.log.clear()
        self.summary.setVisible(False)
        self.progress.setValue(0)
        self.start_requested.emit(self.options(), self.intrusive.isChecked())

    def log_line(self, text: str) -> None:
        self.log.appendPlainText(text)

    def show_notice(self, text: str, colour: str = WARN) -> None:
        self.notice.setText(text)
        self.notice.setStyleSheet(
            f"background: transparent; border-left: 3px solid {colour}; padding: 9px 12px;"
        )
        self.notice.setVisible(True)

    def clear_notice(self) -> None:
        self.notice.setVisible(False)

    def set_state(self, text: str) -> None:
        self.state_label.setText(text)

    def set_progress(self, done: int, total: int) -> None:
        if total <= 0:
            self.progress.setRange(0, 0)
            return
        self.progress.setRange(0, total)
        self.progress.setValue(min(done, total))

    def set_plan(self, hosts: int, checks: List[str], ports: int) -> None:
        self.progress.setRange(0, max(1, hosts))
        self.progress.setValue(0)
        self.log_line(f"scope has {hosts} host(s) · {len(checks)} check(s) · {ports} port(s)")
        self.log_line("")

    def finish(self, result: ScanResult) -> None:
        self.result = result
        counts = result.counts()
        self.summary.setVisible(True)
        worst = result.worst
        self.summary_text.setText(
            f"<b>{len(result.findings)} finding(s)</b> across {len(result.hosts_up)} host(s) "
            f"that answered"
            + (f" · worst: <span style='color:{severity_colour(worst.value)}'>"
               f"{worst.value.upper()}</span>" if result.findings else "")
            + (" · <b>stopped early</b>" if result.interrupted else "")
        )
        from .views import fill_strip

        fill_strip(self.strip_layout, counts)
        self.findings_button.setEnabled(bool(result.findings))
        self.reports_button.setEnabled(True)
        self.progress.setValue(self.progress.maximum())

    def failed(self, message: str) -> None:
        self.log_line(f"scan failed: {message}")
        self.show_notice(
            f"The scan stopped: {message}", colour=SEVERITY_COLOUR["critical"]
        )
        self.reports_button.setEnabled(self.result is not None)


class FindingsView(QWidget):
    """The list, and the reasoning behind each line of it."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.result: Optional[ScanResult] = None
        self._shown: List[Finding] = []
        self._build()

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 16, 20, 16)
        outer.setSpacing(10)
        outer.addWidget(page_title("Findings",
                                   "Worst first. Every finding says what was seen, how it "
                                   "was seen, and what to change."))

        bar = QWidget()
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(0, 0, 0, 0)
        self.severity_filter = QComboBox()
        for label, key in (("Everything", "info"), ("Low and above", "low"),
                           ("Medium and above", "medium"), ("High and above", "high"),
                           ("Critical only", "critical")):
            self.severity_filter.addItem(label, key)
        self.severity_filter.setCurrentIndex(2)               # medium and above: the useful default
        self.severity_filter.currentIndexChanged.connect(self._refill)
        bar_layout.addWidget(QLabel("Show"))
        bar_layout.addWidget(self.severity_filter)
        self.host_filter = QComboBox()
        self.host_filter.currentIndexChanged.connect(self._refill)
        bar_layout.addWidget(QLabel("on"))
        bar_layout.addWidget(self.host_filter)
        self.search = QLineEdit()
        self.search.setPlaceholderText("search the title, the detail or the host…")
        self.search.textChanged.connect(self._refill)
        bar_layout.addWidget(self.search, 1)
        self.count_label = QLabel("")
        self.count_label.setObjectName("Hint")
        bar_layout.addWidget(self.count_label)
        outer.addWidget(bar)

        self.empty = hint("No scan has run in this session yet. The Findings page fills in "
                          "as soon as one finishes — and a scan that finds nothing is a "
                          "result worth reporting too.")
        outer.addWidget(self.empty)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = make_table(["Severity", "Target", "Check", "Finding"], stretch_column=3)
        self.table.itemSelectionChanged.connect(self._show_detail)
        self.table.doubleClicked.connect(self._copy_selected)
        splitter.addWidget(self.table)

        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(0, 6, 0, 0)
        detail_layout.setSpacing(6)
        head = QWidget()
        head_layout = QHBoxLayout(head)
        head_layout.setContentsMargins(0, 0, 0, 0)
        self.detail_title = QLabel("Select a finding")
        self.detail_title.setWordWrap(True)
        font = self.detail_title.font()
        font.setBold(True)
        font.setPointSize(font.pointSize() + 1)
        self.detail_title.setFont(font)
        head_layout.addWidget(self.detail_title, 1)
        self.copy_fix = button("Copy the fix")
        self.copy_fix.setEnabled(False)
        self.copy_fix.clicked.connect(self._copy_selected)
        head_layout.addWidget(self.copy_fix)
        detail_layout.addWidget(head)
        self.detail_body = QPlainTextEdit()
        self.detail_body.setReadOnly(True)
        self.detail_body.setStyleSheet(
            "background: #161b22; border: 1px solid #263041; border-radius: 8px; padding: 6px;"
        )
        detail_layout.addWidget(self.detail_body, 1)
        splitter.addWidget(detail)
        splitter.setSizes([380, 300])
        outer.addWidget(splitter, 1)

    def set_result(self, result: ScanResult) -> None:
        self.result = result
        current = self.host_filter.currentData()
        self.host_filter.blockSignals(True)
        self.host_filter.clear()
        self.host_filter.addItem("every host", "")
        for host in sorted({finding.host for finding in result.findings}):
            self.host_filter.addItem(host, host)
        if current:
            index = self.host_filter.findData(current)
            self.host_filter.setCurrentIndex(max(0, index))
        self.host_filter.blockSignals(False)
        self._refill()

    def refresh(self) -> None:
        self._refill()

    def _refill(self) -> None:
        if self.result is None:
            self.empty.setVisible(True)
            self.table.setVisible(False)
            self.count_label.setText("")
            return
        self.empty.setVisible(False)
        self.table.setVisible(True)
        minimum = severity_from(self.severity_filter.currentData())
        host = self.host_filter.currentData() or ""
        needle = self.search.text().strip().lower()
        rows: List[Finding] = []
        for finding in self.result.sorted_findings(minimum):
            if host and finding.host != host:
                continue
            if needle and needle not in (finding.title + finding.detail + finding.host
                                         + finding.check).lower():
                continue
            rows.append(finding)
        self._shown = rows
        fill_table(self.table, [
            [cell(finding.severity.value.upper(), severity_colour(finding.severity.value), bold=True),
             cell(finding.target, mono_font=True),
             cell(finding.check, TEXT_DIM),
             cell(finding.title, tooltip=finding.detail)]
            for finding in rows
        ])
        self.count_label.setText(f"{len(rows)} of {len(self.result.findings)}")
        if rows:
            self.table.selectRow(0)
        else:
            self.detail_title.setText("Nothing at this level")
            self.detail_body.setPlainText(
                "No finding at or above this severity. Lower the filter to see the rest — "
                "the informational lines are usually where the interesting questions are."
            )
            self.copy_fix.setEnabled(False)

    def _selected(self) -> Optional[Finding]:
        from .widgets import selected_row

        index = selected_row(self.table)
        return self._shown[index] if 0 <= index < len(self._shown) else None

    def _show_detail(self) -> None:
        finding = self._selected()
        if finding is None:
            return
        self.detail_title.setText(finding.title)
        self.detail_title.setStyleSheet(f"color: {severity_colour(finding.severity.value)};")
        lines = [
            f"severity : {finding.severity.value.upper()}",
            f"check    : {finding.check}",
            f"target   : {finding.target}",
            "",
            finding.detail,
        ]
        if finding.evidence:
            lines += ["", "evidence", "─" * 8, finding.evidence]
        if finding.remediation:
            lines += ["", "what to change", "─" * 14, finding.remediation]
        if finding.references:
            lines += ["", "references", "─" * 10] + [f"  {ref}" for ref in finding.references]
        self.detail_body.setPlainText("\n".join(lines))
        self.copy_fix.setEnabled(bool(finding.remediation))

    def _copy_selected(self) -> None:
        finding = self._selected()
        if finding is None:
            return
        from PyQt6.QtWidgets import QApplication

        text = f"{finding.title} — {finding.target}\n\nwhat to change:\n{finding.remediation}"
        QApplication.clipboard().setText(text)
        self.copy_fix.setText("Copied")
        from PyQt6.QtCore import QTimer

        QTimer.singleShot(1200, lambda: self.copy_fix.setText("Copy the fix"))


class ReportsView(QWidget):
    """Turning a run into a document. This is the part the client pays for."""

    def __init__(self, home: pathlib.Path, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.home = pathlib.Path(home)
        self.result: Optional[ScanResult] = None
        self._license: Optional[License] = None
        self._buttons: Dict[str, QPushButton] = {}
        self._build()

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 16, 20, 16)
        outer.setSpacing(12)
        outer.addWidget(page_title(
            "Reports",
            "Every report repeats the scope, who authorised the work, the window it ran in, "
            "the licence it ran under, and the checks that were skipped. That is what makes "
            "it worth signing.",
        ))

        self.state = banner("Run a scan first — there is nothing to report yet.")
        outer.addWidget(self.state)

        formats, body = None, None
        from .widgets import card

        formats, body = card("Formats")
        for key, label, description in (
            ("text", "Text (.txt)", "The same summary the terminal prints. Free."),
            ("markdown", "Markdown (.md)", "Goes into a wiki, a ticket or a git repo."),
            ("html", "HTML (.html)", "Self-contained: no scripts, no external requests. "
                                     "Opens in any browser and prints to PDF."),
            ("json", "JSON (.json)", "For your own tooling — every finding with its evidence."),
        ):
            line = QWidget()
            line_layout = QHBoxLayout(line)
            line_layout.setContentsMargins(0, 0, 0, 0)
            btn = button(label)
            btn.clicked.connect(lambda _=False, kind=key: self._export(kind))
            line_layout.addWidget(btn)
            line_layout.addWidget(hint(description), 1)
            body.addWidget(line)
            self._buttons[key] = btn

        severity_line = QWidget()
        severity_layout = QHBoxLayout(severity_line)
        severity_layout.setContentsMargins(0, 0, 0, 0)
        self.minimum = QComboBox()
        for label, key in (("include everything", "info"), ("low and above", "low"),
                           ("medium and above", "medium"), ("high and above", "high"),
                           ("critical only", "critical")):
            self.minimum.addItem(label, key)
        severity_layout.addWidget(QLabel("In the report, include findings at"))
        severity_layout.addWidget(self.minimum)
        severity_layout.addStretch(1)
        body.addWidget(severity_line)
        outer.addWidget(formats)

        limits, limits_body = card("What this licence can produce")
        self.limits_label = QLabel("")
        self.limits_label.setWordWrap(True)
        limits_body.addWidget(self.limits_label)
        outer.addWidget(limits)
        outer.addStretch(1)

    def apply_license(self, license_: License) -> None:
        self._license = license_
        allowed = set(license_.limits["reports"])
        for key, btn in self._buttons.items():
            ok = key in allowed
            btn.setEnabled(ok and self.result is not None)
            btn.setToolTip("" if ok else "This format is part of the paid licence")
            if not ok:
                btn.setText(btn.text() + "  🔒")
        self.limits_label.setText(
            "This installation can write: " + ", ".join(sorted(allowed)) + "."
            + ("" if license_.is_paid else
               "  Markdown, HTML and JSON come with Pro — one payment, no subscription.")
        )

    def set_result(self, result: ScanResult) -> None:
        self.result = result
        self.state.setText(
            f"Report for <b>{result.scope_name}</b> · {result.started or 'just now'} · "
            f"{len(result.findings)} finding(s). Choose a format."
        )
        if self._license is not None:
            self.apply_license(self._license)

    def refresh(self) -> None:
        if self._license is not None:
            self.apply_license(self._license)

    def _suggested_name(self, kind: str) -> str:
        scope = (self.result.scope_name if self.result else "scan")
        safe = "".join(character if character.isalnum() or character in "-_" else "-"
                       for character in scope)[:40].strip("-") or "scan"
        stamp = datetime.datetime.now().strftime("%Y-%m-%d")
        return f"pentdeck-{safe}-{stamp}.{REPORT_EXTENSIONS.get(kind, 'txt')}"

    def _export(self, kind: str) -> None:
        if self.result is None or self._license is None:
            return
        if not self._license.allows_report(kind):
            QMessageBox.information(
                self, "Pro feature",
                "Markdown, HTML and JSON reports come with the paid licence.\n\n"
                "Open the Licence page to create an order.",
            )
            return
        suggested = str(pathlib.Path(self.home) / self._suggested_name(kind))
        path, _ = QFileDialog.getSaveFileName(self, f"Save the {kind} report", suggested)
        if not path:
            return
        minimum = severity_from(self.minimum.currentData())
        writer = FORMATS[kind]
        text = writer(self.result, minimum) if kind != "text" else writer(
            self.result, colour=False, minimum=minimum
        )
        pathlib.Path(path).write_text(text, encoding="utf-8")
        self.state.setText(f"Written to <span style='font-family:monospace'>{path}</span>")
