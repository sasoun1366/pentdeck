"""Dashboard, Targets, Tools and Licence.

The dashboard answers "where does this assessment stand"; the Targets page is where the
only two things that make a scan legal are entered — what may be touched, and who said
so. Both are treated as first-class UI here on purpose: the authorization record is not
a hidden flag, it is a form you have to fill in before anything else works.
"""

from __future__ import annotations

import json
import os
import pathlib
from typing import Dict, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QCheckBox, QComboBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel,
                             QLineEdit, QMessageBox, QPlainTextEdit, QTabWidget,
                             QVBoxLayout, QWidget)

from ..checks import CHECKS, ORDER
from ..findings import ScanResult
from ..license import TIERS, License, current_license, install_token, machine_id, upgrade_message
from ..purchase import (build_request_text, load_telegram, load_wallet, order_code,
                        save_wallet, send_order)
from ..scope import AuditLog, Authorization, Scope, ScopeError
from .theme import ACCENT, GOOD, SEVERITY_COLOUR, TEXT_DIM, WARN
from .widgets import (banner, button, card, cell, copy_button, fill_table, hint, log_box,
                      make_table, mono, page_title, pill, row, scrollable, set_pill,
                      severity_strip, stat_card)

PAGES = [
    ("dashboard", "Overview"),
    ("targets", "Targets"),
    ("scan", "Scan"),
    ("findings", "Findings"),
    ("reports", "Reports"),
    ("tools", "Tools & checks"),
    ("license", "Licence"),
]


def fill_strip(layout: QVBoxLayout, counts: dict) -> None:
    """Replace whatever severity chips are in ``layout`` with the current counts.

    ``deleteLater()`` alone is not enough: it defers the removal, so a page refreshed
    twice shows the chips twice. Taking the item out of the layout first is what makes
    this idempotent.
    """
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
    layout.addWidget(severity_strip(counts))


def load_scope(home: pathlib.Path) -> Scope:
    """The scope on disk, or an empty one that is not saved yet."""
    if Scope.path(home).exists():
        return Scope.load(home)
    return Scope()


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
class DashboardView(QWidget):
    """The state of the engagement in one screen: what is declared, what was found."""

    navigate = pyqtSignal(str)

    def __init__(self, home: pathlib.Path, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.home = pathlib.Path(home)
        self.result: Optional[ScanResult] = None
        self._build()

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 16, 20, 16)
        outer.setSpacing(12)
        outer.addWidget(page_title("Overview",
                                   "pentdeck only reports. It never changes a setting on a "
                                   "host it scans — a scanner cannot tell a deliberate "
                                   "misconfiguration from a mistake."))

        stats = QWidget()
        stats_layout = QHBoxLayout(stats)
        stats_layout.setContentsMargins(0, 0, 0, 0)
        stats_layout.setSpacing(12)
        self.hosts_card, self.hosts_value, self.hosts_detail = stat_card(
            "Hosts", "0", "in scope, none scanned yet")
        self.ports_card, self.ports_value, self.ports_detail = stat_card(
            "Open ports", "0", "across the hosts that answered")
        self.findings_card, self.findings_value, self.findings_detail = stat_card(
            "Findings", "0", "at medium or above")
        self.worst_card, self.worst_value, self.worst_detail = stat_card(
            "Worst finding", "—", "nothing reported yet")
        for widget in (self.hosts_card, self.ports_card, self.findings_card, self.worst_card):
            stats_layout.addWidget(widget, 1)
        outer.addWidget(stats)

        self.strip_holder = QWidget()
        self.strip_layout = QVBoxLayout(self.strip_holder)
        self.strip_layout.setContentsMargins(0, 0, 0, 0)
        self.strip_layout.addWidget(severity_strip({}))
        outer.addWidget(self.strip_holder)

        middle = QWidget()
        middle_layout = QHBoxLayout(middle)
        middle_layout.setContentsMargins(0, 0, 0, 0)
        middle_layout.setSpacing(12)

        checklist, checklist_body = card("Before a scan will run")
        self._steps: Dict[str, QLabel] = {}
        for key, text in (("targets", "Declare what may be scanned"),
                          ("authorize", "Record who authorised it"),
                          ("license", "Choose the licence this installation runs under")):
            line = QWidget()
            line_layout = QHBoxLayout(line)
            line_layout.setContentsMargins(0, 0, 0, 0)
            state = QLabel("—")
            state.setFixedWidth(18)
            self._steps[key] = state
            line_layout.addWidget(state)
            label = QLabel(text)
            label.setWordWrap(True)
            line_layout.addWidget(label, 1)
            checklist_body.addWidget(line)
        goto = row(button("Open the Targets page"), button("Open the Licence page"))
        actions = goto.layout()
        actions.itemAt(0).widget().clicked.connect(lambda: self.navigate.emit("targets"))
        actions.itemAt(1).widget().clicked.connect(lambda: self.navigate.emit("license"))
        checklist_body.addWidget(goto)
        checklist_body.addWidget(hint(
            "The scope and the authorization live in ~/.pentdeck/scope.json, and every "
            "scan, check and host is written to audit.jsonl."
        ))
        middle_layout.addWidget(checklist, 1)

        last, last_body = card("Last run")
        self.last_label = QLabel("No scan in this session.")
        self.last_label.setWordWrap(True)
        last_body.addWidget(self.last_label)
        self.last_detail = QLabel("")
        self.last_detail.setWordWrap(True)
        self.last_detail.setObjectName("Hint")
        last_body.addWidget(self.last_detail)
        last_actions = row(button("Run a scan", primary=True), button("Open the findings"))
        buttons = last_actions.layout()
        buttons.itemAt(0).widget().clicked.connect(lambda: self.navigate.emit("scan"))
        buttons.itemAt(1).widget().clicked.connect(lambda: self.navigate.emit("findings"))
        last_body.addWidget(last_actions)
        middle_layout.addWidget(last, 1)
        outer.addWidget(middle)

        limit, limit_body = card("What this installation can do")
        self.limits_label = QLabel("")
        self.limits_label.setWordWrap(True)
        limit_body.addWidget(self.limits_label)
        outer.addWidget(limit)
        outer.addStretch(1)

    def refresh(self) -> None:
        scope = load_scope(self.home)
        license_ = current_license(self.home)
        try:
            hosts = scope.hosts()
            host_error = ""
        except ScopeError as exc:
            hosts, host_error = [], str(exc)

        self.hosts_value.setText(str(len(hosts)))
        self.hosts_detail.setText(
            host_error or (f"in scope · {scope.name}" if hosts else "in scope — nothing declared yet")
        )
        scanned = len(self.result.hosts_up) if self.result else 0
        if self.result:
            self.hosts_detail.setText(
                f"{scanned} of {len(hosts)} answered · scope {self.result.scope_name}"
            )
            ports = sum(
                len(finding.detail.split(": ")[-1].split(", "))
                for finding in self.result.findings
                if finding.check == "ports" and "Ports answering" in finding.detail
            )
            self.ports_value.setText(str(ports or 0))
            counts = self.result.counts()
            medium_up = sum(counts[name] for name in ("critical", "high", "medium"))
            self.findings_value.setText(str(len(self.result.findings)))
            self.findings_detail.setText(f"{medium_up} at medium or above")
            worst = self.result.worst
            self.worst_value.setText(worst.value.upper() if self.result.findings else "—")
            self.worst_value.setStyleSheet(
                f"color: {SEVERITY_COLOUR.get(worst.value, TEXT_DIM)};" if self.result.findings else ""
            )
            self.worst_detail.setText(
                "the highest severity reported" if self.result.findings else "nothing reported"
            )
            fill_strip(self.strip_layout, counts)
        else:
            self.ports_value.setText("0")
            self.findings_value.setText("0")
            self.worst_value.setText("—")

        self._steps["targets"].setText("✓" if hosts else "×")
        self._steps["targets"].setStyleSheet(f"color: {GOOD if hosts else SEVERITY_COLOUR['high']};")
        authorized = bool(scope.authorization)
        self._steps["authorize"].setText("✓" if authorized else "×")
        self._steps["authorize"].setStyleSheet(
            f"color: {GOOD if authorized else SEVERITY_COLOUR['high']};"
        )
        self._steps["license"].setText("✓" if license_.is_paid else "·")
        self._steps["license"].setStyleSheet(
            f"color: {GOOD if license_.is_paid else TEXT_DIM};"
        )

        if self.result:
            self.last_label.setText(
                f"<b>{len(self.result.findings)} finding(s)</b> in {len(self.result.hosts_up)} "
                f"host(s) that answered — {self.result.started[:19].replace('T', ' ')} UTC"
                f"{' · stopped early' if self.result.interrupted else ''}"
            )
            self.last_detail.setText(
                "checks: " + ", ".join(self.result.checks_run)
                + (f" · {len(self.result.checks_skipped)} skipped"
                   if self.result.checks_skipped else "")
            )
        self.limits_label.setText(
            f"<b>{TIERS[license_.tier]['label']}</b> — checks: "
            f"{', '.join(license_.limits['checks'])}<br>"
            f"reports: {', '.join(license_.limits['reports'])} · "
            f"hosts per scan: {'unlimited' if license_.host_limit() == 0 else license_.host_limit()}"
        )

    def set_result(self, result: ScanResult) -> None:
        self.result = result
        self.refresh()


# ---------------------------------------------------------------------------
# Targets and authorization
# ---------------------------------------------------------------------------
class TargetsView(QWidget):
    """What may be scanned, what may never be, and who said so."""

    changed = pyqtSignal()

    def __init__(self, home: pathlib.Path, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.home = pathlib.Path(home)
        self.scope = load_scope(self.home)
        self._build()
        self.reload()

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 16, 20, 16)
        outer.setSpacing(10)
        outer.addWidget(page_title(
            "Targets",
            "Ranges, hosts and host:port entries. The scope is enforced before a single "
            "packet is sent, and again for every host.",
        ))

        self.message = banner("")
        self.message.setVisible(False)
        outer.addWidget(self.message)

        tabs = QTabWidget()
        tabs.addTab(self._targets_tab(), "Scope")
        tabs.addTab(self._deny_tab(), "Never touch")
        tabs.addTab(self._authorization_tab(), "Authorization")
        tabs.addTab(self._audit_tab(), "Audit trail")
        outer.addWidget(tabs, 1)

    # scope ------------------------------------------------------------------
    def _targets_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(8)

        name_line = QWidget()
        name_layout = QHBoxLayout(name_line)
        name_layout.setContentsMargins(0, 0, 0, 0)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("what is this engagement called?")
        save_name = button("Rename the scope")
        save_name.clicked.connect(self._rename)
        name_layout.addWidget(QLabel("Scope name"))
        name_layout.addWidget(self.name_edit, 1)
        name_layout.addWidget(save_name)
        layout.addWidget(name_line)

        self.table = make_table(["Entry", "Expands to", "Kind"], stretch_column=0)
        layout.addWidget(self.table, 1)

        add_line = QWidget()
        add_layout = QHBoxLayout(add_line)
        add_layout.setContentsMargins(0, 0, 0, 0)
        self.entry_edit = QLineEdit()
        self.entry_edit.setPlaceholderText("192.168.1.0/28 · 10.0.0.5 · srv-01.lan · 10.0.0.9:8443")
        self.entry_edit.returnPressed.connect(self._add)
        add = button("Add to the scope", primary=True)
        add.clicked.connect(self._add)
        remove = button("Remove the selected")
        remove.clicked.connect(self._remove)
        add_layout.addWidget(self.entry_edit, 1)
        add_layout.addWidget(add)
        add_layout.addWidget(remove)
        layout.addWidget(add_line)

        self.public_box = QCheckBox("Also allow public addresses")
        self.public_box.toggled.connect(self._public_toggled)
        layout.addWidget(self.public_box)
        layout.addWidget(hint(
            "Public addresses stay refused until this is ticked. An internal assessment "
            "that quietly starts scanning the internet is how people end up explaining "
            "themselves to a regulator."
        ))
        layout.addWidget(mono(str(Scope.path(self.home))))
        return page

    # denylist ---------------------------------------------------------------
    def _deny_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(8)
        layout.addWidget(hint(
            "Hosts or ranges that must never be touched, even if they fall inside the "
            "scope — the production database, the MRI scanner, the boss's printer."
        ))
        self.deny_table = make_table(["Entry", "Expands to"], stretch_column=0)
        layout.addWidget(self.deny_table, 1)
        line = QWidget()
        line_layout = QHBoxLayout(line)
        line_layout.setContentsMargins(0, 0, 0, 0)
        self.deny_edit = QLineEdit()
        self.deny_edit.setPlaceholderText("192.168.1.10")
        self.deny_edit.returnPressed.connect(self._add_deny)
        add = button("Never touch this")
        add.clicked.connect(self._add_deny)
        remove = button("Remove")
        remove.clicked.connect(self._remove_deny)
        line_layout.addWidget(self.deny_edit, 1)
        line_layout.addWidget(add)
        line_layout.addWidget(remove)
        layout.addWidget(line)
        return page

    # authorization ----------------------------------------------------------
    def _authorization_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        layout.addWidget(hint(
            "A scan refuses to start without this. Write down who asked for the test and "
            "which document says you may do it — a contract number, an approval e-mail, a "
            "ticket. The record is stored next to the scope and repeated in every report."
        ))
        group = QGroupBox("Authorised by")
        form = QFormLayout(group)
        self.operator_edit = QLineEdit()
        self.operator_edit.setPlaceholderText("the person who signed off")
        self.reference_edit = QLineEdit()
        self.reference_edit.setPlaceholderText("contract 2026-114 · e-mail of 2026-09-04 · TICKET-88")
        self.note_edit = QLineEdit()
        self.note_edit.setPlaceholderText("optional: maintenance window, exclusions, anything agreed")
        form.addRow("Operator", self.operator_edit)
        form.addRow("Reference", self.reference_edit)
        form.addRow("Note", self.note_edit)
        layout.addWidget(group)
        save = button("Record the authorization", primary=True)
        save.clicked.connect(self._authorize)
        layout.addWidget(save)
        self.auth_state = QLabel("")
        self.auth_state.setWordWrap(True)
        layout.addWidget(self.auth_state)
        layout.addStretch(1)
        return page

    # audit ------------------------------------------------------------------
    def _audit_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(8)
        layout.addWidget(hint(
            "Every scan, every check and every authorization, with the time it happened. "
            "If a client ever asks what you did on their network, this is the answer — and "
            "it is written whether or not the scan went well."
        ))
        self.audit_box = log_box("nothing recorded yet")
        layout.addWidget(self.audit_box, 1)
        refresh = button("Refresh")
        refresh.clicked.connect(self._reload_audit)
        layout.addWidget(refresh)
        return page

    # behaviour --------------------------------------------------------------
    def reload(self) -> None:
        self.scope = load_scope(self.home)
        self.name_edit.setText(self.scope.name)
        self.public_box.blockSignals(True)
        self.public_box.setChecked(self.scope.allow_public)
        self.public_box.blockSignals(False)
        fill_table(self.table, [
            [cell(entry, mono_font=True), cell(self._expansion(entry), TEXT_DIM), cell("")]
            for entry in self.scope.entries
        ])
        for row_index, entry in enumerate(self.scope.entries):
            kind = "range" if "/" in entry else ("host:port" if ":" in entry else "host")
            if "." not in entry and ":" not in entry and "/" not in entry:
                kind = "name"
            self.table.setItem(row_index, 2, cell(kind, TEXT_DIM))
        fill_table(self.deny_table, [
            [cell(entry, mono_font=True), cell(self._expansion(entry), TEXT_DIM)]
            for entry in self.scope.deny
        ])
        authorization = self.scope.authorization
        if authorization:
            self.operator_edit.setText(authorization.operator)
            self.reference_edit.setText(authorization.reference)
            self.note_edit.setText(authorization.note)
            self.auth_state.setText(
                f"<span style='color:{GOOD}'>On record:</span> " + authorization.summary()
            )
        else:
            self.auth_state.setText(
                f"<span style='color:{SEVERITY_COLOUR['high']}'>Nothing on record yet — "
                f"a scan will refuse to run.</span>"
            )
        self._reload_audit()

    def _expansion(self, entry: str) -> str:
        from ..scope import expand_entry

        try:
            hosts = expand_entry(entry)
        except ScopeError as exc:
            return f"invalid: {exc}"
        if len(hosts) == 1:
            return hosts[0]
        return f"{len(hosts)} hosts · {hosts[0]} … {hosts[-1]}"

    def _reload_audit(self) -> None:
        records = AuditLog(self.home).tail(60)
        if not records:
            self.audit_box.setPlainText("nothing recorded yet")
            return
        lines = []
        for record in records:
            when = str(record.get("time", ""))[:19]
            event = str(record.get("event", ""))
            rest = {k: v for k, v in record.items() if k not in ("time", "event")}
            lines.append(f"{when}  {event:<14} {json.dumps(rest, ensure_ascii=False)}")
        self.audit_box.setPlainText("\n".join(lines))

    def _say(self, text: str, good: bool = True) -> None:
        colour = GOOD if good else SEVERITY_COLOUR["high"]
        self.message.setText(text)
        self.message.setStyleSheet(
            f"background: transparent; border-left: 3px solid {colour}; padding: 9px 12px;"
        )
        self.message.setVisible(True)

    def _save(self) -> None:
        self.scope.save(self.home)
        self.reload()
        self.changed.emit()

    def _add(self) -> None:
        entry = self.entry_edit.text().strip()
        if not entry:
            return
        try:
            self.scope.add(entry)
            self.scope.save(self.home)
        except ScopeError as exc:
            self._say(str(exc), good=False)
            return
        self.entry_edit.clear()
        self._say(f"added {entry} — {self._expansion(entry)}")
        self.reload()
        self.changed.emit()

    def _remove(self) -> None:
        from .widgets import selected_row

        index = selected_row(self.table)
        if index < 0:
            self._say("Select the entry you want to remove first.", good=False)
            return
        entry = self.scope.entries[index]
        self.scope.remove(entry)
        self._save()
        self._say(f"removed {entry}")

    def _add_deny(self) -> None:
        entry = self.deny_edit.text().strip()
        if not entry:
            return
        try:
            from ..scope import expand_entry

            expand_entry(entry)
        except ScopeError as exc:
            self._say(str(exc), good=False)
            return
        if entry not in self.scope.deny:
            self.scope.deny.append(entry)
        self.deny_edit.clear()
        self._save()
        self._say(f"{entry} will never be touched")

    def _remove_deny(self) -> None:
        from .widgets import selected_row

        index = selected_row(self.deny_table)
        if index < 0 or index >= len(self.scope.deny):
            self._say("Select the entry you want to remove first.", good=False)
            return
        entry = self.scope.deny.pop(index)
        self._save()
        self._say(f"{entry} is back in play if it is inside the scope")

    def _rename(self) -> None:
        name = self.name_edit.text().strip() or "default"
        self.scope.name = name
        self._save()
        self._say(f"scope renamed to {name}")

    def _public_toggled(self, on: bool) -> None:
        self.scope.allow_public = bool(on)
        self._save()
        self._say("public addresses are now allowed " if on else "public addresses are refused again",
                  good=not on)

    def _authorize(self) -> None:
        try:
            authorization = Authorization(
                operator=self.operator_edit.text(),
                reference=self.reference_edit.text(),
                note=self.note_edit.text(),
            )
        except ScopeError as exc:
            self._say(str(exc), good=False)
            return
        self.scope.authorization = authorization
        self._save()
        AuditLog(self.home).append("authorization", operator=authorization.operator,
                                   reference=authorization.reference)
        self._say("recorded: " + authorization.summary())
        self.changed.emit()


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
class ToolsView(QWidget):
    """The catalogue: what exists, what it needs, and whether this copy may run it."""

    def __init__(self, home: pathlib.Path, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.home = pathlib.Path(home)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 16, 20, 16)
        outer.setSpacing(10)
        outer.addWidget(page_title("Tools & checks",
                                   "The workbench. Free includes discovery and service "
                                   "identification; Pro unlocks everything that reads a "
                                   "configuration."))
        self.state = banner("")
        outer.addWidget(self.state)
        self.table = make_table(
            ["Check", "Stage", "Licence", "Intrusive", "Runs here", "What it does"], stretch_column=5
        )
        outer.addWidget(self.table, 1)
        outer.addWidget(hint(
            "Stage is the order inside a run: ports are found first, then banners, then "
            "everything that needs to know which ports are open."
        ))

    def refresh(self) -> None:
        license_ = current_license(self.home)
        self.state.setText(
            f"Licence: <b>{TIERS[license_.tier]['label']}</b> — {license_.summary().splitlines()[0].replace('licence : ', '')}"
        )
        rows = []
        for name in ORDER:
            check = CHECKS[name]
            allowed = license_.allows_check(name)
            rows.append([
                cell(name, mono_font=True, bold=True),
                cell(str(check.stage), TEXT_DIM),
                cell("free" if name in TIERS["free"]["checks"] else "pro",
                     GOOD if name in TIERS["free"]["checks"] else ACCENT),
                cell("yes" if check.intrusive else "—",
                     WARN if check.intrusive else TEXT_DIM),
                cell("yes" if allowed else "locked",
                     GOOD if allowed else SEVERITY_COLOUR["high"]),
                cell(check.description),
            ])
        fill_table(self.table, rows)


# ---------------------------------------------------------------------------
# Licence
# ---------------------------------------------------------------------------
class LicenseView(QWidget):
    """Status, installation, and the order the buyer sends the seller."""

    changed = pyqtSignal()

    def __init__(self, home: pathlib.Path, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.home = pathlib.Path(home)
        self._build()
        self.refresh()

    def _build(self) -> None:
        shell = QVBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        content = QWidget()
        outer = QVBoxLayout(content)
        outer.setContentsMargins(20, 16, 20, 16)
        outer.setSpacing(12)
        outer.addWidget(page_title("Licence",
                                   "One payment, no subscription, no licence server. The "
                                   "token is verified offline with a signature — nothing "
                                   "about this machine is sent anywhere."))

        self.status_card, body = card("This installation")
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        body.addWidget(self.status_label)
        self.limits_label = QLabel("")
        self.limits_label.setWordWrap(True)
        self.limits_label.setObjectName("Hint")
        body.addWidget(self.limits_label)
        machine_line = QWidget()
        machine_layout = QHBoxLayout(machine_line)
        machine_layout.setContentsMargins(0, 0, 0, 0)
        self.machine_label = mono(machine_id())
        machine_layout.addWidget(QLabel("Machine id"))
        machine_layout.addWidget(self.machine_label, 1)
        machine_layout.addWidget(copy_button(machine_id, "the id"))
        body.addWidget(machine_line)
        outer.addWidget(self.status_card)

        middle = QWidget()
        middle_layout = QHBoxLayout(middle)
        middle_layout.setContentsMargins(0, 0, 0, 0)
        middle_layout.setSpacing(12)

        install_card, install_body = card("Install a licence")
        install_body.addWidget(hint(
            "Paste the token the seller sent you. It is signed, so a mistyped character "
            "is rejected instead of half-working."
        ))
        self.token_edit = QPlainTextEdit()
        self.token_edit.setPlaceholderText("PD1.…")
        self.token_edit.setMaximumHeight(90)
        install_body.addWidget(self.token_edit)
        install = button("Install", primary=True)
        install.clicked.connect(self._install)
        install_body.addWidget(install)
        self.install_state = QLabel("")
        self.install_state.setWordWrap(True)
        install_body.addWidget(self.install_state)
        middle_layout.addWidget(install_card, 1)

        keys_card, keys_body = card("Verify a token without installing it")
        keys_body.addWidget(hint(
            "Reads the payload out of a token so you can check the customer name, the "
            "tier and the expiry before you put it on a machine."
        ))
        self.inspect_edit = QPlainTextEdit()
        self.inspect_edit.setPlaceholderText("PD1.…")
        self.inspect_edit.setMaximumHeight(90)
        keys_body.addWidget(self.inspect_edit)
        inspect = button("Read it")
        inspect.clicked.connect(self._inspect)
        keys_body.addWidget(inspect)
        self.inspect_state = QPlainTextEdit()
        self.inspect_state.setReadOnly(True)
        self.inspect_state.setMaximumHeight(120)
        keys_body.addWidget(self.inspect_state)
        middle_layout.addWidget(keys_card, 1)
        outer.addWidget(middle)

        order_card, order_body = card("Get a paid licence")
        order_body.addWidget(hint(
            "Creates an order code and the exact message to send. Pay in USDT (TRC20) "
            "with the order code in the memo, then send the transaction id — the signed "
            "token comes back in the same chat."
        ))
        form = QFormLayout()
        self.buy_name = QLineEdit()
        self.buy_name.setPlaceholderText("your name or company")
        self.buy_email = QLineEdit()
        self.buy_email.setPlaceholderText("where the receipt should go")
        self.buy_tier = QComboBox()
        for key in ("pro", "team"):
            self.buy_tier.addItem(f"{TIERS[key]['label']} — ${TIERS[key]['price_usd']} once", key)
        self.buy_note = QLineEdit()
        self.buy_note.setPlaceholderText("optional: anything the seller should know")
        form.addRow("Name", self.buy_name)
        form.addRow("E-mail", self.buy_email)
        form.addRow("Tier", self.buy_tier)
        form.addRow("Note", self.buy_note)
        order_body.addLayout(form)
        create = button("Create the order", primary=True)
        create.clicked.connect(self._create_order)
        order_body.addWidget(create)
        self.order_text = QPlainTextEdit()
        self.order_text.setReadOnly(True)
        self.order_text.setPlaceholderText("the message appears here")
        self.order_text.setMaximumHeight(190)
        order_body.addWidget(self.order_text)
        self.order_status = QLabel("")
        self.order_status.setWordWrap(True)
        order_body.addWidget(self.order_status)
        order_actions = QWidget()
        order_actions_layout = QHBoxLayout(order_actions)
        order_actions_layout.setContentsMargins(0, 0, 0, 0)
        self.copy_order = button("Copy the message")
        self.copy_order.clicked.connect(self._copy_order)
        self.copy_order.setEnabled(False)
        self.send_order_button = button("Send it to the seller")
        self.send_order_button.clicked.connect(self._send_order)
        self.send_order_button.setEnabled(False)
        self.open_telegram = button("Open Telegram")
        self.open_telegram.clicked.connect(self._open_telegram)
        order_actions_layout.addWidget(self.copy_order)
        order_actions_layout.addWidget(self.send_order_button)
        order_actions_layout.addStretch(1)
        order_actions_layout.addWidget(self.open_telegram)
        order_body.addWidget(order_actions)
        self.upgrade_label = QLabel("")
        self.upgrade_label.setWordWrap(True)
        self.upgrade_label.setObjectName("Hint")
        upgrade = upgrade_message("pro", wallet=load_wallet(self.home),
                                  telegram=load_telegram(self.home))
        self.upgrade_label.setText(upgrade.replace("\n", "<br>"))
        order_body.addWidget(self.upgrade_label)
        outer.addWidget(order_card)
        outer.addStretch(1)
        shell.addWidget(scrollable(content))

        self._order_text_value = ""

    def refresh(self) -> None:
        license_ = current_license(self.home)
        label = TIERS[license_.tier]["label"]
        paid = license_.is_paid
        self.status_label.setText(
            f"<b style='font-size:15px'>{label}</b>"
            + (f" — valid, {license_.days_left} day(s) left" if paid and license_.days_left is not None
               else " — valid, no expiry" if paid else " (no licence installed)")
            + (f" · {license_.customer}" if license_.customer else "")
        )
        self.limits_label.setText(
            "checks: " + ", ".join(license_.limits["checks"])
            + " · reports: " + ", ".join(license_.limits["reports"])
            + " · hosts per scan: "
            + ("unlimited" if license_.host_limit() == 0 else str(license_.host_limit()))
            + (f" · order {license_.order}" if license_.order else "")
        )
        self.upgrade_label.setVisible(not paid)
        self.send_order_button.setEnabled(
            bool(os.environ.get("PENTDECK_BUY_BOT_TOKEN") and os.environ.get("PENTDECK_BUY_CHAT_ID"))
            and bool(self._order_text_value)
        )

    # actions ----------------------------------------------------------------
    def _install(self) -> None:
        token = self.token_edit.toPlainText().strip()
        if not token:
            return
        try:
            license_ = install_token(token, self.home)
        except Exception as exc:                              # noqa: BLE001 - a bad paste is normal
            self.install_state.setText(
                f"<span style='color:{SEVERITY_COLOUR['critical']}'>{exc}</span>"
            )
            return
        self.install_state.setText(
            f"<span style='color:{GOOD}'>Installed: {license_.summary().splitlines()[0]}</span>"
        )
        self.token_edit.clear()
        self.refresh()
        self.changed.emit()

    def _inspect(self) -> None:
        from ..license import inspect_token

        try:
            payload = inspect_token(self.inspect_edit.toPlainText().strip())
        except Exception as exc:                              # noqa: BLE001
            self.inspect_state.setPlainText(f"not a licence token: {exc}")
            return
        self.inspect_state.setPlainText(json.dumps(payload, indent=2, ensure_ascii=False))

    def _create_order(self) -> None:
        name = self.buy_name.text().strip() or "pentdeck customer"
        email = self.buy_email.text().strip()
        tier = self.buy_tier.currentData()
        order = order_code()
        wallet = load_wallet(self.home)
        telegram = load_telegram(self.home)
        self._order_text_value = build_request_text(
            name=name, email=email, tier=tier, order=order,
            note=self.buy_note.text().strip(), wallet=wallet, telegram=telegram,
        )
        self.order_text.setPlainText(self._order_text_value)
        self.copy_order.setEnabled(True)
        if not wallet:
            self.order_text.appendPlainText(
                "\n(No wallet address is set on this copy yet — the seller can set it "
                "once with `pentdeck license wallet <address>`.)"
            )
        self.refresh()

    def _copy_order(self) -> None:
        from PyQt6.QtWidgets import QApplication

        QApplication.clipboard().setText(self._order_text_value)
        self.copy_order.setText("Copied")

        from PyQt6.QtCore import QTimer

        QTimer.singleShot(1200, lambda: self.copy_order.setText("Copy the message"))

    def _send_order(self) -> None:
        token = os.environ.get("PENTDECK_BUY_BOT_TOKEN", "")
        chat_id = os.environ.get("PENTDECK_BUY_CHAT_ID", "")
        if not (token and chat_id and self._order_text_value):
            return
        ok, message = send_order(self._order_text_value, token, chat_id)
        # A modal box would block the window (and any test driving it); the answer belongs
        # next to the message that was sent.
        note = ("sent to the seller's Telegram ✔" if ok
                else f"it did not go through: {message}")
        self.order_text.appendPlainText(f"\n{note}")
        self.order_status.setText(note)

    def _open_telegram(self) -> None:
        from PyQt6.QtCore import QUrl
        from PyQt6.QtGui import QDesktopServices

        QDesktopServices.openUrl(QUrl(load_telegram(self.home)))
