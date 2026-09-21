"""Small widgets the dashboard is assembled from.

Kept apart from the views so the views read like the screen they draw: a stat card, a
status pill, a table that behaves, and a "copy this" button that is on every screen a
pentester needs it — because the point of a report is that somebody acts on it.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (QApplication, QFrame, QHBoxLayout, QHeaderView, QLabel,
                             QPushButton, QSizePolicy, QTableWidget, QTableWidgetItem,
                             QVBoxLayout, QWidget)

from .theme import ACCENT, BG_PANEL, BORDER, SEVERITY_COLOUR, TEXT, TEXT_DIM


def scrollable(inner: QWidget) -> "QScrollArea":
    """Let a tall page scroll instead of squashing its rows into each other."""
    from PyQt6.QtWidgets import QScrollArea

    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QScrollArea.Shape.NoFrame)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setWidget(inner)
    return area


def page_title(text: str, subtitle: str = "") -> QWidget:
    box = QWidget()
    layout = QVBoxLayout(box)
    layout.setContentsMargins(0, 0, 0, 6)
    layout.setSpacing(2)
    title = QLabel(text)
    title.setObjectName("PageTitle")
    layout.addWidget(title)
    if subtitle:
        layout.addWidget(hint(subtitle))
    return box


def hint(text: str) -> QLabel:
    """Dim, wrapping explanation text. Used generously: a scanner that explains itself
    is a scanner whose output can be defended in a meeting."""
    label = QLabel(text)
    label.setObjectName("Hint")
    label.setWordWrap(True)
    return label


def mono(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setObjectName("Mono")
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


def pill(text: str, colour: Optional[str] = None) -> QLabel:
    label = QLabel(text)
    label.setObjectName("Pill")
    if colour:
        label.setStyleSheet(f"#Pill {{ color: {colour}; border-color: {colour}; }}")
    label.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum)
    return label


def set_pill(label: QLabel, text: str, colour: Optional[str] = None) -> None:
    label.setText(text)
    label.setStyleSheet(f"#Pill {{ color: {colour}; border-color: {colour}; }}" if colour else "")


def card(title: str = "") -> tuple:
    """A panel with an optional title. Returns ``(frame, body_layout)``."""
    frame = QFrame()
    frame.setObjectName("Card")
    outer = QVBoxLayout(frame)
    outer.setContentsMargins(16, 14, 16, 14)
    outer.setSpacing(8)
    if title:
        label = QLabel(title.upper())
        label.setObjectName("CardTitle")
        outer.addWidget(label)
    body = QVBoxLayout()
    body.setSpacing(6)
    outer.addLayout(body)
    return frame, body


def stat_card(title: str, value: str = "—", detail: str = "") -> tuple:
    """A big number with a caption. Returns ``(frame, value_label, detail_label)``."""
    frame, body = card(title)
    value_label = QLabel(value)
    value_label.setObjectName("CardValue")
    body.addWidget(value_label)
    detail_label = QLabel(detail)
    detail_label.setObjectName("Hint")
    detail_label.setWordWrap(True)
    body.addWidget(detail_label)
    return frame, value_label, detail_label


def row(*widgets: QWidget, spacing: int = 8, stretch_last: bool = True) -> QWidget:
    box = QWidget()
    box.setObjectName("Row")
    layout = QHBoxLayout(box)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(spacing)
    for index, widget in enumerate(widgets):
        layout.addWidget(widget, 1 if (stretch_last and index == len(widgets) - 1) else 0)
    return box


def button(text: str, primary: bool = False, tooltip: str = "") -> QPushButton:
    btn = QPushButton(text)
    if primary:
        btn.setObjectName("Primary")
    if tooltip:
        btn.setToolTip(tooltip)
    return btn


def copy_button(text: str, what: str = "text", parent: Optional[QWidget] = None) -> QPushButton:
    """Copies ``text`` (or whatever the callable returns) and says so on the button.

    A licence token, a remediation command and a wallet address are all things people
    retype wrong. This button exists so they do not have to.
    """
    btn = QPushButton(f"Copy {what}")
    btn.setToolTip("Copy to the clipboard")

    def _copy() -> None:
        payload = text() if callable(text) else text
        QApplication.clipboard().setText(payload or "")
        btn.setText("Copied")
        btn.setEnabled(False)

        from PyQt6.QtCore import QTimer

        QTimer.singleShot(1200, _restore)

    def _restore() -> None:
        btn.setText(f"Copy {what}")
        btn.setEnabled(True)

    btn.clicked.connect(_copy)
    return btn


def make_table(columns: Sequence[str], stretch_column: int = -1) -> QTableWidget:
    """A read-only table that behaves the way a table should."""
    table = QTableWidget(0, len(columns))
    table.setHorizontalHeaderLabels(list(columns))
    table.verticalHeader().setVisible(False)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    table.setAlternatingRowColors(True)
    table.setWordWrap(False)
    table.setShowGrid(False)
    table.verticalHeader().setDefaultSectionSize(28)
    header: QHeaderView = table.horizontalHeader()
    header.setHighlightSections(False)
    for index in range(len(columns)):
        header.setSectionResizeMode(index, QHeaderView.ResizeMode.ResizeToContents)
    if stretch_column >= 0:
        header.setSectionResizeMode(stretch_column, QHeaderView.ResizeMode.Stretch)
    else:
        header.setStretchLastSection(True)
    return table


def cell(text: str, colour: str = "", bold: bool = False, mono_font: bool = False,
         tooltip: str = "") -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    if colour:
        item.setForeground(QColor(colour))
    if bold:
        font = QFont()
        font.setBold(True)
        item.setFont(font)
    if mono_font:
        font = item.font()
        font.setFamilies(["Consolas", "DejaVu Sans Mono", "monospace"])
        item.setFont(font)
    if tooltip:
        item.setToolTip(tooltip)
    return item


def severity_prefix(severity: str) -> str:
    """``critical`` → ``CRITICAL``, so it lines up in a monospace column."""
    return severity.upper()


def log_box(placeholder: str = "") -> "QPlainTextEdit":
    from PyQt6.QtWidgets import QPlainTextEdit

    box = QPlainTextEdit()
    box.setReadOnly(True)
    box.setPlaceholderText(placeholder)
    box.setStyleSheet(
        f"background: {BG_PANEL}; border: 1px solid {BORDER}; border-radius: 8px;"
        f" font-family: Consolas, 'DejaVu Sans Mono', monospace; font-size: 12px; color: {TEXT};"
    )
    box.setMaximumBlockCount(4000)
    return box


def severity_colour(severity: str) -> str:
    return SEVERITY_COLOUR.get(str(severity).lower(), TEXT_DIM)


def severity_strip(counts: dict) -> QWidget:
    """One chip per severity that actually occurred, worst first."""
    box = QWidget()
    layout = QHBoxLayout(box)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(8)
    order: List[str] = ["critical", "high", "medium", "low", "info"]
    shown = False
    for name in order:
        if not counts.get(name):
            continue
        shown = True
        layout.addWidget(pill(f"{counts[name]} {name}", severity_colour(name)))
    if not shown:
        layout.addWidget(pill("nothing to report yet"))
    layout.addStretch(1)
    return box


def clear_table(table: QTableWidget) -> None:
    table.setRowCount(0)


def fill_table(table: QTableWidget, rows: Iterable[Sequence[QTableWidgetItem]]) -> None:
    clear_table(table)
    for values in rows:
        position = table.rowCount()
        table.insertRow(position)
        for column, item in enumerate(values):
            table.setItem(position, column, item)


def selected_row(table: QTableWidget) -> int:
    rows = table.selectionModel().selectedRows() if table.selectionModel() else []
    return rows[0].row() if rows else -1


def banner(text: str, colour: str = ACCENT) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setStyleSheet(
        f"background: {BG_PANEL}; border-left: 3px solid {colour}; border-radius: 6px;"
        f" padding: 9px 12px; color: {TEXT};"
    )
    return label
