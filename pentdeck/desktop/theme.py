"""Colours and the stylesheet.

One dark palette, kept in one place: the severity colours here are the same hex values
the HTML report uses, so a screenshot of the dashboard and the PDF you send the client
agree with each other.
"""

from __future__ import annotations

from typing import Dict

BG = "#0d1117"
BG_PANEL = "#161b22"
BG_RAISED = "#1c2430"
BORDER = "#263041"
TEXT = "#e6edf3"
TEXT_DIM = "#8b949e"
ACCENT = "#2f81f7"
ACCENT_DIM = "#1f6feb"
GOOD = "#3fb950"
WARN = "#d29922"

SEVERITY_COLOUR: Dict[str, str] = {
    "critical": "#f85149",
    "high": "#ff8c42",
    "medium": "#d29922",
    "low": "#58a6ff",
    "info": "#8b949e",
}

STYLESHEET = f"""
QWidget {{
    background: {BG};
    color: {TEXT};
    font-family: "Segoe UI", "Inter", "DejaVu Sans", "Noto Sans", sans-serif;
    font-size: 13px;
}}
QMainWindow, QDialog {{ background: {BG}; }}

/* A blanket QWidget background paints every label and every container too, which
   turns a card into a stack of dark rectangles. Text and holders stay transparent. */
QLabel, QCheckBox, QRadioButton, QGroupBox::title {{ background: transparent; }}
#Row, #Plain {{ background: transparent; }}
QGroupBox {{
    background: transparent; border: 1px solid {BORDER}; border-radius: 8px;
    margin-top: 12px; padding: 10px 10px 6px 10px;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; color: {TEXT_DIM}; }}

#Sidebar {{ background: {BG_PANEL}; border-right: 1px solid {BORDER}; }}
#Brand {{ font-size: 17px; font-weight: 600; padding: 18px 16px 4px 16px; }}
#BrandTag {{ color: {TEXT_DIM}; font-size: 11px; padding: 0 16px 14px 16px; }}

QPushButton#Nav {{
    text-align: left; padding: 9px 16px; border: none; background: transparent;
    color: {TEXT_DIM}; font-size: 13px; border-left: 3px solid transparent;
}}
QPushButton#Nav:hover {{ background: {BG_RAISED}; color: {TEXT}; }}
QPushButton#Nav:checked {{
    background: {BG_RAISED}; color: {TEXT}; font-weight: 600;
    border-left: 3px solid {ACCENT};
}}

#Card {{ background: {BG_PANEL}; border: 1px solid {BORDER}; border-radius: 10px; }}
#CardTitle {{ color: {TEXT_DIM}; font-size: 11px; letter-spacing: 1px; }}
#CardValue {{ font-size: 26px; font-weight: 600; }}
#PageTitle {{ font-size: 19px; font-weight: 600; }}
#Hint {{ color: {TEXT_DIM}; }}
#Mono {{ font-family: "Consolas", "DejaVu Sans Mono", monospace; font-size: 12px; }}
#Pill {{
    border-radius: 10px; padding: 3px 10px; font-size: 11px; font-weight: 600;
    background: {BG_RAISED}; color: {TEXT_DIM}; border: 1px solid {BORDER};
}}

QPushButton {{
    background: {BG_RAISED}; border: 1px solid {BORDER}; border-radius: 6px;
    padding: 7px 14px; color: {TEXT};
}}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:disabled {{ color: #5a6472; border-color: {BORDER}; background: #12171f; }}
QPushButton#Primary {{
    background: {ACCENT_DIM}; border: 1px solid {ACCENT}; font-weight: 600; padding: 9px 20px;
}}
QPushButton#Primary:hover {{ background: {ACCENT}; }}
QPushButton#Primary:disabled {{ background: #1a2230; border-color: {BORDER}; color: #5a6472; }}
QPushButton#Danger:hover {{ border-color: {SEVERITY_COLOUR["critical"]}; }}

QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background: {BG_PANEL}; border: 1px solid {BORDER}; border-radius: 6px;
    padding: 6px 8px; selection-background-color: {ACCENT_DIM};
}}
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{ border-color: {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{
    background: {BG_PANEL}; border: 1px solid {BORDER}; selection-background-color: {ACCENT_DIM};
}}

QTableWidget, QTableView {{
    background: {BG_PANEL}; alternate-background-color: #131922; border: 1px solid {BORDER};
    border-radius: 8px; gridline-color: {BORDER}; selection-background-color: {ACCENT_DIM};
}}
QHeaderView::section {{
    background: {BG_RAISED}; color: {TEXT_DIM}; padding: 7px 8px; border: none;
    border-bottom: 1px solid {BORDER}; font-weight: 600;
}}
QTableWidget::item {{ padding: 5px 6px; }}

QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 8px; top: -1px; }}
QTabBar::tab {{
    background: transparent; color: {TEXT_DIM}; padding: 7px 14px; border: 1px solid transparent;
}}
QTabBar::tab:selected {{ color: {TEXT}; border: 1px solid {BORDER}; border-bottom-color: {BG_PANEL};
    border-top-left-radius: 6px; border-top-right-radius: 6px; background: {BG_PANEL}; }}

QProgressBar {{
    background: {BG_PANEL}; border: 1px solid {BORDER}; border-radius: 6px; height: 8px;
    text-align: center; color: transparent;
}}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 5px; }}

QCheckBox {{ spacing: 7px; }}
QCheckBox::indicator {{
    width: 15px; height: 15px; border: 1px solid {BORDER}; border-radius: 4px; background: {BG_PANEL};
}}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QCheckBox:disabled {{ color: #5a6472; }}

QStatusBar {{ background: {BG_PANEL}; border-top: 1px solid {BORDER}; color: {TEXT_DIM}; }}
QSplitter::handle {{ background: {BORDER}; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: #30394a; border-radius: 5px; min-height: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QToolTip {{ background: {BG_RAISED}; color: {TEXT}; border: 1px solid {BORDER}; padding: 5px; }}
"""
