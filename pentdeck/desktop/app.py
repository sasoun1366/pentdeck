"""Entry point for the dashboard.

:func:`prepare_runtime` is split out from :func:`run_gui` so it can be tested where it
actually has to work: a packaged build with no console at all. Everything above the first
window is written so that a failure there still leaves a readable file behind instead of a
process that vanishes.
"""

from __future__ import annotations

import logging
import os
import pathlib
import sys
from typing import Optional

from .safety import (install_crash_handler, install_exception_hook, install_logging,
                     write_fatal)

log = logging.getLogger("pentdeck.desktop")


def default_home() -> pathlib.Path:
    override = os.environ.get("PENTDECK_HOME", "").strip()
    return pathlib.Path(override) if override else pathlib.Path.home() / ".pentdeck"


def prepare_runtime(home: str | pathlib.Path | None = None) -> pathlib.Path:
    """Everything that must be true before a window can exist. Returns the log path."""
    directory = pathlib.Path(home) if home else default_home()
    directory.mkdir(parents=True, exist_ok=True)
    log_file = install_logging(directory)
    install_crash_handler(directory)
    install_exception_hook(directory)
    log.info("pentdeck desktop starting (home=%s, log=%s)", directory, log_file)
    return log_file


def run_gui(home: Optional[str] = None, start_scan: bool = False,
            argv: Optional[list] = None) -> int:
    """Launch the dashboard. Returns the process exit code."""
    directory = pathlib.Path(home) if home else default_home()
    try:
        prepare_runtime(directory)
    except Exception as exc:                                  # noqa: BLE001 - no window yet
        path = write_fatal(exc, directory)
        target = sys.stderr or sys.stdout
        if target is not None:
            print(f"pentdeck could not start: {exc!r}", file=target)
            if path is not None:
                print(f"the details are in {path}", file=target)
        return 4

    try:
        from PyQt6.QtWidgets import QApplication, QMessageBox
    except ImportError as exc:                                 # pragma: no cover - extras
        target = sys.stderr or sys.stdout
        if target is not None:
            print('pentdeck desktop needs PyQt6 — install it with: pip install "pentdeck[desktop]"',
                  file=target)
            print(f"({exc})", file=target)
        return 2

    from .theme import STYLESHEET

    arguments = list(argv) if argv is not None else sys.argv[:1]
    if not arguments:
        arguments = ["pentdeck"]
    application = QApplication(arguments)
    application.setApplicationName("pentdeck")
    application.setApplicationDisplayName("pentdeck")
    application.setStyleSheet(STYLESHEET)

    from .main_window import MainWindow
    from .. import __version__

    try:
        window = MainWindow(directory)
    except Exception as exc:                                   # noqa: BLE001
        path = write_fatal(exc, directory)
        log.exception("the window could not be built")
        QMessageBox.critical(
            None, "pentdeck could not start",
            f"{type(exc).__name__}: {exc}\n\n" + (f"Details: {path}" if path else ""),
        )
        return 4

    if start_scan:
        window._show("scan")
    window.show()
    log.info("window shown (version %s)", __version__)
    return application.exec()


def main(argv: Optional[list] = None) -> int:
    """``pentdeck-desktop``: launch the dashboard."""
    parser_argv = sys.argv[1:] if argv is None else list(argv)
    home: Optional[str] = None
    if "--home" in parser_argv:
        try:
            home = parser_argv[parser_argv.index("--home") + 1]
        except IndexError:
            home = None
    return run_gui(home=home)
