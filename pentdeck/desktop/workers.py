"""The scan thread.

A Qt window that blocks while 41 ports are probed on 200 hosts is a window the operator
will kill mid-scan — and a half-finished scan in a report is worse than no scan. So the
engine runs in a ``QThread`` and reports through signals; the UI thread only ever draws.

The scan itself is :func:`pentdeck.engine.run_scan` — the same function the CLI calls,
with the same scope check, the same licence gate and the same audit trail. Nothing about
being graphical makes the rules optional.
"""

from __future__ import annotations

import logging
import pathlib
from typing import Dict, Optional

from PyQt6.QtCore import QThread, pyqtSignal

from ..engine import ScanOptions, run_scan
from ..findings import ScanResult
from ..license import License
from ..scope import Scope

log = logging.getLogger("pentdeck.desktop")


class ScanWorker(QThread):
    """Runs one scan. Emits progress, then exactly one of done/failed."""

    progress = pyqtSignal(str, dict)
    done = pyqtSignal(object)          # ScanResult
    failed = pyqtSignal(str)

    def __init__(self, scope: Scope, license_: License, options: ScanOptions,
                 home: pathlib.Path, parent=None) -> None:
        super().__init__(parent)
        self._scope = scope
        self._license = license_
        self._options = options
        self._home = home
        self._stop = False

    def stop(self) -> None:
        """Ask the engine to wind up. It finishes the host it is on, then returns."""
        self._stop = True

    def should_stop(self) -> bool:
        return self._stop

    def _emit_progress(self, event: str, fields: Dict[str, object]) -> None:
        # A plain dict crosses threads safely; the signal carries it to the UI thread.
        self.progress.emit(event, dict(fields))

    def run(self) -> None:                                    # noqa: D401 - Qt entry point
        try:
            result: Optional[ScanResult] = run_scan(
                self._scope, self._license, self._options, self._home,
                progress=self._emit_progress, should_stop=self.should_stop,
            )
        except Exception as exc:                              # noqa: BLE001 - report, do not vanish
            log.exception("scan failed")
            self.failed.emit(f"{type(exc).__name__}: {exc}")
            return
        if result is not None:
            self.done.emit(result)
