"""The pentdeck desktop dashboard.

The command line stays the source of truth — everything here goes through the same
modules the CLI uses (`scope`, `license`, `engine`, `report`), so the two front ends can
never disagree about what is allowed. PyQt6 is the only optional dependency; without it
the package still imports and the CLI is unaffected.
"""

from __future__ import annotations

__all__ = ["main", "run_gui"]


def main(argv=None) -> int:                                  # pragma: no cover - thin shim
    """Console-script entry point for ``pentdeck-desktop``."""
    from .app import main as _main

    return _main(argv)


def run_gui(home: str | None = None, start_scan: bool = False) -> int:  # pragma: no cover
    """Launch the dashboard. Imported lazily so PyQt6 stays optional."""
    from .app import run_gui as _run

    return _run(home=home, start_scan=start_scan)
