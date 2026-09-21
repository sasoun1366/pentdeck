"""Frozen-build entry point for the desktop dashboard.

Nothing may be imported from `pentdeck.desktop` before the safety net is installed:
that is the whole point of `run_gui`, and this file deliberately does nothing else.
"""

from pentdeck.desktop import run_gui

if __name__ == "__main__":
    raise SystemExit(run_gui())
