"""Keep an unexpected error from taking the whole dashboard down.

PyQt turns an unhandled exception inside a slot into ``qFatal()``. In a windowed build
there is no console, so the traceback goes nowhere and the user sees "it froze".

**Nothing in this module may write to ``sys.stdout`` / ``sys.stderr``.** A windowed build
(``console=False``) starts with both set to ``None``; anything that touches them raises
``RuntimeError`` — including ``faulthandler.enable()`` with no argument — before a window
exists, so the app dies silently. That is a real regression netpilot shipped once, and the
fix is copied here on purpose.
"""

from __future__ import annotations

import faulthandler
import functools
import logging
import logging.handlers
import sys
import traceback
from pathlib import Path
from typing import Any, Callable, TypeVar

log = logging.getLogger("pentdeck.desktop")

F = TypeVar("F", bound=Callable[..., Any])

LOG_NAME = "pentdeck-desktop.log"
CRASH_LOG_NAME = "pentdeck-crash.log"
FATAL_LOG_NAME = "pentdeck-fatal.log"


def data_dir(data_dir_: str | Path | None = None) -> Path:
    """Where the logs go: the same state directory the CLI uses."""
    if data_dir_:
        return Path(data_dir_)
    import os

    override = os.environ.get("PENTDECK_HOME", "").strip()
    return Path(override) if override else Path.home() / ".pentdeck"


def log_path(home: str | Path | None = None) -> Path:
    return data_dir(home) / LOG_NAME


def crash_log_path(home: str | Path | None = None) -> Path:
    return data_dir(home) / CRASH_LOG_NAME


def fatal_log_path(home: str | Path | None = None) -> Path:
    return data_dir(home) / FATAL_LOG_NAME


def has_console() -> bool:
    """False in a windowed build — the condition this module keeps tripping over."""
    return sys.stderr is not None


def install_logging(home: str | Path | None = None, level: int = logging.INFO) -> Path:
    """Log to a rotating file next to the rest of the state; never to a stream."""
    path = log_path(home)
    root = logging.getLogger()
    for handler in root.handlers:
        if isinstance(handler, logging.handlers.RotatingFileHandler) and \
                getattr(handler, "baseFilename", None) == str(path.resolve()):
            root.setLevel(level)
            return path
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=1_000_000, backupCount=2, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    except OSError:
        handler = logging.NullHandler()
    root.addHandler(handler)
    root.setLevel(level)
    return path


def install_crash_handler(home: str | Path | None = None) -> Path:
    """Dump Python stacks if the process dies hard, so a freeze leaves evidence."""
    path = crash_log_path(home)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(path, "a", encoding="utf-8")  # noqa: SIM115 - lives for the process
    except OSError:
        return path
    try:
        # The file argument matters: without it faulthandler reaches for sys.stderr.
        faulthandler.enable(file=handle, all_threads=True)
    except (RuntimeError, ValueError, OSError):
        pass
    return path


def write_fatal(exc: BaseException, home: str | Path | None = None) -> Path | None:
    """Write a failure to disk when logging is not up yet (or is not working)."""
    path = fatal_log_path(home)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "pentdeck could not start.\n\n"
            + "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
            encoding="utf-8",
        )
        return path
    except OSError:
        return None


def _to_console(previous: Any, exc_type: Any, exc_value: Any, exc_tb: Any) -> None:
    if not has_console():
        return
    try:
        previous(exc_type, exc_value, exc_tb)
    except Exception:  # noqa: BLE001 - a reporter must never be the thing that fails
        pass


def install_exception_hook(home: str | Path | None = None) -> None:
    """Log anything that escapes a Qt callback before Qt decides how to die."""
    previous = sys.excepthook

    def hook(exc_type, exc_value, exc_tb):  # type: ignore[no-untyped-def]
        if issubclass(exc_type, KeyboardInterrupt):
            _to_console(previous, exc_type, exc_value, exc_tb)
            return
        log.critical("unhandled exception", exc_info=(exc_type, exc_value, exc_tb))
        _to_console(previous, exc_type, exc_value, exc_tb)

    sys.excepthook = hook


def safe_slot(func: F) -> F:
    """Wrap a Qt slot so an error is reported instead of aborting the process."""

    @functools.wraps(func)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return func(self, *args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - the last line of defence
            log.exception("error in %s", getattr(func, "__qualname__", func))
            write_fatal(exc, getattr(self, "_home", None))
            status = getattr(self, "status", None)
            if status is not None:
                try:
                    status.showMessage(f"{type(exc).__name__}: {exc}  (see pentdeck-desktop.log)", 15000)
                except Exception:  # noqa: BLE001
                    pass
            return None

    return wrapper  # type: ignore[return-value]
