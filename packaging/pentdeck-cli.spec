# PyInstaller spec: the pentdeck command line as a single executable.
#
# Build:  pyinstaller packaging/pentdeck-cli.spec
# Output: dist/pentdeck.exe (Windows) / dist/pentdeck (Linux, macOS)
#
# A console build on purpose: the CLI is run from a terminal, and a pentester wants to
# see the progress of a scan.

import sys
from pathlib import Path

SPEC_DIR = Path(SPECPATH)  # noqa: F821 - injected by PyInstaller
REPO_ROOT = SPEC_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

analysis = Analysis(
    [str(SPEC_DIR / "pentdeck_cli_entry.py")],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        # The dashboard is an optional extra: a CLI build that drags Qt along would be
        # tens of megabytes larger for nothing.
        "PyQt6",
        "PyQt6.QtCore",
        "PyQt6.QtGui",
        "PyQt6.QtWidgets",
        "tkinter",
    ],
    noarchive=False,
)
pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="pentdeck",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
