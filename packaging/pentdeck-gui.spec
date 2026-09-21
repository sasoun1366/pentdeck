# PyInstaller spec: the dashboard as a single windowed executable.
#
# Build:  pyinstaller packaging/pentdeck-gui.spec
# Output: dist/pentdeck-gui.exe (Windows) / dist/pentdeck-gui (Linux, macOS)
#
# console=False is the whole reason this spec is separate: a windowed build starts with
# sys.stderr and sys.stdout set to None, and pentdeck/desktop/safety.py is written so
# that nothing touches them. The CI smoke test launches this file with Start-Process —
# the same way a customer double-clicks it — because launching it from a shell hides
# exactly that class of bug.

import sys
from pathlib import Path

SPEC_DIR = Path(SPECPATH)  # noqa: F821 - injected by PyInstaller
REPO_ROOT = SPEC_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

analysis = Analysis(
    [str(SPEC_DIR / "pentdeck_gui_entry.py")],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=["pentdeck.desktop.app", "pentdeck.desktop.main_window"],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "tkinter",
        # Qt ships far more than a dashboard needs. These are the modules this app never
        # imports; leaving them out takes the download from ~68 MB to something a
        # customer on a hotel wi-fi will actually wait for.
        "PyQt6.QtNetwork", "PyQt6.QtQml", "PyQt6.QtQuick", "PyQt6.QtQuickWidgets",
        "PyQt6.QtMultimedia", "PyQt6.QtMultimediaWidgets", "PyQt6.QtWebEngineCore",
        "PyQt6.QtWebEngineWidgets", "PyQt6.QtWebChannel", "PyQt6.QtWebSockets",
        "PyQt6.QtSql", "PyQt6.QtTest", "PyQt6.QtBluetooth", "PyQt6.QtNfc",
        "PyQt6.QtPositioning", "PyQt6.QtSerialPort", "PyQt6.QtSensors",
        "PyQt6.QtCharts", "PyQt6.QtDataVisualization", "PyQt6.QtPdf", "PyQt6.QtPdfWidgets",
        "PyQt6.QtDesigner", "PyQt6.QtHelp", "PyQt6.QtOpenGL",
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
    name="pentdeck-gui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,          # no black window behind the dashboard
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
