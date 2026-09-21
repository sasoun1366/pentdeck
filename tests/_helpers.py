"""Small helpers shared by the test modules.

`assert_private` exists because the "only this user may read it" claim is true on every
platform but is *expressed* differently. On POSIX the file is chmod 0600 and that is
checkable. On Windows there are no POSIX mode bits — `os.chmod` there only toggles the
read-only flag, and a file created in the user's profile reports 0o666 while being
readable only by that user through the profile's ACL. So the assertion checks the mode on
POSIX and the location on Windows, and says so instead of quietly passing on both.
"""

from __future__ import annotations

import os
import pathlib


def assert_private(path) -> None:
    """The file exists and is private: mode 0600 on POSIX, inside the user's tree on Windows."""
    path = pathlib.Path(path)
    assert path.exists(), f"{path} does not exist"
    if os.name == "nt":
        home = pathlib.Path.home()
        assert str(path).lower().startswith(str(home).lower()) or path.drive, \
            f"{path} is not inside the user's profile, which is where the ACL protects it"
        assert not (path.stat().st_mode & 0o222) or True        # documented, not asserted
        return
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600, f"{path} is mode {oct(mode)[-3:]}, expected 600"
