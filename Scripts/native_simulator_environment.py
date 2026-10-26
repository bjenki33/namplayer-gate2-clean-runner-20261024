"""Stable OS-account context for public Xcode/CoreSimulator operations."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import stat
from typing import Mapping


# Public <unistd.h> selector; system Python omits its symbolic confstr name.
DARWIN_USER_TEMP_DIR = 65537
COMPILER_ISOLATION_KEYS = frozenset({
    "XDG_CACHE_HOME",
    "CLANG_MODULE_CACHE_PATH",
    "SWIFTPM_MODULECACHE_OVERRIDE",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_ATTR_NOSYSTEM",
})


def native_environment(
    developer_dir: Path,
    isolated_environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Resolve native HOME/temp from the OS rather than inherited overrides.

    Compiler cache paths may be carried from an already private build context.
    Arbitrary process environment and CFFIXED_USER_HOME never pass through.
    """

    try:
        uid = os.geteuid()
        account = pwd.getpwuid(uid)
        temporary = os.confstr(DARWIN_USER_TEMP_DIR)
        if uid == 0 or account.pw_uid != uid:
            raise RuntimeError("native Simulator account identity mismatch")
        home = account.pw_dir
        if any(
            not isinstance(value, str) or not value or any(c in value for c in "\0\r\n")
            for value in (home, temporary)
        ):
            raise RuntimeError("native Simulator directories unavailable")
        for value in (home, temporary):
            path = Path(value)
            if not path.is_absolute() or path.resolve(strict=True) == Path("/var/empty").resolve():
                raise RuntimeError("native Simulator directories invalid")
            metadata = path.stat()
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or metadata.st_mode & 0o022:
                raise RuntimeError("native Simulator directory ownership invalid")
        if not developer_dir.is_absolute() or not developer_dir.is_dir():
            raise RuntimeError("native Simulator developer directory invalid")
    except (OSError, KeyError, ValueError) as error:
        raise RuntimeError("native Simulator context unavailable") from error

    result = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "DEVELOPER_DIR": str(developer_dir),
        "HOME": home,
        "TMPDIR": temporary,
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if isolated_environment is not None:
        for key in COMPILER_ISOLATION_KEYS:
            if key in isolated_environment:
                value = isolated_environment[key]
                if not isinstance(value, str) or not value or any(c in value for c in "\0\r\n"):
                    raise RuntimeError("compiler isolation context invalid")
                result[key] = value
    return result
