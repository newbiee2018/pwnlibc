"""Repair file ownership after privileged (sudo) writes.

``sudo pwnlibc download ...`` writes root-owned files into a user-owned
glibc dir; every later unprivileged command then dies on the first
permission error. These helpers hand the tree back to the invoking user
(SUDO_USER) right after a privileged command finishes writing.
"""

from __future__ import annotations

import os
import pwd
from pathlib import Path


def invoking_uid_gid() -> tuple[int, int] | None:
    """(uid, gid) of SUDO_USER when running as root under sudo, else None.

    Mirrors the sudo-awareness of config._user_home: an empty or ``root``
    SUDO_USER doesn't count, and a name pwd can't resolve falls back to
    None (the caller then leaves ownership alone).
    """
    sudo_user = os.environ.get("SUDO_USER", "").strip()
    if (
        sudo_user
        and sudo_user != "root"
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
    ):
        try:
            entry = pwd.getpwnam(sudo_user)
        except (KeyError, ValueError):
            return None
        return (entry.pw_uid, entry.pw_gid)
    return None


def chown_tree(path: Path) -> int:
    """lchown every entry under path (plus path itself) to the invoking user.

    Returns the number of entries changed; 0 when not running as root
    under sudo (nothing to repair). Failures on individual entries are
    skipped, not counted, and never fatal.
    """
    uid_gid = invoking_uid_gid()
    if uid_gid is None:
        return 0
    uid, gid = uid_gid

    changed = 0

    def _lchown(entry: str) -> None:
        nonlocal changed
        try:
            os.lchown(entry, uid, gid)
            changed += 1
        except OSError:
            pass  # skip entries we can't chown; never fail the command

    _lchown(path)
    for dirpath, dirnames, filenames in os.walk(path):
        for name in dirnames + filenames:
            _lchown(os.path.join(dirpath, name))
    return changed
