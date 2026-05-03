from __future__ import annotations

import shutil
from pathlib import Path

from .config import BACKUP_SUFFIX


def create_backup(binary: Path) -> Path:
    backup_path = binary.parent / (binary.name + BACKUP_SUFFIX)
    if backup_path.exists():
        i = 1
        while True:
            numbered = binary.parent / f"{binary.name}{BACKUP_SUFFIX}.{i}"
            if not numbered.exists():
                backup_path = numbered
                break
            i += 1
    shutil.copy2(binary, backup_path)
    return backup_path


def restore_backup(binary: Path) -> Path | None:
    base = binary.parent / (binary.name + BACKUP_SUFFIX)

    # Find the highest-numbered backup (.bak.N), or fall back to .bak
    latest = None
    i = 1
    while True:
        numbered = binary.parent / f"{binary.name}{BACKUP_SUFFIX}.{i}"
        if not numbered.exists():
            break
        latest = numbered
        i += 1

    if latest is None:
        if not base.exists():
            return None
        latest = base

    shutil.copy2(latest, binary)
    removed = latest
    latest.unlink()
    return removed
