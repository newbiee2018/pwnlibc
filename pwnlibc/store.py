"""Persistent install database — the single source of truth for what is
installed, mirroring the apt model:

  download/build/setup  -> write records (like `apt install` writing to the
                           dpkg status database)
  remove / source remove-> delete records (like `apt remove`)
  list / verify         -> read records (verify checks the exact .deb that
                           was installed, not today's mirror state)

The database lives at <glibc-dir>/.install-db.json and is maintained
automatically. Installs made before the database existed (or by hand) are
adopted on discovery with unknown origin, so the file converges to the
truth without a migration step.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

DB_FILENAME = ".install-db.json"
DB_FORMAT = 1


@dataclass
class InstallRecord:
    version: str
    arch: str
    variant: str                 # "deb" or "built"
    mirror: str | None = None    # mirror the deb came from; None = unknown/built/imported
    filename: str | None = None  # libc6 .deb filename (deb variant)
    full_id: str | None = None   # e.g. "2.28-0ubuntu1_amd64"
    dbg_filename: str | None = None
    has_dbg: bool = False
    installed_at: str = ""       # ISO timestamp

    def key(self) -> tuple:
        return (self.version, self.arch, self.variant)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class InstallStore:
    """CRUD access to the install database. Tolerant by design: a missing or
    corrupt file behaves like an empty database (a fresh one is written on
    the next save), never as an error."""

    def __init__(self, glibc_dir: Path):
        self.path = Path(glibc_dir) / DB_FILENAME
        self._installs: dict[tuple, InstallRecord] = {}
        self._sources: set[str] = set()
        self._load()

    # -- persistence -------------------------------------------------------

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            # Corrupt database: keep it aside and start fresh rather than
            # refusing to work; the next save rewrites it.
            try:
                self.path.rename(self.path.with_suffix(".json.bak"))
            except OSError:
                pass
            return
        for raw in data.get("installs", []):
            try:
                rec = InstallRecord(**{k: v for k, v in raw.items()
                                       if k in InstallRecord.__dataclass_fields__})
                self._installs[rec.key()] = rec
            except TypeError:
                continue
        self._sources = {str(v) for v in data.get("sources", [])}

    def save(self) -> None:
        payload = {
            "version": DB_FORMAT,
            "installs": [asdict(r) for r in sorted(self._installs.values(),
                                                   key=lambda r: r.key())],
            "sources": sorted(self._sources),
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            # Read-only glibc dir etc: the database is an index, not the
            # data itself — degrade silently rather than failing a command.
            pass

    # -- install records ---------------------------------------------------

    def all(self) -> list[InstallRecord]:
        return list(self._installs.values())

    def get(self, version: str, arch: str, variant: str) -> InstallRecord | None:
        return self._installs.get((version, arch, variant))

    def upsert(self, record: InstallRecord) -> None:
        if not record.installed_at:
            record.installed_at = _now()
        self._installs[record.key()] = record

    def remove(self, version: str, arch: str | None = None,
               variant: str | None = None) -> int:
        """Delete matching records; returns how many were removed."""
        doomed = [k for k in self._installs
                  if k[0] == version
                  and (arch is None or k[1] == arch)
                  and (variant is None or k[2] == variant)]
        for k in doomed:
            del self._installs[k]
        return len(doomed)

    # -- source records ----------------------------------------------------

    def has_source(self, version: str) -> bool:
        return version in self._sources

    def add_source(self, version: str) -> None:
        self._sources.add(version)

    def remove_source(self, version: str) -> bool:
        if version in self._sources:
            self._sources.discard(version)
            return True
        return False

    def sources(self) -> set[str]:
        return set(self._sources)
