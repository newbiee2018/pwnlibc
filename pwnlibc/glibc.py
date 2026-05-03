from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import (
    ARCH_INFO,
    get_ld_real_name,
    get_libc_real_name,
    parse_version,
    uses_new_naming,
)
from .elfutil import has_debug_info


@dataclass
class GlibcInstall:
    version: str
    arch: str
    base_dir: Path
    lib_dir: Path
    libc_path: Path
    ld_path: Path
    has_source: bool
    has_debug: bool
    new_naming: bool


def resolve_lib_paths(version: str, arch: str, glibc_dir: Path) -> GlibcInstall:
    base_dir = glibc_dir / version / arch
    lib_dir = base_dir / "lib"
    if not lib_dir.is_dir():
        raise FileNotFoundError(
            f"Glibc {version} ({arch}) not found at {lib_dir}. "
            f"Run: pwnlibc download {version}"
        )

    libc_name = get_libc_real_name(version)
    ld_name = get_ld_real_name(version, arch)

    libc_path = lib_dir / libc_name
    ld_path = lib_dir / ld_name

    if not libc_path.exists():
        alt_libc = lib_dir / "libc.so.6"
        if alt_libc.exists():
            libc_path = alt_libc.resolve()
        else:
            raise FileNotFoundError(f"libc not found: tried {libc_path} and {alt_libc}")

    if not ld_path.exists():
        alt_ld = lib_dir / ARCH_INFO[arch]["ld_soname"]
        if alt_ld.exists():
            ld_path = alt_ld.resolve()
        else:
            raise FileNotFoundError(f"ld not found: tried {ld_path} and {alt_ld}")

    source_dir = glibc_dir / version / "source"
    debug_dir = lib_dir / ".debug"
    has_dbg = debug_dir.is_dir() or has_debug_info(libc_path)

    return GlibcInstall(
        version=version,
        arch=arch,
        base_dir=base_dir,
        lib_dir=lib_dir,
        libc_path=libc_path,
        ld_path=ld_path,
        has_source=source_dir.is_dir(),
        has_debug=has_dbg,
        new_naming=uses_new_naming(version),
    )


def discover_installed(glibc_dir: Path) -> list[GlibcInstall]:
    if not glibc_dir.is_dir():
        return []

    installs = []
    for version_dir in sorted(glibc_dir.iterdir()):
        if not version_dir.is_dir() or version_dir.name.startswith("."):
            continue
        try:
            parse_version(version_dir.name)
        except (ValueError, IndexError):
            continue

        for arch in ("amd64", "i686"):
            try:
                install = resolve_lib_paths(version_dir.name, arch, glibc_dir)
                installs.append(install)
            except FileNotFoundError:
                continue

    return installs


def find_library(glibc: GlibcInstall, soname: str) -> Path | None:
    direct = glibc.lib_dir / soname
    if direct.exists():
        return direct.resolve()

    base = soname.split(".so")[0]
    for f in glibc.lib_dir.iterdir():
        if f.name.startswith(base) and f.name.endswith(".so") and f.is_file():
            return f
    return None
