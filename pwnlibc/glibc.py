from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .config import (
    ALL_ARCHES,
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
    variant: str = "deb"  # "deb", "deb-dbg", "built"


def _find_libc(lib_dir: Path, version: str) -> Path | None:
    for name in [get_libc_real_name(version), "libc.so.6"]:
        p = lib_dir / name
        if p.exists():
            return p.resolve() if p.is_symlink() else p
    return None


def _find_ld(lib_dir: Path, version: str, arch: str) -> Path | None:
    for name in [get_ld_real_name(version, arch), ARCH_INFO[arch]["ld_soname"]]:
        p = lib_dir / name
        if p.exists():
            return p.resolve() if p.is_symlink() else p
    return None


def resolve_lib_paths(version: str, arch: str, glibc_dir: Path,
                      variant: str = "deb") -> GlibcInstall:
    if variant == "built":
        base_dir = glibc_dir / version / f"{arch}-built"
    else:
        base_dir = glibc_dir / version / arch

    lib_dir = base_dir / "lib"

    if not lib_dir.is_dir():
        for alt in [
            base_dir / "usr" / "lib",
            base_dir / glibc_dir.name / version / f"{arch}-built" / "lib",
        ]:
            if alt.is_dir():
                lib_dir = alt
                break
        else:
            raise FileNotFoundError(
                f"Glibc {version} ({arch}, {variant}) not found at {lib_dir}. "
                f"Run: pwnlibc download {version}"
            )

    libc_path = _find_libc(lib_dir, version)
    if libc_path is None:
        raise FileNotFoundError(f"libc not found in {lib_dir}")

    ld_path = _find_ld(lib_dir, version, arch)
    if ld_path is None:
        raise FileNotFoundError(f"ld not found in {lib_dir}")

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
        variant=variant,
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

        for arch in ALL_ARCHES:
            # Standard deb install
            try:
                install = resolve_lib_paths(version_dir.name, arch, glibc_dir, "deb")
                installs.append(install)
            except FileNotFoundError:
                pass

            # Source-built install
            built_dir = version_dir / f"{arch}-built"
            if built_dir.is_dir():
                try:
                    install = resolve_lib_paths(version_dir.name, arch, glibc_dir, "built")
                    installs.append(install)
                except FileNotFoundError:
                    pass

    return installs


def get_debug_build_path(glibc: GlibcInstall) -> str | None:
    import re
    for path in [glibc.lib_dir / ".debug" / glibc.libc_path.name, glibc.libc_path]:
        if not path.exists():
            continue
        try:
            with open(path, "rb") as f:
                data = f.read()
            m = re.search(rb"/build/glibc-[^/]+/glibc-" + glibc.version.encode(), data)
            if m:
                return m.group(0).decode("ascii")
        except Exception:
            continue
    return None


def find_library(glibc: GlibcInstall, soname: str) -> Path | None:
    direct = glibc.lib_dir / soname
    if direct.exists():
        return direct.resolve()

    base = soname.split(".so")[0]
    for f in glibc.lib_dir.iterdir():
        if f.name.startswith(base) and f.name.endswith(".so") and f.is_file():
            return f
    return None
