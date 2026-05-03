from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .elfutil import get_needed_libs
from .glibc import GlibcInstall, find_library


def _run_patchelf(args: list[str]):
    result = subprocess.run(
        ["patchelf"] + args,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"patchelf failed: {result.stderr.strip()}")


def _check_patchelf():
    if not shutil.which("patchelf"):
        raise RuntimeError("patchelf not found. Install with: sudo apt install patchelf")


def _copy_lib(src: Path, dst: Path):
    shutil.copy2(src, dst)
    os.chmod(dst, 0o755)


def _collect_extra_libs(binary: Path, glibc: GlibcInstall) -> list[tuple[str, Path]]:
    skip = {"libc.so.6", glibc.ld_path.name}
    if not glibc.new_naming:
        skip.add(f"libc-{glibc.version}.so")
        skip.add(f"ld-{glibc.version}.so")

    needed = get_needed_libs(binary)
    extra = []
    for soname in needed:
        if soname in skip:
            continue
        lib = find_library(glibc, soname)
        if lib:
            extra.append((soname, lib))
    return extra


def patch_copy(binary: Path, glibc: GlibcInstall, set_rpath: bool = True) -> list[Path]:
    _check_patchelf()
    target_dir = binary.parent
    copied_files = []

    libc_copy = f"libc-{glibc.version}.so"
    ld_copy = f"ld-{glibc.version}.so"

    _copy_lib(glibc.libc_path, target_dir / libc_copy)
    _copy_lib(glibc.ld_path, target_dir / ld_copy)
    copied_files.extend([target_dir / libc_copy, target_dir / ld_copy])

    extra = _collect_extra_libs(binary, glibc)
    for soname, lib_path in extra:
        copy_name = lib_path.name
        _copy_lib(lib_path, target_dir / copy_name)
        copied_files.append(target_dir / copy_name)

    _run_patchelf([
        "--replace-needed", "libc.so.6", f"./{libc_copy}", str(binary),
    ])
    _run_patchelf(["--set-interpreter", f"./{ld_copy}", str(binary)])

    for soname, lib_path in extra:
        _run_patchelf([
            "--replace-needed", soname, f"./{lib_path.name}", str(binary),
        ])

    if set_rpath:
        _run_patchelf(["--set-rpath", ".", str(binary)])

    return copied_files


def patch_inplace(binary: Path, glibc: GlibcInstall, set_rpath: bool = True):
    _check_patchelf()

    interp = str(glibc.ld_path.resolve())
    _run_patchelf(["--set-interpreter", interp, str(binary)])

    if set_rpath:
        _run_patchelf(["--set-rpath", str(glibc.lib_dir), str(binary)])
