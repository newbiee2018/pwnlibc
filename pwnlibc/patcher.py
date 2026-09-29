from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from .elfutil import get_debuglink, get_needed_libs
from .glibc import GlibcInstall, find_library

PATCHED_SUFFIX = ".patched"
PATCHED_MANIFEST_SUFFIX = ".patched.manifest"


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


def _make_patched_copy(binary: Path) -> Path:
    patched = binary.parent / (binary.name + PATCHED_SUFFIX)
    shutil.copy2(binary, patched)
    os.chmod(patched, 0o755)
    return patched


def _find_debug_file(debug_dir: Path, lib: Path) -> Path | None:
    # Ubuntu libc6-dbg names debug files after the build-id hash recorded in
    # the lib's .gnu_debuglink. GDB resolves <binary-dir>/.debug/<debuglink>,
    # so the hash name must be kept verbatim when copying.
    link = get_debuglink(lib)
    if link and (debug_dir / link).is_file():
        return debug_dir / link

    exact = debug_dir / lib.name
    if exact.is_file():
        return exact

    # Legacy prefixed debug files. Trailing dash: "libc-" must not match
    # libcidn-/libcrypt-, "libm-" must not match libmvec-/libmemusage.
    prefix = lib.name.split("-")[0] + "-"
    for candidate in sorted(debug_dir.iterdir()):
        if candidate.is_file() and candidate.name.startswith(prefix):
            return candidate
    return None


def _copy_debug_files(glibc: GlibcInstall, copied_libs: list[Path], target_dir: Path) -> list[str]:
    """Copy matching debug files; return their paths relative to target_dir."""
    debug_dir = glibc.lib_dir / ".debug"
    if not debug_dir.is_dir():
        return []
    target_debug = target_dir / ".debug"
    target_debug.mkdir(exist_ok=True)
    copied = []
    for lib in copied_libs:
        dbg_src = _find_debug_file(debug_dir, lib)
        if dbg_src is not None:
            shutil.copy2(dbg_src, target_debug / dbg_src.name)
            copied.append(f".debug/{dbg_src.name}")
    return copied


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


def patch_copy(binary: Path, glibc: GlibcInstall, set_rpath: bool = True) -> tuple[Path, list[Path]]:
    _check_patchelf()
    patched = _make_patched_copy(binary)
    target_dir = patched.parent
    copied_files = []

    libc_copy = f"libc-{glibc.version}.so"
    ld_copy = f"ld-{glibc.version}.so"

    _copy_lib(glibc.libc_path, target_dir / libc_copy)
    _copy_lib(glibc.ld_path, target_dir / ld_copy)
    copied_files.extend([target_dir / libc_copy, target_dir / ld_copy])

    extra = _collect_extra_libs(patched, glibc)
    extra_names = []
    for soname, lib_path in extra:
        copy_name = lib_path.name
        _copy_lib(lib_path, target_dir / copy_name)
        copied_files.append(target_dir / copy_name)
        extra_names.append(copy_name)

    debug_files = _copy_debug_files(glibc, copied_files, target_dir)

    # Record every file we created next to the binary (keyed on the ORIGINAL
    # binary name, not the .patched copy) so `pwnlibc restore` can remove
    # exactly these and nothing else. Written before the patchelf calls: a
    # mid-patch failure still leaves a consumable cleanup record, and
    # re-patching simply overwrites it with the new list.
    manifest_files = [libc_copy, ld_copy] + extra_names + debug_files
    manifest_path = binary.parent / (binary.name + PATCHED_MANIFEST_SUFFIX)
    manifest_path.write_text(json.dumps({"files": manifest_files}, indent=1) + "\n")

    # Order matters: rpath first, then replace-needed, interpreter last.
    # Reversing this causes "Loadable section outside of ELF segments" in GDB.
    if set_rpath:
        _run_patchelf(["--set-rpath", ".", str(patched)])

    _run_patchelf([
        "--replace-needed", "libc.so.6", libc_copy, str(patched),
    ])
    for soname, lib_path in extra:
        _run_patchelf([
            "--replace-needed", soname, lib_path.name, str(patched),
        ])

    _run_patchelf(["--set-interpreter", f"./{ld_copy}", str(patched)])

    return patched, copied_files


def patch_inplace(binary: Path, glibc: GlibcInstall, set_rpath: bool = True) -> Path:
    _check_patchelf()
    patched = _make_patched_copy(binary)

    # rpath first, interpreter last — avoids patchelf segment corruption
    if set_rpath:
        _run_patchelf(["--set-rpath", str(glibc.lib_dir), str(patched)])

    interp = str(glibc.ld_path.resolve())
    _run_patchelf(["--set-interpreter", interp, str(patched)])

    return patched
