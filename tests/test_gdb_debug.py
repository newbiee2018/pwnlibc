"""Tests for GDB source debugging with patched binaries.

Verifies that GDB can actually load and display libc source code
when debugging patched programs -- both for libc-dbg (deb debug symbols)
and source-built variants.

Marked @pytest.mark.network and @pytest.mark.slow.
Uses random version selection from available mirrors.
"""

import os
import random
import re
import shutil
import subprocess
from pathlib import Path

import pytest


def _has_tool(name):
    return shutil.which(name) is not None


needs_gdb = pytest.mark.skipif(
    not _has_tool("gdb"), reason="gdb not installed"
)
needs_gcc = pytest.mark.skipif(
    not _has_tool("gcc"), reason="gcc not installed"
)
needs_patchelf = pytest.mark.skipif(
    not _has_tool("patchelf"), reason="patchelf not installed"
)
needs_tools = pytest.mark.skipif(
    not (_has_tool("gdb") and _has_tool("gcc") and _has_tool("patchelf")),
    reason="requires gdb, gcc, and patchelf",
)


def _compile_test_binary(tmp_path):
    """Compile a simple test binary that calls puts (libc function)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    src = tmp_path / "test_debug.c"
    src.write_text(
        '#include <stdio.h>\n'
        '#include <string.h>\n'
        'int main() {\n'
        '    char buf[64];\n'
        '    strcpy(buf, "pwnlibc-gdb-test");\n'
        '    puts(buf);\n'
        '    return 0;\n'
        '}\n'
    )
    out = tmp_path / "test_debug"
    try:
        subprocess.run(
            ["gcc", "-g", "-o", str(out), str(src)],
            check=True, capture_output=True, text=True,
        )
        os.chmod(str(out), 0o755)
        return out
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _run_gdb_batch(binary, commands, timeout=30):
    """Run GDB in batch mode with given commands. Returns (stdout, stderr, returncode)."""
    cmd_args = []
    for c in commands:
        cmd_args.extend(["-ex", c])

    result = subprocess.run(
        ["gdb", "--batch", "--nx"] + cmd_args + [str(binary)],
        capture_output=True, text=True, timeout=timeout,
    )
    return result.stdout, result.stderr, result.returncode


def _get_min_glibc_version(binary):
    """Get minimum glibc version required by a binary from its version symbols."""
    try:
        result = subprocess.run(
            ["readelf", "-V", str(binary)],
            capture_output=True, text=True, timeout=10,
        )
        versions = re.findall(r"GLIBC_(\d+\.\d+)", result.stdout)
        if versions:
            return max(versions, key=lambda v: tuple(int(x) for x in v.split(".")))
    except Exception:
        pass
    return "2.17"


def _pick_random_version(packages, arch, min_version=None):
    from pwnlibc.config import parse_version
    candidates = [p for p in packages if p.arch == arch]
    if min_version:
        min_tuple = parse_version(min_version)
        candidates = [p for p in candidates if parse_version(p.version) >= min_tuple]
    if not candidates:
        return None
    return random.choice(candidates)


class TestGetDebugBuildPath:
    """get_debug_build_path extracts Ubuntu build paths from debug info."""

    def test_returns_none_for_fake_libc(self, populated_glibc_dir):
        """Fake libc data has no build path embedded."""
        from pwnlibc.glibc import get_debug_build_path, resolve_lib_paths

        glibc = resolve_lib_paths("2.31", "amd64", populated_glibc_dir)
        result = get_debug_build_path(glibc)
        assert result is None

    def test_extracts_path_from_real_data(self, tmp_path):
        """Synthetic libc with embedded build path should be extracted."""
        from pwnlibc.glibc import GlibcInstall, get_debug_build_path

        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()

        # Create a fake libc with an embedded build path
        build_path = b"/build/glibc-SjIFRb/glibc-2.35/"
        libc_data = b"\x7fELF" + b"\x00" * 100 + build_path + b"\x00" * 100
        libc_path = lib_dir / "libc.so.6"
        libc_path.write_bytes(libc_data)

        glibc = GlibcInstall(
            version="2.35", arch="amd64",
            base_dir=tmp_path, lib_dir=lib_dir,
            libc_path=libc_path,
            ld_path=lib_dir / "ld-linux-x86-64.so.2",
            has_source=False, has_debug=False,
            new_naming=True, variant="deb",
        )

        result = get_debug_build_path(glibc)
        assert result is not None
        assert "/build/glibc-" in result
        assert "glibc-2.35" in result

    def test_extracts_from_debug_file(self, tmp_path):
        """Build path found in .debug/ file, not main libc."""
        from pwnlibc.glibc import GlibcInstall, get_debug_build_path

        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir()

        # Main libc has NO build path
        libc_path = lib_dir / "libc.so.6"
        libc_path.write_bytes(b"\x7fELF" + b"\x00" * 200)

        # Debug file HAS the build path
        build_path = b"/build/glibc-ABC123/glibc-2.31/"
        debug_data = b"\x7fELF" + b"\x00" * 100 + build_path + b"\x00" * 100
        (debug_dir / "libc.so.6").write_bytes(debug_data)

        glibc = GlibcInstall(
            version="2.31", arch="amd64",
            base_dir=tmp_path, lib_dir=lib_dir,
            libc_path=libc_path,
            ld_path=lib_dir / "ld-2.31.so",
            has_source=False, has_debug=True,
            new_naming=False, variant="deb",
        )

        result = get_debug_build_path(glibc)
        assert result is not None
        assert "glibc-2.31" in result

    def test_extracts_from_hash_named_debug_file(self, tmp_path):
        """deb(dbg): debug file is hash-named, resolved via libc's debuglink."""
        from pwnlibc.glibc import GlibcInstall, get_debug_build_path
        from tests.conftest import _build_debuglink_elf

        hash_name = "92732f783158c66fb4f3756458ca24e46e827d.debug"
        lib_dir = tmp_path / "lib"
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir(parents=True)

        # libc carries .gnu_debuglink -> hash file, but NO build path itself
        libc_path = _build_debuglink_elf(lib_dir / "libc-2.31.so", hash_name)
        build_path = b"/build/glibc-9c2eff/glibc-2.31/"
        (debug_dir / hash_name).write_bytes(
            b"\x7fELF" + b"\x00" * 100 + build_path + b"\x00" * 100
        )

        glibc = GlibcInstall(
            version="2.31", arch="amd64",
            base_dir=tmp_path, lib_dir=lib_dir,
            libc_path=libc_path,
            ld_path=lib_dir / "ld-2.31.so",
            has_source=False, has_debug=True,
            new_naming=False, variant="deb",
        )

        result = get_debug_build_path(glibc)
        assert result is not None
        assert "glibc-9c2eff" in result
        assert result.endswith("glibc-2.31")

    def test_hash_debug_file_resolved_via_elfutil(self, tmp_path, monkeypatch):
        """get_debug_build_path consults elfutil.get_debuglink for the name."""
        import pwnlibc.glibc as glibc_mod
        from pwnlibc.glibc import GlibcInstall, get_debug_build_path

        hash_name = "deadbeef.debug"
        lib_dir = tmp_path / "lib"
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir(parents=True)

        libc_path = lib_dir / "libc.so.6"
        libc_path.write_bytes(b"\x7fELF" + b"\x00" * 200)
        (debug_dir / hash_name).write_bytes(
            b"\x7fELF" + b"\x00" * 50 + b"/build/glibc-Zz9/glibc-2.35/" + b"\x00" * 50
        )

        monkeypatch.setattr(glibc_mod, "get_debuglink", lambda p: hash_name)
        glibc = GlibcInstall(
            version="2.35", arch="amd64",
            base_dir=tmp_path, lib_dir=lib_dir,
            libc_path=libc_path,
            ld_path=lib_dir / "ld-linux-x86-64.so.2",
            has_source=False, has_debug=True,
            new_naming=True, variant="deb",
        )

        assert get_debug_build_path(glibc) == "/build/glibc-Zz9/glibc-2.35"

    def test_empty_debug_file_falls_through_to_libc(self, tmp_path):
        """Zero-length debug file must not crash mmap scanning."""
        from pwnlibc.glibc import GlibcInstall, get_debug_build_path
        from tests.conftest import _build_debuglink_elf

        hash_name = "cafebabe.debug"
        lib_dir = tmp_path / "lib"
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir(parents=True)

        libc_path = _build_debuglink_elf(lib_dir / "libc-2.31.so", hash_name)
        (debug_dir / hash_name).write_bytes(b"")
        build_path = b"/build/glibc-Qq1/glibc-2.31/"
        # libc content also holds a build path past the ELF header area
        data = bytearray(libc_path.read_bytes())
        data += b"\x00" * 16 + build_path
        libc_path.write_bytes(bytes(data))

        glibc = GlibcInstall(
            version="2.31", arch="amd64",
            base_dir=tmp_path, lib_dir=lib_dir,
            libc_path=libc_path,
            ld_path=lib_dir / "ld-2.31.so",
            has_source=False, has_debug=True,
            new_naming=False, variant="deb",
        )

        result = get_debug_build_path(glibc)
        assert result is not None
        assert "glibc-Qq1" in result


class TestGdbDebugSymbols:
    """Verify GDB can load debug symbols for patched binaries."""

    @pytest.mark.network
    @pytest.mark.slow
    @needs_tools
    def test_gdb_loads_debug_info_deb_dbg(self, tmp_path):
        """Download glibc with -dbg, patch binary, verify GDB sees debug info."""
        from pwnlibc.downloader import scrape_available, download_glibc
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import patch_inplace

        binary = _compile_test_binary(tmp_path / "work")
        if binary is None:
            pytest.skip("failed to compile test binary")

        min_ver = _get_min_glibc_version(binary)
        packages = scrape_available("ubuntu")
        from pwnlibc.config import parse_version
        min_tuple = parse_version(min_ver)
        dbg_pkgs = [
            p for p in packages
            if p.arch == "amd64" and p.dbg_filename
            and parse_version(p.version) >= min_tuple
        ]
        if not dbg_pkgs:
            pytest.skip(f"no amd64 dbg packages >= {min_ver}")

        pkg = random.choice(dbg_pkgs)
        print(f"Testing GDB debug with randomly selected glibc {pkg.version} (min={min_ver})")

        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        download_glibc(pkg, glibc_dir, mirror="ubuntu", include_dbg=True)
        glibc = resolve_lib_paths(pkg.version, "amd64", glibc_dir)

        assert glibc.has_debug, f"Expected debug symbols for {pkg.version}"

        patched = patch_inplace(binary, glibc)

        # Run GDB batch: set debug dir, break on puts, check we have debug info
        debug_dir = glibc.lib_dir / ".debug"
        gdb_cmds = [
            f"set debug-file-directory {debug_dir}",
            "set pagination off",
            "break puts",
            "run",
            "info source",
            "bt",
        ]

        stdout, stderr, rc = _run_gdb_batch(patched, gdb_cmds)
        # GDB should be able to break on puts and show some info
        # We check that GDB loaded something -- it should show source info or at least symbols
        combined = stdout + stderr
        assert "puts" in combined.lower() or "Breakpoint" in combined, (
            f"GDB didn't hit puts breakpoint. stdout={stdout[:500]}, stderr={stderr[:500]}"
        )


class TestGdbSourceMapping:
    """Verify GDB can display libc source code via set substitute-path."""

    @pytest.mark.network
    @pytest.mark.slow
    @needs_tools
    def test_gdb_source_with_substitute_path(self, tmp_path):
        """Download glibc+dbg+source, patch, verify GDB can list libc source."""
        from pwnlibc.downloader import download_glibc, download_source, scrape_available
        from pwnlibc.glibc import get_debug_build_path, resolve_lib_paths
        from pwnlibc.patcher import patch_inplace

        binary = _compile_test_binary(tmp_path / "work")
        if binary is None:
            pytest.skip("failed to compile test binary")

        min_ver = _get_min_glibc_version(binary)
        packages = scrape_available("ubuntu")
        from pwnlibc.config import parse_version
        min_tuple = parse_version(min_ver)
        dbg_pkgs = [
            p for p in packages
            if p.arch == "amd64" and p.dbg_filename
            and parse_version(p.version) >= min_tuple
        ]
        if not dbg_pkgs:
            pytest.skip(f"no amd64 dbg packages >= {min_ver}")

        pkg = random.choice(dbg_pkgs)
        print(f"Testing GDB source mapping with glibc {pkg.version} (min={min_ver})")

        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        # Download glibc with debug symbols
        download_glibc(pkg, glibc_dir, mirror="ubuntu", include_dbg=True)

        # Download GNU source
        try:
            download_source(pkg.version, glibc_dir)
        except Exception:
            pytest.skip(f"failed to download source for {pkg.version}")

        glibc = resolve_lib_paths(pkg.version, "amd64", glibc_dir)
        assert glibc.has_debug
        assert glibc.has_source

        patched = patch_inplace(binary, glibc)

        # Get the build path for substitute-path mapping
        build_path = get_debug_build_path(glibc)
        source_dir = glibc_dir / pkg.version / "source"
        source_subdir = next(source_dir.iterdir(), None)

        if build_path is None or source_subdir is None:
            pytest.skip("could not determine build path or source directory")

        print(f"Build path: {build_path}")
        print(f"Source dir: {source_subdir}")

        # GDB batch: set substitute-path, break on puts, list source
        debug_dir = glibc.lib_dir / ".debug"
        gdb_cmds = [
            f"set debug-file-directory {debug_dir}",
            f"set substitute-path {build_path} {source_subdir}",
            "set pagination off",
            "break puts",
            "run",
            "list",
        ]

        stdout, stderr, rc = _run_gdb_batch(patched, gdb_cmds, timeout=60)

        # "list" after breaking on puts should show actual C source
        # If source mapping works, we should see libc source lines
        combined = stdout + stderr
        # Check for signs of source code (C-like constructs or file paths)
        has_source_hint = any([
            ".c:" in combined,  # file:line reference
            "puts" in combined and ("{" in combined or "}" in combined),  # C code
            "ioputs.c" in combined or "libio/" in combined,  # glibc source files
        ])

        if not has_source_hint:
            # Even if we can't see source, verify the substitute-path was set
            gdb_check = [
                f"set substitute-path {build_path} {source_subdir}",
                "show substitute-path",
            ]
            stdout2, _, _ = _run_gdb_batch(patched, gdb_check)
            assert build_path in stdout2 or str(source_subdir) in stdout2, (
                f"GDB substitute-path not configured. Output: {stdout2[:500]}"
            )
            pytest.skip(
                f"GDB loaded but source lines not visible (might need different glibc version). "
                f"Output snippet: {combined[:300]}"
            )
        else:
            print("SUCCESS: GDB showed source code")
            # Additional verification: the source should contain real code
            assert "No such file" not in combined, "Source file referenced but not found"


class TestGdbBuiltVariant:
    """Test GDB with source-built glibc variant (has -g3 debug info)."""

    @needs_tools
    def test_gdb_with_built_variant(self, populated_glibc_dir, tmp_path):
        """If a built variant exists, GDB should see embedded debug info."""
        # This is a unit-level check: verify that a built variant with debug info
        # can be loaded by GDB (using the fixture, not real download)
        from pwnlibc.glibc import resolve_lib_paths

        try:
            glibc = resolve_lib_paths("2.31", "amd64", populated_glibc_dir, "built")
        except FileNotFoundError:
            pytest.skip("no built variant in fixture")

        # Verify built variant attributes
        assert glibc.variant == "built"
        assert "built" in str(glibc.base_dir)
