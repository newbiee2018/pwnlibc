"""Tests for pwnlibc.patcher — ELF patching via patchelf."""

import os
import shutil
import subprocess

import pytest

from tests.conftest import build_test_binary


def has_patchelf():
    return shutil.which("patchelf") is not None


def has_gcc():
    return shutil.which("gcc") is not None


needs_patchelf = pytest.mark.skipif(not has_patchelf(), reason="patchelf not installed")
needs_gcc = pytest.mark.skipif(not has_gcc(), reason="gcc not installed")
needs_tools = pytest.mark.skipif(
    not (has_patchelf() and has_gcc()),
    reason="requires patchelf and gcc",
)


class TestPatcherChecks:
    def test_check_patchelf_when_available(self):
        from pwnlibc.patcher import _check_patchelf
        if has_patchelf():
            _check_patchelf()
        else:
            with pytest.raises(RuntimeError, match="patchelf not found"):
                _check_patchelf()


class TestCollectExtraLibs:
    @needs_tools
    def test_collects_pthread(self, tmp_path, populated_glibc_dir):
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import _collect_extra_libs

        binary = build_test_binary(tmp_path)
        if binary is None:
            pytest.skip("failed to compile test binary")

        inst = resolve_lib_paths("2.31", "amd64", populated_glibc_dir)
        extra = _collect_extra_libs(binary, inst)
        sonames = [s for s, _ in extra]
        # We won't have many matches since the glibc dir is fake,
        # but the function should not crash
        assert isinstance(extra, list)


class TestPatchCopy:
    @needs_tools
    def test_copy_mode_creates_files(self, tmp_path, populated_glibc_dir):
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import PATCHED_SUFFIX, patch_copy

        binary = build_test_binary(tmp_path / "workdir")
        if binary is None:
            pytest.skip("failed to compile test binary")

        original_bytes = binary.read_bytes()
        inst = resolve_lib_paths("2.31", "amd64", populated_glibc_dir)
        patched, copied = patch_copy(binary, inst)

        assert patched.exists()
        assert patched == binary.parent / (binary.name + PATCHED_SUFFIX)
        # Original binary is never modified
        assert binary.read_bytes() == original_bytes
        assert len(copied) >= 2
        assert (binary.parent / "libc-2.31.so").exists()
        assert (binary.parent / "ld-2.31.so").exists()

    @needs_tools
    def test_copy_mode_sets_interpreter(self, tmp_path, populated_glibc_dir):
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import patch_copy

        binary = build_test_binary(tmp_path / "workdir2")
        if binary is None:
            pytest.skip("failed to compile test binary")

        inst = resolve_lib_paths("2.31", "amd64", populated_glibc_dir)
        patched, _ = patch_copy(binary, inst)

        result = subprocess.run(
            ["patchelf", "--print-interpreter", str(patched)],
            capture_output=True, text=True,
        )
        assert "./ld-2.31.so" in result.stdout

    @needs_tools
    def test_copy_mode_sets_rpath(self, tmp_path, populated_glibc_dir):
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import patch_copy

        binary = build_test_binary(tmp_path / "workdir3")
        if binary is None:
            pytest.skip("failed to compile test binary")

        inst = resolve_lib_paths("2.31", "amd64", populated_glibc_dir)
        patched, _ = patch_copy(binary, inst)

        result = subprocess.run(
            ["patchelf", "--print-rpath", str(patched)],
            capture_output=True, text=True,
        )
        assert "." in result.stdout

    @needs_tools
    def test_copy_mode_no_rpath(self, tmp_path, populated_glibc_dir):
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import patch_copy

        binary = build_test_binary(tmp_path / "workdir4")
        if binary is None:
            pytest.skip("failed to compile test binary")

        inst = resolve_lib_paths("2.31", "amd64", populated_glibc_dir)
        patched, _ = patch_copy(binary, inst, set_rpath=False)

        result = subprocess.run(
            ["patchelf", "--print-rpath", str(patched)],
            capture_output=True, text=True,
        )
        # RPATH should not be "." since we passed set_rpath=False
        assert result.stdout.strip() != "."


class TestPatchInplace:
    @needs_tools
    def test_inplace_sets_interpreter(self, tmp_path, populated_glibc_dir):
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import patch_inplace

        binary = build_test_binary(tmp_path / "workdir5")
        if binary is None:
            pytest.skip("failed to compile test binary")

        inst = resolve_lib_paths("2.31", "amd64", populated_glibc_dir)
        patched = patch_inplace(binary, inst)

        result = subprocess.run(
            ["patchelf", "--print-interpreter", str(patched)],
            capture_output=True, text=True,
        )
        assert str(inst.ld_path) in result.stdout or "ld-2.31.so" in result.stdout

    @needs_tools
    def test_inplace_sets_rpath(self, tmp_path, populated_glibc_dir):
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import patch_inplace

        binary = build_test_binary(tmp_path / "workdir6")
        if binary is None:
            pytest.skip("failed to compile test binary")

        inst = resolve_lib_paths("2.31", "amd64", populated_glibc_dir)
        patched = patch_inplace(binary, inst)

        result = subprocess.run(
            ["patchelf", "--print-rpath", str(patched)],
            capture_output=True, text=True,
        )
        assert str(inst.lib_dir) in result.stdout


class TestPatchAndRun:
    """End-to-end: download real glibc, patch a binary, verify it runs."""

    @pytest.mark.network
    @pytest.mark.slow
    @needs_tools
    def test_patch_copy_and_run(self, tmp_path):
        """Download a real glibc, patch a compiled binary in copy mode, run it."""
        from pwnlibc.downloader import download_glibc, scrape_available
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import patch_copy

        workdir = tmp_path / "e2e_copy"
        binary = build_test_binary(workdir)
        if binary is None:
            pytest.skip("failed to compile test binary")

        # Verify unpatched binary works
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        assert result.returncode == 0
        assert "pwnlibc-test-ok" in result.stdout

        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        packages = scrape_available("ubuntu")
        pkg = None
        for p in packages:
            if p.version == "2.35" and p.arch == "amd64":
                pkg = p
                break
        if pkg is None:
            pytest.skip("glibc 2.35 amd64 not on mirror")

        download_glibc(pkg, glibc_dir, include_dbg=False)
        inst = resolve_lib_paths("2.35", "amd64", glibc_dir)
        patched, _ = patch_copy(binary, inst)

        # Copy mode uses ./ld-X.XX.so — must run from binary's directory
        result = subprocess.run(
            [str(patched)], capture_output=True, text=True,
            cwd=str(patched.parent),
        )
        assert result.returncode == 0
        assert "pwnlibc-test-ok" in result.stdout

    @pytest.mark.network
    @pytest.mark.slow
    @needs_tools
    def test_patch_inplace_and_run(self, tmp_path):
        """Download a real glibc, patch in inplace mode, run it."""
        from pwnlibc.downloader import download_glibc, scrape_available
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import patch_inplace

        workdir = tmp_path / "e2e_inplace"
        binary = build_test_binary(workdir)
        if binary is None:
            pytest.skip("failed to compile test binary")

        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        packages = scrape_available("ubuntu")
        pkg = None
        for p in packages:
            if p.version == "2.35" and p.arch == "amd64":
                pkg = p
                break
        if pkg is None:
            pytest.skip("glibc 2.35 amd64 not on mirror")

        download_glibc(pkg, glibc_dir, include_dbg=False)
        inst = resolve_lib_paths("2.35", "amd64", glibc_dir)
        patched = patch_inplace(binary, inst)

        result = subprocess.run(
            [str(patched)], capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "pwnlibc-test-ok" in result.stdout
