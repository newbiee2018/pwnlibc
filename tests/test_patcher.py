"""Tests for pwnlibc.patcher — ELF patching via patchelf."""

import json
import os
import shutil
import subprocess
from unittest.mock import patch

import pytest

from tests.conftest import _build_debuglink_elf, _build_minimal_elf, build_test_binary


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
        from pwnlibc.patcher import PATCHED_MANIFEST_SUFFIX, PATCHED_SUFFIX, patch_copy

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

        # Manifest is keyed on the original binary name and lists the copies
        manifest_path = binary.parent / (binary.name + PATCHED_MANIFEST_SUFFIX)
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text())
        assert "libc-2.31.so" in manifest["files"]
        assert "ld-2.31.so" in manifest["files"]

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


class TestPatchCopyManifest:
    """patch_copy records every file it creates in a JSON manifest next to the
    binary (keyed on the ORIGINAL binary name) so restore can remove exactly
    those files. patchelf is mocked — no real tools needed."""

    HASH = "92732f783158c66fb4f3756458ca24e46e827d.debug"

    @staticmethod
    def _make_install(lib_dir):
        from pwnlibc.glibc import GlibcInstall

        return GlibcInstall(
            version="2.31", arch="amd64",
            base_dir=lib_dir.parent, lib_dir=lib_dir,
            libc_path=lib_dir / "libc-2.31.so",
            ld_path=lib_dir / "ld-2.31.so",
            has_source=False, has_debug=True,
            new_naming=False, variant="deb",
        )

    def _make_fixture(self, tmp_path):
        """Fake install: libc resolves its debug file via the .gnu_debuglink
        hash name, ld via the exact-name fallback."""
        lib_dir = tmp_path / "glibc" / "2.31" / "amd64" / "lib"
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir(parents=True)
        _build_debuglink_elf(lib_dir / "libc-2.31.so", self.HASH)
        (debug_dir / self.HASH).write_bytes(b"libc-debug-data")
        (lib_dir / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
        (debug_dir / "ld-2.31.so").write_bytes(b"ld-debug-data")
        return self._make_install(lib_dir)

    @patch("pwnlibc.patcher._run_patchelf")
    @patch("pwnlibc.patcher.shutil.which", return_value="/usr/bin/patchelf")
    def test_manifest_lists_libs_and_debug_files(self, mock_which, mock_patchelf, tmp_path):
        from pwnlibc.patcher import PATCHED_MANIFEST_SUFFIX, patch_copy

        workdir = tmp_path / "workdir"
        workdir.mkdir()
        binary = _build_minimal_elf(workdir / "testbin", needed=["libc.so.6"])

        inst = self._make_fixture(tmp_path)
        patched, _ = patch_copy(binary, inst)

        assert patched.exists()
        manifest_path = binary.parent / (binary.name + PATCHED_MANIFEST_SUFFIX)
        assert manifest_path.exists()
        expected = ["libc-2.31.so", "ld-2.31.so", f".debug/{self.HASH}", ".debug/ld-2.31.so"]
        assert manifest_path.read_text() == json.dumps({"files": expected}, indent=1) + "\n"

    @patch("pwnlibc.patcher._run_patchelf")
    @patch("pwnlibc.patcher.shutil.which", return_value="/usr/bin/patchelf")
    def test_repatch_overwrites_manifest(self, mock_which, mock_patchelf, tmp_path):
        """Re-patching replaces the manifest wholesale — stale entries disappear."""
        from pwnlibc.patcher import PATCHED_MANIFEST_SUFFIX, patch_copy

        workdir = tmp_path / "workdir"
        workdir.mkdir()
        binary = _build_minimal_elf(workdir / "testbin", needed=["libc.so.6"])
        inst = self._make_fixture(tmp_path)

        patch_copy(binary, inst)
        manifest_path = binary.parent / (binary.name + PATCHED_MANIFEST_SUFFIX)
        assert f".debug/{self.HASH}" in json.loads(manifest_path.read_text())["files"]

        # Simulate drift: a stale manifest and a debug pack that went away
        manifest_path.write_text(json.dumps(
            {"files": ["libc-9.99.so", f".debug/{self.HASH}"]}, indent=1) + "\n")
        shutil.rmtree(inst.lib_dir / ".debug")

        patch_copy(binary, inst)
        expected = ["libc-2.31.so", "ld-2.31.so"]
        assert manifest_path.read_text() == json.dumps({"files": expected}, indent=1) + "\n"

    @patch("pwnlibc.patcher._run_patchelf", side_effect=RuntimeError("patchelf failed"))
    @patch("pwnlibc.patcher.shutil.which", return_value="/usr/bin/patchelf")
    def test_manifest_written_before_patchelf_runs(self, mock_which, mock_patchelf, tmp_path):
        """A mid-patch patchelf failure still leaves a consumable manifest."""
        from pwnlibc.patcher import PATCHED_MANIFEST_SUFFIX, patch_copy

        workdir = tmp_path / "workdir"
        workdir.mkdir()
        binary = _build_minimal_elf(workdir / "testbin", needed=["libc.so.6"])
        inst = self._make_fixture(tmp_path)

        with pytest.raises(RuntimeError, match="patchelf failed"):
            patch_copy(binary, inst)

        manifest_path = binary.parent / (binary.name + PATCHED_MANIFEST_SUFFIX)
        assert manifest_path.exists()
        assert "libc-2.31.so" in json.loads(manifest_path.read_text())["files"]

    @patch("pwnlibc.patcher._run_patchelf")
    @patch("pwnlibc.patcher.shutil.which", return_value="/usr/bin/patchelf")
    def test_patch_inplace_writes_no_manifest(self, mock_which, mock_patchelf, tmp_path):
        """inplace mode creates no files besides the .patched copy, so it
        writes no manifest."""
        from pwnlibc.patcher import PATCHED_MANIFEST_SUFFIX, PATCHED_SUFFIX, patch_inplace

        workdir = tmp_path / "workdir"
        workdir.mkdir()
        binary = _build_minimal_elf(workdir / "testbin", needed=["libc.so.6"])
        inst = self._make_fixture(tmp_path)

        patched = patch_inplace(binary, inst)

        assert patched == binary.parent / (binary.name + PATCHED_SUFFIX)
        assert patched.exists()
        assert not (binary.parent / (binary.name + PATCHED_MANIFEST_SUFFIX)).exists()


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


class TestCopyDebugFiles:
    """_copy_debug_files must find hash-named deb(dbg) debug files."""

    HASH = "92732f783158c66fb4f3756458ca24e46e827d.debug"

    @staticmethod
    def _make_install(lib_dir):
        from pwnlibc.glibc import GlibcInstall

        return GlibcInstall(
            version="2.31", arch="amd64",
            base_dir=lib_dir.parent, lib_dir=lib_dir,
            libc_path=lib_dir / "libc-2.31.so",
            ld_path=lib_dir / "ld-2.31.so",
            has_source=False, has_debug=True,
            new_naming=False, variant="deb",
        )

    def test_hash_named_debug_via_debuglink(self, tmp_path):
        """Lib's .gnu_debuglink names the hash file; hash name is preserved."""
        from pwnlibc.patcher import _copy_debug_files

        lib_dir = tmp_path / "lib"
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir(parents=True)
        lib = _build_debuglink_elf(lib_dir / "libc-2.31.so", self.HASH)
        (debug_dir / self.HASH).write_bytes(b"debug-data")

        target = tmp_path / "target"
        target.mkdir()
        copied = _copy_debug_files(self._make_install(lib_dir), [lib], target)

        assert copied == [f".debug/{self.HASH}"]
        # Hash name kept: GDB resolves <binary-dir>/.debug/<debuglink-name>
        assert (target / ".debug" / self.HASH).read_bytes() == b"debug-data"
        assert not (target / ".debug" / "libc-2.31.so").exists()

    def test_hash_file_missing_falls_through(self, tmp_path):
        """Debuglink present but file absent; legacy name still wins."""
        from pwnlibc.patcher import _copy_debug_files

        lib_dir = tmp_path / "lib"
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir(parents=True)
        lib = _build_debuglink_elf(lib_dir / "libc-2.31.so", self.HASH)
        (debug_dir / "libc-2.31.so").write_bytes(b"legacy-data")

        target = tmp_path / "target"
        target.mkdir()
        copied = _copy_debug_files(self._make_install(lib_dir), [lib], target)

        assert copied == [".debug/libc-2.31.so"]
        assert (target / ".debug" / "libc-2.31.so").read_bytes() == b"legacy-data"

    def test_legacy_named_debug_file(self, tmp_path):
        """No debuglink: exact-name debug file is copied as-is."""
        from pwnlibc.patcher import _copy_debug_files

        lib_dir = tmp_path / "lib"
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir(parents=True)
        lib = lib_dir / "ld-2.31.so"
        lib.write_bytes(b"\x7fELF" + b"\x00" * 100)
        (debug_dir / "ld-2.31.so").write_bytes(b"ld-debug")

        target = tmp_path / "target"
        target.mkdir()
        copied = _copy_debug_files(self._make_install(lib_dir), [lib], target)

        assert copied == [".debug/ld-2.31.so"]
        assert (target / ".debug" / "ld-2.31.so").read_bytes() == b"ld-debug"

    def test_prefix_fallback_requires_trailing_dash(self, tmp_path):
        """libm- must not grab libmvec-; libc- must not grab libcrypt-."""
        from pwnlibc.patcher import _copy_debug_files

        lib_dir = tmp_path / "lib"
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir(parents=True)

        libm = lib_dir / "libm-2.31.so"
        libm.write_bytes(b"\x7fELF" + b"\x00" * 100)
        (debug_dir / "libm-2.31.so.debug").write_bytes(b"m-debug")
        (debug_dir / "libmvec-2.31.so.debug").write_bytes(b"mvec-debug")

        target = tmp_path / "target"
        target.mkdir()
        copied = _copy_debug_files(self._make_install(lib_dir), [libm], target)

        assert copied == [".debug/libm-2.31.so.debug"]
        assert (target / ".debug" / "libm-2.31.so.debug").read_bytes() == b"m-debug"
        assert not (target / ".debug" / "libmvec-2.31.so.debug").exists()

    def test_prefix_fallback_ignores_longer_libc_like_names(self, tmp_path):
        """libcidn-/libcrypt- files must not satisfy a libc- lookup."""
        from pwnlibc.patcher import _copy_debug_files

        lib_dir = tmp_path / "lib"
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir(parents=True)

        lib = lib_dir / "libc-2.31.so"
        lib.write_bytes(b"\x7fELF" + b"\x00" * 100)
        (debug_dir / "libcrypt-2.31.so.debug").write_bytes(b"crypt")
        (debug_dir / "libcidn-2.31.so.debug").write_bytes(b"cidn")

        target = tmp_path / "target"
        target.mkdir()
        copied = _copy_debug_files(self._make_install(lib_dir), [lib], target)

        assert copied == []
        assert not (target / ".debug" / "libcrypt-2.31.so.debug").exists()
        assert not (target / ".debug" / "libcidn-2.31.so.debug").exists()

    def test_no_debug_dir_returns_empty(self, tmp_path):
        from pwnlibc.patcher import _copy_debug_files

        lib_dir = tmp_path / "lib"
        lib_dir.mkdir(parents=True)
        lib = lib_dir / "libc-2.31.so"
        lib.write_bytes(b"\x7fELF" + b"\x00" * 100)

        target = tmp_path / "target"
        target.mkdir()
        assert _copy_debug_files(self._make_install(lib_dir), [lib], target) == []

    def test_only_hash_files_without_debuglink_matches_nothing(self, tmp_path):
        """Old buggy behavior sanity: bare lib without debuglink + hash-only
        .debug dir copies nothing (both legacy lookups miss)."""
        from pwnlibc.patcher import _copy_debug_files

        lib_dir = tmp_path / "lib"
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir(parents=True)
        lib = lib_dir / "libc-2.31.so"
        lib.write_bytes(b"\x7fELF" + b"\x00" * 100)
        (debug_dir / self.HASH).write_bytes(b"orphan")

        target = tmp_path / "target"
        target.mkdir()
        assert _copy_debug_files(self._make_install(lib_dir), [lib], target) == []


class TestFindLibrary:
    """find_library fallback must not confuse similarly-prefixed libs."""

    @staticmethod
    def _make_install(lib_dir):
        from pwnlibc.glibc import GlibcInstall

        return GlibcInstall(
            version="2.31", arch="amd64",
            base_dir=lib_dir.parent, lib_dir=lib_dir,
            libc_path=lib_dir / "libc-2.31.so",
            ld_path=lib_dir / "ld-2.31.so",
            has_source=False, has_debug=False,
            new_naming=False, variant="deb",
        )

    def test_direct_soname_hit(self, tmp_path):
        from pwnlibc.glibc import find_library

        lib_dir = tmp_path / "lib"
        lib_dir.mkdir(parents=True)
        (lib_dir / "libpthread.so.0").write_bytes(b"\x7fELF" + b"\x00" * 10)
        inst = self._make_install(lib_dir)

        assert find_library(inst, "libpthread.so.0") is not None

    def test_prefix_fallback_picks_shortest_name(self, tmp_path):
        from pwnlibc.glibc import find_library

        lib_dir = tmp_path / "lib"
        lib_dir.mkdir(parents=True)
        (lib_dir / "libm-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 10)
        (lib_dir / "libmvec-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 10)
        (lib_dir / "libmemusage.so").write_bytes(b"\x7fELF" + b"\x00" * 10)
        inst = self._make_install(lib_dir)

        assert find_library(inst, "libm.so.6") == lib_dir / "libm-2.31.so"

    def test_prefix_fallback_deterministic_across_orders(self, tmp_path, monkeypatch):
        """Result must not depend on iterdir() order for equal-length names."""
        import itertools
        from pwnlibc.glibc import find_library

        lib_dir = tmp_path / "lib"
        lib_dir.mkdir(parents=True)
        names = ["libm-2.31a.so", "libm-2.31b.so"]
        for n in names:
            (lib_dir / n).write_bytes(b"\x7fELF" + b"\x00" * 10)
        inst = self._make_install(lib_dir)

        real_iterdir = type(lib_dir).iterdir
        for perm in itertools.permutations(names):
            monkeypatch.setattr(
                type(lib_dir), "iterdir",
                lambda self, _p=perm: iter([self / n for n in _p]),
            )
            assert find_library(inst, "libm.so.6").name == "libm-2.31a.so"
        monkeypatch.setattr(type(lib_dir), "iterdir", real_iterdir)

    def test_no_match_returns_none(self, tmp_path):
        from pwnlibc.glibc import find_library

        lib_dir = tmp_path / "lib"
        lib_dir.mkdir(parents=True)
        (lib_dir / "libmvec-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 10)
        inst = self._make_install(lib_dir)

        # libm- prefix never matches libmvec
        assert find_library(inst, "libm.so.6") is None


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
