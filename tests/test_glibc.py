"""Tests for pwnlibc.glibc — glibc install discovery and path resolution."""

import pytest

from pwnlibc.glibc import GlibcInstall, discover_installed, find_library, resolve_lib_paths


class TestResolveLibPaths:
    def test_old_naming_amd64(self, populated_glibc_dir):
        inst = resolve_lib_paths("2.31", "amd64", populated_glibc_dir)
        assert inst.version == "2.31"
        assert inst.arch == "amd64"
        assert inst.libc_path.exists()
        assert inst.ld_path.exists()
        assert inst.new_naming is False

    def test_old_naming_i686(self, populated_glibc_dir):
        inst = resolve_lib_paths("2.31", "i686", populated_glibc_dir)
        assert inst.version == "2.31"
        assert inst.arch == "i686"
        assert inst.new_naming is False

    def test_new_naming_amd64(self, populated_glibc_dir):
        inst = resolve_lib_paths("2.35", "amd64", populated_glibc_dir)
        assert inst.version == "2.35"
        assert inst.new_naming is True
        assert inst.has_debug is True
        assert inst.has_source is True

    def test_new_naming_no_debug(self, populated_glibc_dir):
        inst = resolve_lib_paths("2.39", "amd64", populated_glibc_dir)
        assert inst.has_debug is False
        assert inst.has_source is False

    def test_missing_version_raises(self, populated_glibc_dir):
        with pytest.raises(FileNotFoundError):
            resolve_lib_paths("2.99", "amd64", populated_glibc_dir)

    def test_missing_arch_raises(self, populated_glibc_dir):
        with pytest.raises(FileNotFoundError):
            resolve_lib_paths("2.35", "i686", populated_glibc_dir)

    def test_empty_dir_raises(self, tmp_glibc_dir):
        tmp_glibc_dir.mkdir(parents=True)
        with pytest.raises(FileNotFoundError):
            resolve_lib_paths("2.31", "amd64", tmp_glibc_dir)


class TestDiscoverInstalled:
    def test_discovers_all(self, populated_glibc_dir):
        installs = discover_installed(populated_glibc_dir)
        versions = {(i.version, i.arch) for i in installs}
        assert ("2.31", "amd64") in versions
        assert ("2.31", "i686") in versions
        assert ("2.35", "amd64") in versions
        assert ("2.39", "amd64") in versions

    def test_empty_dir(self, tmp_path):
        d = tmp_path / "empty_glibc"
        d.mkdir()
        assert discover_installed(d) == []

    def test_nonexistent_dir(self, tmp_path):
        assert discover_installed(tmp_path / "nonexistent") == []

    def test_ignores_dotfiles(self, populated_glibc_dir):
        (populated_glibc_dir / ".cache").mkdir()
        (populated_glibc_dir / ".hidden").mkdir()
        installs = discover_installed(populated_glibc_dir)
        versions = {i.version for i in installs}
        assert ".cache" not in versions
        assert ".hidden" not in versions

    def test_ignores_non_version_dirs(self, populated_glibc_dir):
        (populated_glibc_dir / "readme").mkdir()
        (populated_glibc_dir / "source").mkdir()
        installs = discover_installed(populated_glibc_dir)
        versions = {i.version for i in installs}
        assert "readme" not in versions


class TestFindLibrary:
    def test_direct_match(self, populated_glibc_dir):
        inst = resolve_lib_paths("2.31", "amd64", populated_glibc_dir)
        result = find_library(inst, "libpthread.so.0")
        assert result is not None

    def test_no_match(self, populated_glibc_dir):
        inst = resolve_lib_paths("2.31", "amd64", populated_glibc_dir)
        result = find_library(inst, "libnotexist.so.1")
        assert result is None

    def test_symlink_resolved(self, populated_glibc_dir):
        inst = resolve_lib_paths("2.31", "amd64", populated_glibc_dir)
        result = find_library(inst, "libc.so.6")
        assert result is not None
