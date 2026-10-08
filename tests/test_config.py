"""Tests for pwnlibc.config — version parsing, naming conventions, constants."""

import os

import pytest

from pwnlibc.config import (
    ARCH_INFO,
    DEFAULT_GLIBC_DIR,
    MIRRORS,
    get_ld_real_name,
    get_libc_real_name,
    parse_version,
    uses_new_naming,
)


class TestParseVersion:
    def test_basic(self):
        assert parse_version("2.31") == (2, 31)

    def test_high_minor(self):
        assert parse_version("2.39") == (2, 39)

    def test_boundary(self):
        assert parse_version("2.34") == (2, 34)

    def test_old(self):
        assert parse_version("2.17") == (2, 17)

    def test_invalid_raises(self):
        with pytest.raises((ValueError, IndexError)):
            parse_version("notaversion")

    def test_single_number_valid(self):
        assert parse_version("2") == (2,)


class TestUsesNewNaming:
    def test_old_naming(self):
        for v in ["2.17", "2.23", "2.27", "2.31", "2.33"]:
            assert uses_new_naming(v) is False, v

    def test_new_naming(self):
        for v in ["2.34", "2.35", "2.38", "2.39", "2.40"]:
            assert uses_new_naming(v) is True, v

    def test_exact_boundary(self):
        assert uses_new_naming("2.33") is False
        assert uses_new_naming("2.34") is True


class TestGetLibcRealName:
    def test_old(self):
        assert get_libc_real_name("2.31") == "libc-2.31.so"
        assert get_libc_real_name("2.27") == "libc-2.27.so"

    def test_new(self):
        assert get_libc_real_name("2.35") == "libc.so.6"
        assert get_libc_real_name("2.39") == "libc.so.6"


class TestGetLdRealName:
    def test_old_amd64(self):
        assert get_ld_real_name("2.31", "amd64") == "ld-2.31.so"

    def test_old_i686(self):
        assert get_ld_real_name("2.31", "i686") == "ld-2.31.so"

    def test_new_amd64(self):
        assert get_ld_real_name("2.35", "amd64") == "ld-linux-x86-64.so.2"

    def test_new_i686(self):
        assert get_ld_real_name("2.35", "i686") == "ld-linux.so.2"


class TestConstants:
    def test_arch_info_has_amd64(self):
        info = ARCH_INFO["amd64"]
        assert info["elf_machine"] == 62
        assert info["ld_soname"] == "ld-linux-x86-64.so.2"
        assert info["deb_arch"] == "amd64"

    def test_arch_info_has_i686(self):
        info = ARCH_INFO["i686"]
        assert info["elf_machine"] == 3
        assert info["ld_soname"] == "ld-linux.so.2"
        assert info["deb_arch"] == "i386"

    def test_mirrors_keys(self):
        assert "ubuntu" in MIRRORS
        assert "old-ubuntu" in MIRRORS
        assert "tsinghua" in MIRRORS

    def test_mirrors_are_urls(self):
        for url in MIRRORS.values():
            assert url.startswith("http://") or url.startswith("https://")

    def test_default_glibc_dir(self):
        # Without PWNLIBC_DIR env var, resolves to a Path
        # (The actual value depends on env at import time, just check it's a Path)
        from pathlib import Path
        assert isinstance(DEFAULT_GLIBC_DIR, Path)


class TestGlibcDirResolution:
    """resolve_glibc_dir: $PWNLIBC_DIR > config file > ~/pwnlibc."""

    def test_env_overrides_everything(self, monkeypatch, tmp_path):
        from pwnlibc.config import resolve_glibc_dir
        monkeypatch.setenv("PWNLIBC_DIR", str(tmp_path / "from-env"))
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        (tmp_path / ".config" / "pwnlibc").mkdir(parents=True)
        (tmp_path / ".config" / "pwnlibc" / "glibc_dir").write_text("/from-config\n")
        assert resolve_glibc_dir() == tmp_path / "from-env"

    def test_config_file_used_when_no_env(self, monkeypatch, tmp_path):
        from pwnlibc.config import resolve_glibc_dir
        monkeypatch.delenv("PWNLIBC_DIR", raising=False)
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        cfg = tmp_path / ".config" / "pwnlibc"
        cfg.mkdir(parents=True)
        (cfg / "glibc_dir").write_text(str(tmp_path / "chosen") + "\n")
        assert resolve_glibc_dir() == tmp_path / "chosen"

    def test_default_when_no_config(self, monkeypatch, tmp_path):
        from pwnlibc.config import resolve_glibc_dir
        monkeypatch.delenv("PWNLIBC_DIR", raising=False)
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        assert resolve_glibc_dir() == tmp_path / "pwnlibc"

    def test_empty_config_falls_back_to_default(self, monkeypatch, tmp_path):
        from pwnlibc.config import resolve_glibc_dir
        monkeypatch.delenv("PWNLIBC_DIR", raising=False)
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        cfg = tmp_path / ".config" / "pwnlibc"
        cfg.mkdir(parents=True)
        (cfg / "glibc_dir").write_text("   \n")
        assert resolve_glibc_dir() == tmp_path / "pwnlibc"

    def test_blank_env_falls_through_to_config(self, monkeypatch, tmp_path):
        from pwnlibc.config import resolve_glibc_dir
        monkeypatch.setenv("PWNLIBC_DIR", "  ")
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        cfg = tmp_path / ".config" / "pwnlibc"
        cfg.mkdir(parents=True)
        (cfg / "glibc_dir").write_text(str(tmp_path / "chosen") + "\n")
        assert resolve_glibc_dir() == tmp_path / "chosen"
