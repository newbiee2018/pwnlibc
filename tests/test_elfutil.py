"""Tests for pwnlibc.elfutil — ELF parsing without external dependencies."""

import struct

import pytest

from pwnlibc.elfutil import detect_arch, get_debuglink, get_needed_libs, has_debug_info
from tests.conftest import _build_debuglink_elf, _build_minimal_elf


class TestDetectArch:
    def test_amd64(self, minimal_elf_amd64):
        assert detect_arch(minimal_elf_amd64) == "amd64"

    def test_i686(self, minimal_elf_i686):
        assert detect_arch(minimal_elf_i686) == "i686"

    def test_not_elf(self, tmp_path):
        f = tmp_path / "notelf"
        f.write_bytes(b"MZ\x00\x00")
        with pytest.raises(ValueError, match="Not an ELF"):
            detect_arch(f)

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty"
        f.write_bytes(b"")
        with pytest.raises(Exception):
            detect_arch(f)

    def test_truncated_elf(self, tmp_path):
        f = tmp_path / "truncated"
        f.write_bytes(b"\x7fELF\x02")
        with pytest.raises(Exception):
            detect_arch(f)


class TestGetNeededLibs:
    def test_single_needed(self, minimal_elf_amd64):
        needed = get_needed_libs(minimal_elf_amd64)
        assert needed == ["libc.so.6"]

    def test_multi_needed(self, minimal_elf_multi_needed):
        needed = get_needed_libs(minimal_elf_multi_needed)
        assert "libc.so.6" in needed
        assert "libpthread.so.0" in needed
        assert "libm.so.6" in needed
        assert "libdl.so.2" in needed
        assert len(needed) == 4

    def test_i686_needed(self, minimal_elf_i686):
        needed = get_needed_libs(minimal_elf_i686)
        assert needed == ["libc.so.6"]

    def test_no_dynamic_section(self, tmp_path):
        """An ELF with no .dynamic section should return empty list."""
        f = tmp_path / "nodyn"
        is_64 = True
        ei_class = 2
        ehdr_size = 64
        shent_size = 64

        shstrtab_data = b"\x00.shstrtab\x00"

        shstrtab_offset = ehdr_size
        sh_offset = shstrtab_offset + len(shstrtab_data)
        if sh_offset % 8 != 0:
            pad = 8 - (sh_offset % 8)
            shstrtab_data += b"\x00" * pad
            sh_offset = shstrtab_offset + len(shstrtab_data)

        ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
        ehdr = ident
        ehdr += struct.pack("<HHI", 2, 62, 1)
        ehdr += struct.pack("<QQQ", 0, 0, sh_offset)
        ehdr += struct.pack("<IHHHHHH", 0, ehdr_size, 0, 0, shent_size, 2, 1)

        # Null section + shstrtab (Elf64_Shdr = IIQQQQIIQQ, 64 bytes)
        null_sh = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        shstrtab_sh = struct.pack("<IIQQQQIIQQ",
                                   1, 3, 0, 0,
                                   shstrtab_offset, len(shstrtab_data),
                                   0, 0, 1, 0)

        f.write_bytes(ehdr + shstrtab_data + null_sh + shstrtab_sh)
        assert get_needed_libs(f) == []


class TestHasDebugInfo:
    def test_no_debug(self, minimal_elf_amd64):
        assert has_debug_info(minimal_elf_amd64) is False

    def test_with_debug_section(self, tmp_path):
        """Build an ELF that has a .debug_info section name."""
        f = tmp_path / "debug_elf"
        ehdr_size = 64
        shent_size = 64

        shstrtab_data = b"\x00.debug_info\x00.shstrtab\x00"
        debug_name_off = 1
        shstrtab_name_off = 13

        fake_debug_data = b"\x00" * 16

        debug_offset = ehdr_size
        shstrtab_offset = debug_offset + len(fake_debug_data)
        sh_offset = shstrtab_offset + len(shstrtab_data)
        if sh_offset % 8 != 0:
            pad = 8 - (sh_offset % 8)
            shstrtab_data += b"\x00" * pad
            sh_offset = shstrtab_offset + len(shstrtab_data)

        ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
        ehdr = ident
        ehdr += struct.pack("<HHI", 2, 62, 1)
        ehdr += struct.pack("<QQQ", 0, 0, sh_offset)
        ehdr += struct.pack("<IHHHHHH", 0, ehdr_size, 0, 0, shent_size, 3, 2)

        # Elf64_Shdr = IIQQQQIIQQ (64 bytes)
        null_sh = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        debug_sh = struct.pack("<IIQQQQIIQQ",
                                debug_name_off, 1, 0, 0,
                                debug_offset, len(fake_debug_data),
                                0, 0, 1, 0)
        shstrtab_sh = struct.pack("<IIQQQQIIQQ",
                                   shstrtab_name_off, 3, 0, 0,
                                   shstrtab_offset, len(shstrtab_data),
                                   0, 0, 1, 0)

        f.write_bytes(ehdr + fake_debug_data + shstrtab_data +
                      null_sh + debug_sh + shstrtab_sh)
        assert has_debug_info(f) is True

    def test_non_elf_returns_false(self, tmp_path):
        f = tmp_path / "not_elf"
        f.write_bytes(b"not an elf file at all")
        assert has_debug_info(f) is False


class TestGetDebuglink:
    def test_returns_debuglink_filename(self, tmp_path):
        hash_name = "92732f783158c66fb4f3756458ca24e46e827d.debug"
        f = _build_debuglink_elf(tmp_path / "with_link", hash_name)
        assert get_debuglink(f) == hash_name

    def test_no_debuglink_section(self, minimal_elf_amd64):
        assert get_debuglink(minimal_elf_amd64) is None

    def test_non_elf_returns_none(self, tmp_path):
        f = tmp_path / "not_elf"
        f.write_bytes(b"not an elf file at all")
        assert get_debuglink(f) is None

    def test_truncated_elf_returns_none(self, tmp_path):
        f = tmp_path / "truncated"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        assert get_debuglink(f) is None
