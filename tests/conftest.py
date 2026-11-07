import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent


@pytest.fixture(autouse=True)
def _offline_by_default(request, monkeypatch):
    """Enforce pytest.ini's offline-by-default policy instead of trusting it.

    A bare `pytest` must not touch the network: unmarked tests that attempt a
    real connection (or a DNS lookup) fail fast here instead of quietly
    hitting archive.ubuntu.com / ftp.gnu.org. time.sleep is neutralized too,
    so the blocked fetch's retry backoff cannot stall the suite. Tests that
    mock urlopen / the fetch helpers are unaffected — only real sockets are.
    Tests marked `network` (the -m network opt-in) are exempt entirely.
    """
    if request.node.get_closest_marker("network") is not None:
        return

    def _blocked(*args, **kwargs):
        raise OSError(
            "real network use in an unmarked test — mock the fetch "
            "or mark the test @pytest.mark.network"
        )

    import socket
    import time

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: (_ for _ in ()).throw(
            socket.gaierror("DNS disabled in the offline test run")),
    )
    monkeypatch.setattr(time, "sleep", lambda *_: None)


@pytest.fixture
def tmp_glibc_dir(tmp_path):
    """Temporary glibc directory with realistic structure."""
    return tmp_path / "glibc"


@pytest.fixture
def populated_glibc_dir(tmp_path):
    """Glibc dir pre-populated with fake installs for old and new naming."""
    glibc_dir = tmp_path / "glibc"

    # Old naming: 2.31 amd64
    lib_dir = glibc_dir / "2.31" / "amd64" / "lib"
    lib_dir.mkdir(parents=True)
    (lib_dir / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
    (lib_dir / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
    (lib_dir / "libc.so.6").symlink_to("libc-2.31.so")
    (lib_dir / "ld-linux-x86-64.so.2").symlink_to("ld-2.31.so")
    (lib_dir / "libpthread-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
    (lib_dir / "libpthread.so.0").symlink_to("libpthread-2.31.so")

    # Old naming: 2.31 i686
    lib_dir_i686 = glibc_dir / "2.31" / "i686" / "lib"
    lib_dir_i686.mkdir(parents=True)
    (lib_dir_i686 / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
    (lib_dir_i686 / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
    (lib_dir_i686 / "libc.so.6").symlink_to("libc-2.31.so")
    (lib_dir_i686 / "ld-linux.so.2").symlink_to("ld-2.31.so")

    # New naming: 2.35 amd64
    lib_dir_new = glibc_dir / "2.35" / "amd64" / "lib"
    lib_dir_new.mkdir(parents=True)
    (lib_dir_new / "libc.so.6").write_bytes(b"\x7fELF" + b"\x00" * 100)
    (lib_dir_new / "ld-linux-x86-64.so.2").write_bytes(b"\x7fELF" + b"\x00" * 100)
    debug_dir = lib_dir_new / ".debug"
    debug_dir.mkdir()
    (debug_dir / "libc.so.6.debug").write_bytes(b"\x00" * 10)

    # New naming: 2.39 amd64 (no debug)
    lib_dir_39 = glibc_dir / "2.39" / "amd64" / "lib"
    lib_dir_39.mkdir(parents=True)
    (lib_dir_39 / "libc.so.6").write_bytes(b"\x7fELF" + b"\x00" * 100)
    (lib_dir_39 / "ld-linux-x86-64.so.2").write_bytes(b"\x7fELF" + b"\x00" * 100)

    # Source dir for 2.35
    (glibc_dir / "2.35" / "source").mkdir(parents=True)

    # Built variant: 2.31 amd64-built
    built_dir = glibc_dir / "2.31" / "amd64-built" / "lib"
    built_dir.mkdir(parents=True)
    (built_dir / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
    (built_dir / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
    (built_dir / "libc.so.6").symlink_to("libc-2.31.so")
    (built_dir / "ld-linux-x86-64.so.2").symlink_to("ld-2.31.so")

    # arm64 deb install: 2.35
    arm64_dir = glibc_dir / "2.35" / "arm64" / "lib"
    arm64_dir.mkdir(parents=True)
    (arm64_dir / "libc.so.6").write_bytes(b"\x7fELF" + b"\x00" * 100)
    (arm64_dir / "ld-linux-aarch64.so.1").write_bytes(b"\x7fELF" + b"\x00" * 100)

    return glibc_dir


SAMPLE_PORTS_MIRROR_HTML = """
<html><body>
<a href="libc6_2.23-0ubuntu11.3_arm64.deb">libc6_2.23-0ubuntu11.3_arm64.deb</a>
<a href="libc6-dbg_2.23-0ubuntu11.3_arm64.deb">libc6-dbg_2.23-0ubuntu11.3_arm64.deb</a>
<a href="libc6_2.27-3ubuntu1.6_arm64.deb">libc6_2.27-3ubuntu1.6_arm64.deb</a>
<a href="libc6-dbg_2.27-3ubuntu1.6_arm64.deb">libc6-dbg_2.27-3ubuntu1.6_arm64.deb</a>
<a href="libc6_2.31-0ubuntu9.16_arm64.deb">libc6_2.31-0ubuntu9.16_arm64.deb</a>
<a href="libc6_2.31-0ubuntu9.16_armhf.deb">libc6_2.31-0ubuntu9.16_armhf.deb</a>
<a href="libc6_2.35-0ubuntu3.8_arm64.deb">libc6_2.35-0ubuntu3.8_arm64.deb</a>
<a href="libc6-dbg_2.35-0ubuntu3.8_arm64.deb">libc6-dbg_2.35-0ubuntu3.8_arm64.deb</a>
<a href="libc6_2.35-0ubuntu3.8_armhf.deb">libc6_2.35-0ubuntu3.8_armhf.deb</a>
<a href="libc6_2.35-0ubuntu3.8_ppc64el.deb">libc6_2.35-0ubuntu3.8_ppc64el.deb</a>
<a href="libc6_2.35-0ubuntu3.8_s390x.deb">libc6_2.35-0ubuntu3.8_s390x.deb</a>
<a href="libc6_2.35-0ubuntu3.8_riscv64.deb">libc6_2.35-0ubuntu3.8_riscv64.deb</a>
</body></html>
"""

SAMPLE_DEBIAN_MIRROR_HTML = """
<html><body>
<a href="libc6_2.31-13+deb11u10_mipsel.deb">libc6_2.31-13+deb11u10_mipsel.deb</a>
<a href="libc6-dbg_2.31-13+deb11u10_mipsel.deb">libc6-dbg_2.31-13+deb11u10_mipsel.deb</a>
<a href="libc6_2.31-13+deb11u10_mips64el.deb">libc6_2.31-13+deb11u10_mips64el.deb</a>
<a href="libc6_2.36-9+deb12u9_mipsel.deb">libc6_2.36-9+deb12u9_mipsel.deb</a>
<a href="libc6_2.36-9+deb12u9_mips64el.deb">libc6_2.36-9+deb12u9_mips64el.deb</a>
<a href="libc6-dbg_2.36-9+deb12u9_mips64el.deb">libc6-dbg_2.36-9+deb12u9_mips64el.deb</a>
</body></html>
"""

SAMPLE_OLD_UBUNTU_MIRROR_HTML = """
<html><body>
<a href="libc6_2.3.6-0ubuntu20.6_amd64.deb">libc6_2.3.6-0ubuntu20.6_amd64.deb</a>
<a href="libc6_2.3.6-0ubuntu20.6_i386.deb">libc6_2.3.6-0ubuntu20.6_i386.deb</a>
<a href="libc6_2.3.6-0ubuntu20.6_powerpc.deb">libc6_2.3.6-0ubuntu20.6_powerpc.deb</a>
<a href="libc6_2.19-0ubuntu6.15_amd64.deb">libc6_2.19-0ubuntu6.15_amd64.deb</a>
<a href="libc6_2.19-0ubuntu6.15_i386.deb">libc6_2.19-0ubuntu6.15_i386.deb</a>
<a href="libc6-dbg_2.19-0ubuntu6.15_amd64.deb">libc6-dbg_2.19-0ubuntu6.15_amd64.deb</a>
<a href="libc6_2.21-0ubuntu4.3_amd64.deb">libc6_2.21-0ubuntu4.3_amd64.deb</a>
<a href="libc6_2.23-0ubuntu11_amd64.deb">libc6_2.23-0ubuntu11_amd64.deb</a>
<a href="libc6-dbg_2.23-0ubuntu11_amd64.deb">libc6-dbg_2.23-0ubuntu11_amd64.deb</a>
</body></html>
"""


def _build_minimal_elf(path, arch="amd64", needed=None):
    """Build a minimal valid ELF binary with optional DT_NEEDED entries.

    This creates a real enough ELF for elfutil parsing but is NOT executable.
    For executable test binaries, use build_test_binary().
    """
    if needed is None:
        needed = ["libc.so.6"]

    is_64 = arch == "amd64"

    strtab_data = b"\x00"
    needed_offsets = []
    for lib in needed:
        needed_offsets.append(len(strtab_data))
        strtab_data += lib.encode("ascii") + b"\x00"

    section_names = [b"\x00", b".dynamic\x00", b".dynstr\x00", b".shstrtab\x00"]
    shstrtab_data = b""
    name_offsets = []
    for name in section_names:
        name_offsets.append(len(shstrtab_data))
        shstrtab_data += name

    if is_64:
        entry_size = 16
    else:
        entry_size = 8

    dyn_entries = []
    for off in needed_offsets:
        dyn_entries.append((1, off))  # DT_NEEDED
    dyn_entries.append((5, 0))  # DT_STRTAB (placeholder)
    dyn_entries.append((0, 0))  # DT_NULL

    if is_64:
        dynamic_data = b""
        for tag, val in dyn_entries:
            dynamic_data += struct.pack("<qQ", tag, val)
    else:
        dynamic_data = b""
        for tag, val in dyn_entries:
            dynamic_data += struct.pack("<iI", tag, val)

    if is_64:
        ehdr_size = 64
        shent_size = 64
        e_machine = 62
        ei_class = 2
    else:
        ehdr_size = 52
        shent_size = 40
        e_machine = 3
        ei_class = 1

    # Layout: ehdr | dynamic | strtab | shstrtab | section headers
    dynamic_offset = ehdr_size
    strtab_offset = dynamic_offset + len(dynamic_data)
    shstrtab_offset = strtab_offset + len(strtab_data)
    sh_offset = shstrtab_offset + len(shstrtab_data)
    # Align to 8
    if sh_offset % 8 != 0:
        padding = 8 - (sh_offset % 8)
        shstrtab_data += b"\x00" * padding
        sh_offset = shstrtab_offset + len(shstrtab_data)

    num_sections = 4  # null + .dynamic + .dynstr + .shstrtab

    ident = b"\x7fELF"
    ident += struct.pack("B", ei_class)
    ident += struct.pack("B", 1)  # little endian
    ident += struct.pack("B", 1)  # EV_CURRENT
    ident += b"\x00" * 9

    if is_64:
        ehdr = ident
        ehdr += struct.pack("<H", 2)    # e_type ET_EXEC
        ehdr += struct.pack("<H", e_machine)
        ehdr += struct.pack("<I", 1)    # e_version
        ehdr += struct.pack("<Q", 0)    # e_entry
        ehdr += struct.pack("<Q", 0)    # e_phoff
        ehdr += struct.pack("<Q", sh_offset)  # e_shoff
        ehdr += struct.pack("<I", 0)    # e_flags
        ehdr += struct.pack("<H", ehdr_size)
        ehdr += struct.pack("<H", 0)    # e_phentsize
        ehdr += struct.pack("<H", 0)    # e_phnum
        ehdr += struct.pack("<H", shent_size)
        ehdr += struct.pack("<H", num_sections)
        ehdr += struct.pack("<H", 3)    # e_shstrndx
    else:
        ehdr = ident
        ehdr += struct.pack("<H", 2)
        ehdr += struct.pack("<H", e_machine)
        ehdr += struct.pack("<I", 1)
        ehdr += struct.pack("<I", 0)    # e_entry
        ehdr += struct.pack("<I", 0)    # e_phoff
        ehdr += struct.pack("<I", sh_offset)
        ehdr += struct.pack("<I", 0)
        ehdr += struct.pack("<H", ehdr_size)
        ehdr += struct.pack("<H", 0)
        ehdr += struct.pack("<H", 0)
        ehdr += struct.pack("<H", shent_size)
        ehdr += struct.pack("<H", num_sections)
        ehdr += struct.pack("<H", 3)

    def make_shdr(sh_name, sh_type, sh_offset, sh_size, sh_link=0):
        if is_64:
            # Elf64_Shdr: name(I) type(I) flags(Q) addr(Q) offset(Q) size(Q) link(I) info(I) addralign(Q) entsize(Q) = 64 bytes
            return struct.pack("<IIQQQQIIQQ",
                               sh_name, sh_type, 0, 0,
                               sh_offset, sh_size, sh_link, 0, 1, 0)
        else:
            return struct.pack("<IIIIIIIIII",
                               sh_name, sh_type, 0, 0,
                               sh_offset, sh_size, sh_link, 0, 1, 0)

    # Section 0: null
    shdrs = make_shdr(0, 0, 0, 0)
    # Section 1: .dynamic (type=6, link=2 for strtab)
    shdrs += make_shdr(name_offsets[1], 6, dynamic_offset, len(dynamic_data), sh_link=2)
    # Section 2: .dynstr (type=3)
    shdrs += make_shdr(name_offsets[2], 3, strtab_offset, len(strtab_data))
    # Section 3: .shstrtab (type=3)
    shdrs += make_shdr(name_offsets[3], 3, shstrtab_offset, len(shstrtab_data))

    binary = ehdr + dynamic_data + strtab_data + shstrtab_data + shdrs

    path.write_bytes(binary)
    return path


def _build_debuglink_elf(path, debuglink_name):
    """Build a minimal 64-bit ELF whose .gnu_debuglink names debuglink_name.

    Mirrors Ubuntu libc, where .gnu_debuglink holds the build-id-named
    debug file (e.g. <hash>.debug) shipped separately in libc6-dbg.
    """
    ehdr_size = 64
    shent_size = 64

    # .gnu_debuglink contents: NUL-terminated filename + 4-byte CRC (zero
    # placeholder here; only the string is meaningful to our parser)
    debuglink_data = debuglink_name.encode("ascii") + b"\x00"
    debuglink_data += b"\x00" * (4 - len(debuglink_data) % 4 or 4)

    shstrtab_data = b"\x00.gnu_debuglink\x00.shstrtab\x00"
    debuglink_name_off = 1
    shstrtab_name_off = 1 + len(b".gnu_debuglink\x00")

    debuglink_offset = ehdr_size
    shstrtab_offset = debuglink_offset + len(debuglink_data)
    sh_offset = shstrtab_offset + len(shstrtab_data)
    if sh_offset % 8 != 0:
        shstrtab_data += b"\x00" * (8 - sh_offset % 8)
        sh_offset = shstrtab_offset + len(shstrtab_data)

    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    ehdr = ident
    ehdr += struct.pack("<HHI", 2, 62, 1)
    ehdr += struct.pack("<QQQ", 0, 0, sh_offset)
    ehdr += struct.pack("<IHHHHHH", 0, ehdr_size, 0, 0, shent_size, 3, 2)

    # Elf64_Shdr = IIQQQQIIQQ (64 bytes)
    null_sh = struct.pack("<IIQQQQIIQQ", *([0] * 10))
    debuglink_sh = struct.pack(
        "<IIQQQQIIQQ",
        debuglink_name_off, 1, 0, 0,
        debuglink_offset, len(debuglink_data),
        0, 0, 1, 0,
    )
    shstrtab_sh = struct.pack(
        "<IIQQQQIIQQ",
        shstrtab_name_off, 3, 0, 0,
        shstrtab_offset, len(shstrtab_data),
        0, 0, 1, 0,
    )

    path.write_bytes(
        ehdr + debuglink_data + shstrtab_data + null_sh + debuglink_sh + shstrtab_sh
    )
    return path


@pytest.fixture
def minimal_elf_amd64(tmp_path):
    """A synthetic amd64 ELF with DT_NEEDED libc.so.6."""
    return _build_minimal_elf(
        tmp_path / "test_amd64",
        arch="amd64",
        needed=["libc.so.6"],
    )


@pytest.fixture
def minimal_elf_i686(tmp_path):
    """A synthetic i686 ELF with DT_NEEDED libc.so.6."""
    return _build_minimal_elf(
        tmp_path / "test_i686",
        arch="i686",
        needed=["libc.so.6"],
    )


@pytest.fixture
def minimal_elf_multi_needed(tmp_path):
    """A synthetic amd64 ELF with multiple DT_NEEDED entries."""
    return _build_minimal_elf(
        tmp_path / "test_multi",
        arch="amd64",
        needed=["libc.so.6", "libpthread.so.0", "libm.so.6", "libdl.so.2"],
    )


def build_test_binary(tmp_path, arch="amd64"):
    """Compile a real minimal C binary for patch/run testing.

    Returns the path to the compiled binary, or None if compilation fails.
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    c_src = tmp_path / "test_hello.c"
    c_src.write_text('#include <stdio.h>\nint main(){puts("pwnlibc-test-ok");return 0;}\n')
    out = tmp_path / "test_hello"

    gcc = "gcc"
    flags = []
    if arch == "i686":
        flags = ["-m32"]

    try:
        subprocess.run(
            [gcc] + flags + ["-o", str(out), str(c_src), "-static-libgcc"],
            check=True, capture_output=True, text=True,
        )
        os.chmod(str(out), 0o755)
        return out
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def build_cross_test_binary(tmp_path, arch):
    """Cross-compile a minimal C binary for a given architecture.

    Returns the path to the compiled binary, or None if compilation fails
    (e.g. cross-compiler not installed).
    """
    from pwnlibc.config import ARCH_INFO

    tmp_path.mkdir(parents=True, exist_ok=True)
    c_src = tmp_path / f"test_cross_{arch}.c"
    c_src.write_text('#include <stdio.h>\nint main(){puts("pwnlibc-test-ok");return 0;}\n')
    out = tmp_path / f"test_cross_{arch}"

    cross_triplet = ARCH_INFO[arch]["cross_triplet"]
    gcc = f"{cross_triplet}-gcc"

    try:
        subprocess.run(
            [gcc, "-o", str(out), str(c_src), "-static"],
            check=True, capture_output=True, text=True,
        )
        os.chmod(str(out), 0o755)
        return out
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


SAMPLE_MIRROR_HTML = """
<html><body>
<a href="libc6_2.27-3ubuntu1.6_amd64.deb">libc6_2.27-3ubuntu1.6_amd64.deb</a>
<a href="libc6_2.27-3ubuntu1.6_i386.deb">libc6_2.27-3ubuntu1.6_i386.deb</a>
<a href="libc6-dbg_2.27-3ubuntu1.6_amd64.deb">libc6-dbg_2.27-3ubuntu1.6_amd64.deb</a>
<a href="libc6-dbg_2.27-3ubuntu1.6_i386.deb">libc6-dbg_2.27-3ubuntu1.6_i386.deb</a>
<a href="libc6_2.31-0ubuntu9.16_amd64.deb">libc6_2.31-0ubuntu9.16_amd64.deb</a>
<a href="libc6_2.31-0ubuntu9.16_i386.deb">libc6_2.31-0ubuntu9.16_i386.deb</a>
<a href="libc6-dbg_2.31-0ubuntu9.16_amd64.deb">libc6-dbg_2.31-0ubuntu9.16_amd64.deb</a>
<a href="libc6_2.35-0ubuntu3.8_amd64.deb">libc6_2.35-0ubuntu3.8_amd64.deb</a>
<a href="libc6_2.35-0ubuntu3.8_i386.deb">libc6_2.35-0ubuntu3.8_i386.deb</a>
<a href="libc6-dbg_2.35-0ubuntu3.8_amd64.deb">libc6-dbg_2.35-0ubuntu3.8_amd64.deb</a>
<a href="libc6-dbg_2.35-0ubuntu3.8_i386.deb">libc6-dbg_2.35-0ubuntu3.8_i386.deb</a>
<a href="libc6_2.39-0ubuntu8.4_amd64.deb">libc6_2.39-0ubuntu8.4_amd64.deb</a>
<a href="libc6-dbg_2.39-0ubuntu8.4_amd64.deb">libc6-dbg_2.39-0ubuntu8.4_amd64.deb</a>
</body></html>
"""
