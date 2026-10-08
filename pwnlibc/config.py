from __future__ import annotations

import os
from pathlib import Path

BACKUP_SUFFIX = ".bak"

NEW_NAMING_MIN = (2, 34)

GLIBC_DIR_ENV = "PWNLIBC_DIR"


def _config_file() -> Path:
    return Path.home() / ".config" / "pwnlibc" / "glibc_dir"


def _default_data_dir() -> Path:
    return Path.home() / ".local" / "share" / "pwnlibc"


def _dir_from_config() -> Path | None:
    """The directory the user chose during `bash install.sh` (if any)."""
    try:
        text = _config_file().read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return Path(text) if text else None


def resolve_glibc_dir() -> Path:
    """Where glibc versions live.

    Resolution order: $PWNLIBC_DIR, then the config file written by
    install.sh (~/.config/pwnlibc/glibc_dir), then the default
    ~/.local/share/pwnlibc.
    """
    env = os.environ.get(GLIBC_DIR_ENV, "").strip()
    if env:
        return Path(env)
    return _dir_from_config() or _default_data_dir()


DEFAULT_GLIBC_DIR = resolve_glibc_dir()

ARCH_INFO = {
    "amd64": {
        "elf_machine": 62,
        "elf_class": 2,
        "ld_soname": "ld-linux-x86-64.so.2",
        "deb_arch": "amd64",
        "deb_lib_dir": "x86_64-linux-gnu",
        "mirror": "ubuntu",
    },
    "i686": {
        "elf_machine": 3,
        "elf_class": 1,
        "ld_soname": "ld-linux.so.2",
        "deb_arch": "i386",
        "deb_lib_dir": "i386-linux-gnu",
        "mirror": "ubuntu",
    },
    "arm64": {
        "elf_machine": 183,
        "elf_class": 2,
        "ld_soname": "ld-linux-aarch64.so.1",
        "deb_arch": "arm64",
        "deb_lib_dir": "aarch64-linux-gnu",
        "mirror": "ports",
    },
    "armhf": {
        "elf_machine": 40,
        "elf_class": 1,
        "ld_soname": "ld-linux-armhf.so.3",
        "deb_arch": "armhf",
        "deb_lib_dir": "arm-linux-gnueabihf",
        "mirror": "ports",
    },
    "ppc64el": {
        "elf_machine": 21,
        "elf_class": 2,
        "ld_soname": "ld64.so.2",
        "deb_arch": "ppc64el",
        "deb_lib_dir": "powerpc64le-linux-gnu",
        "mirror": "ports",
    },
    "s390x": {
        "elf_machine": 22,
        "elf_class": 2,
        "ld_soname": "ld64.so.1",
        "deb_arch": "s390x",
        "deb_lib_dir": "s390x-linux-gnu",
        "mirror": "ports",
    },
    "riscv64": {
        "elf_machine": 243,
        "elf_class": 2,
        "ld_soname": "ld-linux-riscv64-lp64d.so.1",
        "deb_arch": "riscv64",
        "deb_lib_dir": "riscv64-linux-gnu",
        "mirror": "ports",
        "cross_gcc": "gcc-riscv64-linux-gnu",
        "cross_triplet": "riscv64-linux-gnu",
    },
    "powerpc": {
        "elf_machine": 20,
        "elf_class": 1,
        "ld_soname": "ld.so.1",
        "deb_arch": "powerpc",
        "deb_lib_dir": "powerpc-linux-gnu",
        "mirror": "old-ubuntu",
        "cross_gcc": "gcc-powerpc-linux-gnu",
        "cross_triplet": "powerpc-linux-gnu",
    },
    "mipsel": {
        "elf_machine": 8,
        "elf_class": 1,
        "ld_soname": "ld.so.1",
        "deb_arch": "mipsel",
        "deb_lib_dir": "mipsel-linux-gnu",
        "mirror": "debian",
        "cross_gcc": "gcc-mipsel-linux-gnu",
        "cross_triplet": "mipsel-linux-gnu",
    },
    "mips64el": {
        "elf_machine": 8,
        "elf_class": 2,
        "ld_soname": "ld.so.1",
        "deb_arch": "mips64el",
        "deb_lib_dir": "mips64el-linux-gnuabi64",
        "mirror": "debian",
        "cross_gcc": "gcc-mips64el-linux-gnuabi64",
        "cross_triplet": "mips64el-linux-gnuabi64",
    },
}

# Back-fill cross-compiler info for arches that don't have it yet
_CROSS_DEFAULTS = {
    "amd64": ("gcc", "x86_64-linux-gnu"),
    "i686": ("gcc", "i686-linux-gnu"),
    "arm64": ("gcc-aarch64-linux-gnu", "aarch64-linux-gnu"),
    "armhf": ("gcc-arm-linux-gnueabihf", "arm-linux-gnueabihf"),
    "ppc64el": ("gcc-powerpc64le-linux-gnu", "powerpc64le-linux-gnu"),
    "s390x": ("gcc-s390x-linux-gnu", "s390x-linux-gnu"),
}
for _arch, (_gcc, _triplet) in _CROSS_DEFAULTS.items():
    ARCH_INFO[_arch].setdefault("cross_gcc", _gcc)
    ARCH_INFO[_arch].setdefault("cross_triplet", _triplet)

ALL_ARCHES = list(ARCH_INFO.keys())
X86_ARCHES = ["amd64", "i686"]

# All mirrors serve identical pool content over TLS with valid certificates
# (and plain http is NOT redirected), so https is used throughout.
MIRRORS = {
    "ubuntu": "https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/",
    "old-ubuntu": "https://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/",
    "tsinghua": "https://mirror.tuna.tsinghua.edu.cn/ubuntu/pool/main/g/glibc/",
    # NB: ports.ubuntu.com serves its pool WITHOUT the /ubuntu prefix
    "ports": "https://ports.ubuntu.com/pool/main/g/glibc/",
    "debian": "https://deb.debian.org/debian/pool/main/g/glibc/",
    "old-debian": "https://archive.debian.org/debian/pool/main/g/glibc/",
}

GNU_SOURCE_BASE = "https://ftp.gnu.org/gnu/glibc/"
GNU_SOURCE_FORMATS = [
    "glibc-{version}.tar.xz",
    "glibc-{version}.tar.gz",
    "glibc-{version}.tar.bz2",
]


def gnu_source_version(version: str) -> str:
    """Strip .ds1 suffix — 2.3.2.ds1 uses glibc-2.3.2 source."""
    return version.replace(".ds1", "")

BUILD_DEPS = ["make", "gawk", "bison", "python3"]


def parse_version(version: str) -> tuple[int, ...]:
    clean = version.replace(".ds1", "")
    parts = clean.split(".")
    return tuple(int(p) for p in parts)


def uses_new_naming(version: str) -> bool:
    return parse_version(version) >= NEW_NAMING_MIN


def get_libc_real_name(version: str) -> str:
    if uses_new_naming(version):
        return "libc.so.6"
    return f"libc-{version}.so"


def get_ld_real_name(version: str, arch: str) -> str:
    if uses_new_naming(version):
        return ARCH_INFO[arch]["ld_soname"]
    return f"ld-{version}.so"
