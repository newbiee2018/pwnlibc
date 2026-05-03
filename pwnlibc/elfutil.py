from __future__ import annotations

import struct
from pathlib import Path

ELF_MAGIC = b"\x7fELF"

ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5

SHT_DYNAMIC = 6
SHT_STRTAB = 3

ELFDATA2MSB = 2

# (e_machine, ei_class) -> pwnlibc arch name
_MACHINE_MAP = {
    (62, ELFCLASS64): "amd64",
    (3, ELFCLASS32): "i686",
    (183, ELFCLASS64): "arm64",
    (40, ELFCLASS32): "armhf",
    (21, ELFCLASS64): "ppc64el",
    (22, ELFCLASS64): "s390x",
    (243, ELFCLASS64): "riscv64",
}


def detect_arch(path: Path) -> str:
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != ELF_MAGIC:
            raise ValueError(f"Not an ELF binary: {path}")
        ei_class = struct.unpack("B", f.read(1))[0]
        ei_data = struct.unpack("B", f.read(1))[0]
        f.seek(18)
        # e_machine is always at offset 18; use host endian based on ei_data
        raw = f.read(2)
        if ei_data == ELFDATA2MSB:
            e_machine = struct.unpack(">H", raw)[0]
        else:
            e_machine = struct.unpack("<H", raw)[0]

    key = (e_machine, ei_class)
    arch = _MACHINE_MAP.get(key)
    if arch is None:
        raise ValueError(f"Unsupported ELF architecture: e_machine={e_machine}, class={ei_class}")
    return arch


def _read_elf_header(f):
    f.seek(0)
    ident = f.read(16)
    if ident[:4] != ELF_MAGIC:
        raise ValueError("Not an ELF file")
    ei_class = ident[4]
    ei_data = ident[5]

    endian = ">" if ei_data == ELFDATA2MSB else "<"

    if ei_class == ELFCLASS64:
        fmt_half = f"{endian}H"
        fmt_word = f"{endian}I"
        fmt_xword = f"{endian}Q"
        fmt_addr = f"{endian}Q"
        fmt_off = f"{endian}Q"
        ehdr_size = 64
        shentsize = 64
    else:
        fmt_half = f"{endian}H"
        fmt_word = f"{endian}I"
        fmt_xword = f"{endian}I"
        fmt_addr = f"{endian}I"
        fmt_off = f"{endian}I"
        ehdr_size = 52
        shentsize = 40

    f.seek(0)
    ehdr = f.read(ehdr_size)

    if ei_class == ELFCLASS64:
        e_shoff = struct.unpack_from(fmt_off, ehdr, 40)[0]
        e_shentsize = struct.unpack_from(fmt_half, ehdr, 58)[0]
        e_shnum = struct.unpack_from(fmt_half, ehdr, 60)[0]
        e_shstrndx = struct.unpack_from(fmt_half, ehdr, 62)[0]
    else:
        e_shoff = struct.unpack_from(fmt_off, ehdr, 32)[0]
        e_shentsize = struct.unpack_from(fmt_half, ehdr, 46)[0]
        e_shnum = struct.unpack_from(fmt_half, ehdr, 48)[0]
        e_shstrndx = struct.unpack_from(fmt_half, ehdr, 50)[0]

    return {
        "ei_class": ei_class,
        "endian": endian,
        "e_shoff": e_shoff,
        "e_shentsize": e_shentsize,
        "e_shnum": e_shnum,
        "e_shstrndx": e_shstrndx,
        "fmt_word": fmt_word,
        "fmt_xword": fmt_xword,
        "fmt_addr": fmt_addr,
        "fmt_off": fmt_off,
        "fmt_half": fmt_half,
    }


def _read_section_headers(f, hdr):
    sections = []
    for i in range(hdr["e_shnum"]):
        offset = hdr["e_shoff"] + i * hdr["e_shentsize"]
        f.seek(offset)
        data = f.read(hdr["e_shentsize"])

        sh_name = struct.unpack_from(hdr["fmt_word"], data, 0)[0]
        sh_type = struct.unpack_from(hdr["fmt_word"], data, 4)[0]

        if hdr["ei_class"] == ELFCLASS64:
            sh_offset = struct.unpack_from(hdr["fmt_off"], data, 24)[0]
            sh_size = struct.unpack_from(hdr["fmt_xword"], data, 32)[0]
            sh_link = struct.unpack_from(hdr["fmt_word"], data, 40)[0]
        else:
            sh_offset = struct.unpack_from(hdr["fmt_off"], data, 16)[0]
            sh_size = struct.unpack_from(hdr["fmt_xword"], data, 20)[0]
            sh_link = struct.unpack_from(hdr["fmt_word"], data, 24)[0]

        sections.append({
            "sh_name": sh_name,
            "sh_type": sh_type,
            "sh_offset": sh_offset,
            "sh_size": sh_size,
            "sh_link": sh_link,
        })
    return sections


def _read_cstring(data: bytes, offset: int) -> str:
    end = data.index(b"\x00", offset)
    return data[offset:end].decode("ascii", errors="replace")


def get_needed_libs(path: Path) -> list[str]:
    needed = []
    with open(path, "rb") as f:
        hdr = _read_elf_header(f)
        sections = _read_section_headers(f, hdr)

        dynamic = None
        for sec in sections:
            if sec["sh_type"] == SHT_DYNAMIC:
                dynamic = sec
                break
        if dynamic is None:
            return needed

        strtab_sec = sections[dynamic["sh_link"]]
        f.seek(strtab_sec["sh_offset"])
        strtab_data = f.read(strtab_sec["sh_size"])

        entry_size = 16 if hdr["ei_class"] == ELFCLASS64 else 8
        f.seek(dynamic["sh_offset"])
        dyn_data = f.read(dynamic["sh_size"])

        endian = hdr["endian"]
        for i in range(0, len(dyn_data), entry_size):
            if hdr["ei_class"] == ELFCLASS64:
                d_tag = struct.unpack_from(f"{endian}q", dyn_data, i)[0]
                d_val = struct.unpack_from(f"{endian}Q", dyn_data, i + 8)[0]
            else:
                d_tag = struct.unpack_from(f"{endian}i", dyn_data, i)[0]
                d_val = struct.unpack_from(f"{endian}I", dyn_data, i + 4)[0]
            if d_tag == DT_NULL:
                break
            if d_tag == DT_NEEDED:
                name = _read_cstring(strtab_data, d_val)
                needed.append(name)

    return needed


def has_debug_info(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            hdr = _read_elf_header(f)
            sections = _read_section_headers(f, hdr)

            shstrtab = sections[hdr["e_shstrndx"]]
            f.seek(shstrtab["sh_offset"])
            shstrtab_data = f.read(shstrtab["sh_size"])

            for sec in sections:
                name = _read_cstring(shstrtab_data, sec["sh_name"])
                if name == ".debug_info":
                    return True
    except Exception:
        pass
    return False
