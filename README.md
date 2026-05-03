# pwnlibc

CTF glibc manager and ELF patcher. Downloads prebuilt glibc from Ubuntu mirrors, builds from source with debug symbols, verifies integrity, and patches ELF binaries to use a specific glibc version via `patchelf`.

## Requirements

- Python 3.8+
- `patchelf` (`sudo apt install patchelf`)
- `ar` (from `binutils`, usually pre-installed)
- `zstd` (for Ubuntu 22.04+ `.deb` files: `sudo apt install zstd`)
- For source builds: `make`, `gawk`, `bison`, cross-compiler (see `pwnlibc build`)

## Install

```bash
cd pwnlibc/
bash install.sh
```

This installs Python dependencies (`click`, `rich`), adds the package to Python's path, and creates `/usr/local/bin/pwnlibc`.

Alternatively, run directly without installing:

```bash
pip3 install click rich
python3 -m pwnlibc --help
```

## Quick start

```bash
# See what's available
pwnlibc available --arch amd64

# Download glibc 2.31 (amd64 + i686, with debug symbols)
sudo pwnlibc download 2.31

# Download multiple versions at once
sudo pwnlibc download 2.27 2.31 2.35

# Download everything available for amd64
sudo pwnlibc download-all --arch amd64

# List what you have
pwnlibc list

# Patch a CTF binary
pwnlibc patch ./vuln -v 2.31

# Done — run it
./vuln

# Restore the original
pwnlibc restore ./vuln

# Build from source with full debug symbols
sudo pwnlibc build 2.31 --arch amd64
```

## Commands

### `pwnlibc list`

Show all installed glibc versions with their variants.

```bash
pwnlibc list                    # table of installed versions
pwnlibc list --arch amd64       # filter by architecture
```

The table shows per-architecture availability (including whether each is a `deb` install or source `built`), debug symbol status, source availability, and naming style.

### `pwnlibc available`

List all glibc versions available for download from Ubuntu mirrors.

```bash
pwnlibc available                          # show all arches, all mirrors
pwnlibc available --arch amd64             # just amd64
pwnlibc available --arch arm64             # just arm64 (from ports.ubuntu.com)
pwnlibc available --arch powerpc           # just powerpc (from old-releases)
pwnlibc available --mirror old-ubuntu      # only old-releases mirror
```

Shows a numbered table with version, arch, debug .deb availability, and whether already installed.

### `pwnlibc download VERSION [VERSION ...]`

Download one or more glibc versions from Ubuntu mirrors.

```bash
pwnlibc download 2.31                          # amd64+i686, with debug
pwnlibc download 2.27 2.31 2.35                # multiple versions at once
pwnlibc download 2.39 --arch arm64             # arm64 only
pwnlibc download 2.39 --no-dbg                 # skip debug symbols
pwnlibc download 2.39 --source                 # also grab GNU source
pwnlibc download 2.23 --mirror old-ubuntu      # EOL Ubuntu releases
pwnlibc download 2.19 --arch powerpc --mirror old-ubuntu  # old powerpc
```

Downloads `libc6` and `libc6-dbg` `.deb` packages, extracts them, and installs to `/glibc/<version>/<arch>/lib/`.

Mirror auto-selection: x86 from `archive.ubuntu.com`, non-x86 from `ports.ubuntu.com`, powerpc from `old-releases.ubuntu.com`. Override with `--mirror`.

### `pwnlibc download-all`

Download all available glibc versions for specified architecture(s).

```bash
pwnlibc download-all                        # all versions for amd64+i686
pwnlibc download-all --arch arm64           # all versions for arm64
pwnlibc download-all --arch powerpc         # all powerpc versions
pwnlibc download-all --check                # dry run: show what would be downloaded
```

Skips versions already installed.

### `pwnlibc build VERSION [VERSION ...] --arch ARCH`

Build glibc from GNU source with full debug symbols (`-g3 -O1`).

```bash
pwnlibc build 2.31 --arch amd64              # native build
pwnlibc build 2.27 2.31 --arch arm64         # cross-compile for arm64
pwnlibc build 2.19 --arch powerpc            # cross-compile for powerpc
```

Creates a separate `<arch>-built` variant under `/glibc/<version>/`. This coexists with deb-installed versions — use `pwnlibc patch --variant built` to select it, or let `--variant auto` (default) pick the deb first.

**Toolchain requirements**: The build command checks for required tools and shows the install command if anything is missing:

| Target arch | Cross-compiler package |
|---|---|
| amd64 | `gcc` (native) |
| i686 | `gcc`, `gcc-multilib` |
| arm64 | `gcc-aarch64-linux-gnu` |
| armhf | `gcc-arm-linux-gnueabihf` |
| ppc64el | `gcc-powerpc64le-linux-gnu` |
| powerpc | `gcc-powerpc-linux-gnu` |
| s390x | `gcc-s390x-linux-gnu` |
| riscv64 | `gcc-riscv64-linux-gnu` |

Plus: `make`, `gawk`, `bison`, `python3`.

**Three variants of glibc** can coexist per version/arch:
- **deb**: Extracted from Ubuntu `libc6` package (prebuilt, optimized)
- **deb-dbg**: Debug symbols from `libc6-dbg` package (added to `deb` via `.debug/` dir)
- **built**: Compiled from source with `-g3` (full debug info baked into the binary itself)

### `pwnlibc patch BINARY`

Patch an ELF binary to use a specific glibc version.

```bash
pwnlibc patch ./vuln -v 2.27                        # copy mode (default)
pwnlibc patch ./vuln -v 2.35 -m inplace              # inplace mode
pwnlibc patch ./vuln -v 2.27 --no-backup             # skip backup
pwnlibc patch ./vuln -v 2.27 -a i686                 # force 32-bit
pwnlibc patch ./vuln -v 2.31 --variant built          # use source-built variant
```

**Copy mode** (default): Copies `libc-<ver>.so`, `ld-<ver>.so`, and any other NEEDED libraries to the binary's directory. Patches the binary with relative paths. The binary must be run from its directory.

**Inplace mode**: Sets the ELF interpreter and RPATH to absolute paths pointing at `/glibc/<ver>/<arch>/lib/`. No files copied. The binary can be run from anywhere, but breaks if `/glibc/` is moved.

Architecture is auto-detected from the ELF header. A `.bak` backup is created before patching (auto-numbered if multiple patches).

### `pwnlibc restore BINARY`

Restore a binary from its most recent backup.

```bash
pwnlibc restore ./vuln
```

### `pwnlibc update`

Find and download all glibc versions available on mirrors but not yet installed.

```bash
pwnlibc update --check        # dry run
pwnlibc update                # download all missing (x86)
pwnlibc update --arch arm64   # update arm64
```

### `pwnlibc verify`

Compare installed glibc files against official Ubuntu `.deb` packages (SHA256).

```bash
pwnlibc verify                # check all deb-installed versions
pwnlibc verify --fix          # re-download mismatched/missing files
```

Only verifies `deb` variant installs (not source-built ones).

### `pwnlibc setup`

Extract existing `.tar.gz` archives (from `debug_glibc/`) to the glibc directory.

```bash
sudo pwnlibc setup
sudo pwnlibc setup --archive-dir /path/to/debug_glibc
```

### `pwnlibc info BINARY`

Show ELF info: architecture, interpreter, RPATH, and NEEDED libraries.

```bash
pwnlibc info ./vuln
```

## Glibc directory layout

```
/glibc/
├── .cache/                    # downloaded .deb files
├── 2.23/
│   ├── amd64/                 # from libc6 .deb (deb variant)
│   │   └── lib/
│   │       ├── libc-2.23.so
│   │       ├── ld-2.23.so
│   │       ├── .debug/        # from libc6-dbg .deb
│   │       └── ...
│   ├── amd64-built/           # from source build (built variant)
│   │   └── lib/
│   │       ├── libc-2.23.so   # compiled with -g3
│   │       └── ...
│   ├── i686/
│   ├── arm64/
│   └── source/
│       └── glibc-2.23/
├── 2.35/
│   └── amd64/
│       └── lib/
│           ├── libc.so.6            # (new naming, >=2.34)
│           ├── ld-linux-x86-64.so.2
│           └── ...
└── ...
```

## Architecture support

| Architecture | Pwnlibc name | Download source | Build | Version range |
|---|---|---|---|---|
| x86-64 | `amd64` | archive.ubuntu.com | native | 2.4+ |
| x86 32-bit | `i686` | archive.ubuntu.com | native | 2.4+ |
| AArch64 | `arm64` | ports.ubuntu.com | cross | 2.23+ |
| ARM hard-float | `armhf` | ports.ubuntu.com | cross | 2.23+ |
| POWER 64-bit LE | `ppc64el` | ports.ubuntu.com | cross | 2.23+ |
| IBM z/Arch | `s390x` | ports.ubuntu.com | cross | 2.23+ |
| RISC-V 64-bit | `riscv64` | ports.ubuntu.com | cross | 2.31+ |
| PowerPC 32-bit | `powerpc` | old-releases.ubuntu.com | cross | 2.3-2.24 (discontinued) |

Older versions (2.3.x, 2.4, 2.5, 2.7, 2.9, 2.19, 2.21) are available on `old-releases.ubuntu.com` for x86 and powerpc. Use `--mirror old-ubuntu` to access them.

**Cross-architecture patching**: `patchelf` works on any architecture from any host — it manipulates ELF headers without executing the binary.

**Running non-x86 binaries**:
```bash
sudo apt install qemu-user qemu-user-static
qemu-aarch64 ./arm_binary      # after patching with pwnlibc
```

**MIPS**: Not on Ubuntu mirrors. Debian ships mipsel/mips64el at `ftp.debian.org` (glibc 2.36). Older versions via [snapshot.debian.org](https://snapshot.debian.org/). Not automated by pwnlibc yet.

## Glibc 2.34 naming change

| | glibc <= 2.33 | glibc >= 2.34 |
|---|---|---|
| libc | `libc-2.XX.so` (real file) | `libc.so.6` (real file) |
| ld (amd64) | `ld-2.XX.so` (real file) | `ld-linux-x86-64.so.2` (real file) |
| libpthread | `libpthread-2.XX.so` (real file) | stub (merged into libc) |

Handled transparently. In copy mode, libs are always renamed to `libc-<ver>.so` / `ld-<ver>.so`.

## Typical CTF workflow

1. Get challenge binary `vuln` and `libc.so.6` from the remote server.

2. Identify the libc version:
   ```bash
   strings libc.so.6 | grep 'GNU C Library'
   ```

3. Download and patch:
   ```bash
   pwnlibc download 2.31
   pwnlibc patch ./vuln -v 2.31
   ```

4. Need full debug symbols for heap analysis? Build from source:
   ```bash
   pwnlibc build 2.31 --arch amd64
   pwnlibc patch ./vuln -v 2.31 --variant built
   ```

5. Debug with GDB + source:
   ```bash
   gdb ./vuln
   # Source at /glibc/2.31/source/glibc-2.31/malloc/malloc.c
   ```

## Configuration

**Glibc directory**: Default `/glibc/`. Override with `--glibc-dir` or:
```bash
export PWNLIBC_DIR=/opt/glibc
```

## Project structure

```
pwnlibc/
├── pwnlibc/
│   ├── __init__.py        # version
│   ├── __main__.py        # python -m pwnlibc entrypoint
│   ├── cli.py             # click CLI commands
│   ├── config.py          # arch table, mirrors, naming rules, build deps
│   ├── elfutil.py         # pure-Python ELF parser (arch detect, NEEDED libs)
│   ├── glibc.py           # glibc install discovery and path resolution
│   ├── patcher.py         # patchelf operations (copy + inplace modes)
│   ├── downloader.py      # mirror scraping, .deb download/extract, verify
│   ├── builder.py         # source download, configure, cross-compile
│   └── backup.py          # backup/restore logic
├── tests/                 # pytest suite (113+ tests)
├── requirements.txt
├── install.sh
└── README.md
```

### Adding new architectures

1. Add entry to `ARCH_INFO` in `config.py`: `elf_machine`, `elf_class`, `ld_soname`, `deb_arch`, `deb_lib_dir`, `mirror`, `cross_gcc`, `cross_triplet`
2. Add `(elf_machine, elf_class)` to `_MACHINE_MAP` in `elfutil.py`
3. Everything else is data-driven
