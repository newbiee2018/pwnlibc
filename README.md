# pwnlibc

CTF glibc manager and ELF patcher. Downloads prebuilt glibc from Ubuntu mirrors, verifies integrity, and patches ELF binaries to use a specific glibc version via `patchelf`.

## Requirements

- Python 3.8+
- `patchelf` (`sudo apt install patchelf`)
- `ar` (from `binutils`, usually pre-installed)
- `zstd` (for Ubuntu 22.04+ `.deb` files: `sudo apt install zstd`)

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
# Download glibc 2.31 (amd64 + i686, with debug symbols)
sudo pwnlibc download 2.31

# List what you have
pwnlibc list

# Patch a CTF binary
pwnlibc patch ./vuln -v 2.31

# Done — run it
./vuln

# Restore the original
pwnlibc restore ./vuln
```

## Commands

### `pwnlibc list`

Show all installed glibc versions.

```bash
pwnlibc list                    # table of installed versions
pwnlibc list --available        # also show what's downloadable
pwnlibc list --arch amd64       # filter by architecture
```

The table shows per-architecture availability, debug symbol status, and naming style (old for <=2.33, new for >=2.34).

### `pwnlibc patch BINARY`

Patch an ELF binary to use a specific glibc version.

```bash
pwnlibc patch ./vuln -v 2.27              # copy mode (default)
pwnlibc patch ./vuln -v 2.35 -m inplace   # inplace mode
pwnlibc patch ./vuln -v 2.27 --no-backup  # skip backup
pwnlibc patch ./vuln -v 2.27 -a i686      # force 32-bit
```

**Copy mode** (default): Copies `libc-<ver>.so`, `ld-<ver>.so`, and any other NEEDED libraries (libpthread, libm, etc.) to the binary's directory. Patches the binary with relative paths (`./libc-2.27.so`). The binary must be run from its directory.

**Inplace mode**: Sets the ELF interpreter and RPATH to absolute paths pointing at `/glibc/<ver>/<arch>/lib/`. No files copied. The binary can be run from anywhere, but breaks if `/glibc/` is moved.

Architecture is auto-detected from the ELF header. A `.bak` backup is created before patching (auto-numbered if multiple patches).

### `pwnlibc restore BINARY`

Restore a binary from its most recent backup.

```bash
pwnlibc restore ./vuln
```

Restores from the latest `.bak.N` file, or `.bak` if no numbered backups exist.

### `pwnlibc download VERSION`

Download a glibc version from Ubuntu package mirrors.

```bash
pwnlibc download 2.39                          # amd64+i686, with debug
pwnlibc download 2.39 --arch arm64             # arm64 only
pwnlibc download 2.39 --no-dbg                 # skip debug symbols
pwnlibc download 2.39 --source                 # also grab GNU source
pwnlibc download 2.23 --mirror old-ubuntu      # EOL Ubuntu releases
```

Downloads `libc6` and `libc6-dbg` `.deb` packages, extracts them, and installs to `/glibc/<version>/<arch>/lib/`.

Mirror auto-selection: x86 packages come from `archive.ubuntu.com`, non-x86 (arm64, armhf, ppc64el, s390x, riscv64) from `ports.ubuntu.com`. Override with `--mirror`.

### `pwnlibc update`

Find and download all glibc versions available on mirrors but not yet installed.

```bash
pwnlibc update --check        # dry run: show what would be downloaded
pwnlibc update                # download everything missing
pwnlibc update --arch arm64   # only update arm64
```

### `pwnlibc verify`

Compare installed glibc files against official Ubuntu `.deb` packages (SHA256).

```bash
pwnlibc verify                # check all installed versions
pwnlibc verify --fix          # re-download mismatched/missing files
```

Reports MATCH, MISMATCH, or MISSING for key files (`libc.so.6`, `ld-linux-x86-64.so.2`, etc.).

### `pwnlibc setup`

Extract existing `.tar.gz` archives (from `debug_glibc/`) to the glibc directory.

```bash
sudo pwnlibc setup                                      # auto-detect archives
sudo pwnlibc setup --archive-dir /path/to/debug_glibc   # specify location
sudo pwnlibc setup --target-dir /opt/glibc               # custom target
```

Skips versions that are already extracted.

### `pwnlibc info BINARY`

Show ELF info: architecture, interpreter, RPATH, and NEEDED libraries.

```bash
pwnlibc info ./vuln
```

## Glibc directory layout

All glibc versions live under a single root (default `/glibc/`, override with `--glibc-dir` or `PWNLIBC_DIR` env var):

```
/glibc/
├── .cache/                    # downloaded .deb files (for verify/re-download)
├── 2.23/
│   ├── amd64/
│   │   ├── lib/
│   │   │   ├── libc-2.23.so          # (old naming, <=2.33)
│   │   │   ├── libc.so.6 -> libc-2.23.so
│   │   │   ├── ld-2.23.so
│   │   │   ├── ld-linux-x86-64.so.2 -> ld-2.23.so
│   │   │   ├── libpthread-2.23.so
│   │   │   ├── .debug/              # debug symbols
│   │   │   └── ...
│   │   ├── include/
│   │   └── bin/
│   ├── i686/
│   │   └── lib/
│   └── source/                       # GNU source (if downloaded)
│       └── glibc-2.23/
├── 2.35/
│   └── amd64/
│       └── lib/
│           ├── libc.so.6            # (new naming, >=2.34: real file)
│           ├── ld-linux-x86-64.so.2 # (real file)
│           └── ...
└── 2.39/
    └── ...
```

## Architecture support

| Architecture | Pwnlibc name | ELF detection | Download source | Patchelf | Run on x86 host |
|---|---|---|---|---|---|
| x86-64 | `amd64` | yes | archive.ubuntu.com | native | native |
| x86 32-bit | `i686` | yes | archive.ubuntu.com | native | native |
| AArch64 | `arm64` | yes | ports.ubuntu.com | cross-arch | `qemu-aarch64` |
| ARM hard-float | `armhf` | yes | ports.ubuntu.com | cross-arch | `qemu-arm` |
| POWER 64-bit LE | `ppc64el` | yes | ports.ubuntu.com | cross-arch | `qemu-ppc64le` |
| IBM z/Arch | `s390x` | yes | ports.ubuntu.com | cross-arch | `qemu-s390x` |
| RISC-V 64-bit | `riscv64` | yes | ports.ubuntu.com | cross-arch | `qemu-riscv64` |

**Cross-architecture patching**: `patchelf` works on any architecture from any host — it only manipulates ELF headers, never executes the binary. You can patch an arm64 binary on an x86 host.

**Running non-x86 binaries**: Install QEMU user-mode emulation:

```bash
sudo apt install qemu-user qemu-user-static
```

Then run with the patched interpreter:

```bash
# After: pwnlibc patch ./arm_vuln -v 2.35 -a arm64 -m inplace
qemu-aarch64 ./arm_vuln

# Or with copy mode, from the binary's directory:
qemu-aarch64 -L /glibc/2.35/arm64 ./arm_vuln
```

**MIPS**: Not available from Ubuntu mirrors (Ubuntu dropped MIPS). Debian still ships mipsel/mips64el glibc packages (with `libc6-dbg`) at `http://ftp.debian.org/debian/pool/main/g/glibc/`. The current pool only has glibc 2.36 (Debian Bookworm). For older versions (2.19/Jessie, 2.24/Stretch, 2.28/Buster), use [snapshot.debian.org](https://snapshot.debian.org/). Debian MIPS packages are not automated by pwnlibc yet — manual download and extraction with `ar x` + `tar xf` works.

**Debug symbols**: All architectures on Ubuntu ports have `libc6-dbg` packages available. riscv64 starts at glibc 2.31 (Ubuntu 20.04); all others go back to 2.23 (Ubuntu 16.04). For versions where no prebuilt debug package exists, cross-compile glibc from source with `gcc-<arch>-linux-gnu` and `-g3 -O1`.

## Glibc 2.34 naming change

Glibc 2.34 changed how shared libraries are named:

| | glibc <= 2.33 | glibc >= 2.34 |
|---|---|---|
| libc | `libc-2.XX.so` (real file) | `libc.so.6` (real file) |
| ld (amd64) | `ld-2.XX.so` (real file) | `ld-linux-x86-64.so.2` (real file) |
| libpthread | `libpthread-2.XX.so` (real file) | stub (merged into libc) |

pwnlibc handles this transparently. In copy mode, libs are always renamed to `libc-<ver>.so` / `ld-<ver>.so` regardless of the glibc version, so the workflow is identical.

## Typical CTF workflow

1. You get a challenge binary `vuln` and a `libc.so.6` from the remote server.

2. Identify the libc version:
   ```bash
   strings libc.so.6 | grep 'GNU C Library'
   # GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.9) ...
   ```

3. Download and patch:
   ```bash
   pwnlibc download 2.31
   pwnlibc patch ./vuln -v 2.31
   ```

4. Debug with the correct libc:
   ```bash
   gdb ./vuln
   # libc symbols and source are available at /glibc/2.31/amd64/lib/.debug/
   # and /glibc/2.31/source/glibc-2.31/
   ```

5. Write your exploit (`exploit.py`), test locally, then point at remote.

## Configuration

**Glibc directory**: Default `/glibc/`. Override per-command with `--glibc-dir` or set globally:

```bash
export PWNLIBC_DIR=/opt/glibc
```

**Permissions**: The glibc directory is typically root-owned. Use `sudo` for `download`, `update`, `setup`, and `patch` (for copy mode when the target dir is root-owned). For working on your own CTF files, no `sudo` is needed for `patch`/`restore`.

## Project structure

```
pwnlibc/
├── pwnlibc/
│   ├── __init__.py        # version
│   ├── __main__.py        # python -m pwnlibc entrypoint
│   ├── cli.py             # click CLI commands (list, patch, download, ...)
│   ├── config.py          # constants: arch table, mirrors, naming rules
│   ├── elfutil.py         # pure-Python ELF parser (arch detect, NEEDED libs)
│   ├── glibc.py           # glibc install discovery and path resolution
│   ├── patcher.py         # patchelf operations (copy + inplace modes)
│   ├── downloader.py      # mirror scraping, .deb download/extract, verify
│   └── backup.py          # backup/restore logic
├── requirements.txt
├── install.sh
├── .gitignore
└── README.md
```

### Module responsibilities

- **`config.py`** — Single source of truth for architecture definitions (ELF machine types, dynamic linker names, deb package arch names, mirror selection), glibc naming boundary (2.34), and mirror URLs.

- **`elfutil.py`** — Pure-Python ELF header parser. Detects architecture (including endianness for s390x), extracts `DT_NEEDED` entries from the dynamic section, and checks for `.debug_info` sections. No external dependencies.

- **`glibc.py`** — Scans the glibc directory for installed versions. Resolves the actual libc/ld binary paths (handling both old and new naming). Finds specific libraries by soname.

- **`backup.py`** — Creates `.bak` / `.bak.N` backups before patching. Restores from the most recent backup.

- **`patcher.py`** — Wraps `patchelf` operations. Copy mode: copies libs with versioned names, runs `--replace-needed` and `--set-interpreter`. Inplace mode: sets interpreter and RPATH to absolute paths. Both modes auto-detect and handle all NEEDED libraries.

- **`downloader.py`** — Scrapes Ubuntu mirror HTML index pages to discover available `.deb` packages. Downloads and extracts `libc6` + `libc6-dbg` debs. Handles both xz and zstd compression. Verification: SHA256 comparison of installed files against reference `.deb` contents.

- **`cli.py`** — Click command group tying everything together. All user-facing output goes through `rich` for formatted tables and progress bars.

### Data flow

```
User runs: pwnlibc patch ./vuln -v 2.27

  cli.py:patch()
    ├── elfutil.detect_arch(./vuln) → "amd64"
    ├── glibc.resolve_lib_paths("2.27", "amd64", /glibc)
    │     └── checks /glibc/2.27/amd64/lib/ for libc-2.27.so, ld-2.27.so
    ├── backup.create_backup(./vuln) → ./vuln.bak
    └── patcher.patch_copy(./vuln, glibc_install)
          ├── elfutil.get_needed_libs(./vuln) → ["libc.so.6", "libpthread.so.0"]
          ├── copies libc-2.27.so, ld-2.27.so, libpthread-2.27.so
          └── patchelf --replace-needed / --set-interpreter / --set-rpath
```

### Adding new architectures

To add a new architecture:

1. Add an entry to `ARCH_INFO` in `config.py` with: `elf_machine`, `elf_class`, `ld_soname`, `deb_arch`, `deb_lib_dir`, `mirror`
2. Add a `(elf_machine, elf_class)` mapping in `elfutil.py`'s `_MACHINE_MAP`
3. That's it — everything else is data-driven
