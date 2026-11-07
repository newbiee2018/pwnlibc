# pwnlibc

CTF glibc manager and ELF patcher. Downloads prebuilt glibc from Ubuntu mirrors, builds from source with debug symbols, verifies integrity, and patches ELF binaries to use a specific glibc version via `patchelf`.

## Requirements

- Python 3.8+
- `patchelf` (`sudo apt install patchelf`)
- `ar` (from `binutils`, usually pre-installed)
- `zstd` (for Ubuntu 22.04+ `.deb` files: `sudo apt install zstd`)
- For source builds: `make`, `gawk`, `bison`, cross-compiler (see `pwnlibc build`)

## Clone

This repo uses the `debug_glibc` submodule. Clone recursively:

```bash
git clone --recursive https://github.com/newbiee2018/pwnlibc.git
```

If you already cloned without submodules:

```bash
git submodule update --init --recursive
```

## Install

Recommended — [pipx](https://pipx.pypa.io) (isolated venv, no dependency pollution, easy upgrades):

```bash
sudo apt install pipx                     # if not already installed
pipx install --editable /path/to/pwnlibc  # from your clone of this repo
pipx ensurepath
```

`--editable` makes the `pwnlibc` command always run your current checkout: `git pull` and local edits apply immediately, no reinstall needed. For a snapshot install instead, drop `--editable` and update later with `pipx upgrade pwnlibc`. Once published, `pipx install git+https://github.com/newbiee2018/pwnlibc.git` will work the same way.

Upgrade / uninstall:

```bash
pipx upgrade pwnlibc      # snapshot installs only; editable installs update automatically
pipx uninstall pwnlibc
```

No pipx (e.g. stock Python 3.8+ systems)? Plain pip works too:

```bash
python3 -m pip install --user --editable /path/to/pwnlibc
# newer Debian/Ubuntu (PEP 668) needs the bypass flag BEFORE the path:
python3 -m pip install --user --break-system-packages --editable /path/to/pwnlibc
```

The `pwnlibc` command lands in `~/.local/bin` (add it to PATH if needed). Uninstall with `python3 -m pip uninstall pwnlibc`. `bash install.sh` picks the best method automatically: pipx when present, then pip `--user` (editable), then a legacy `.pth` path-hook fallback that needs no pip at all — and it cleans up artifacts older versions of the script left behind.

Or run the repo installer, which prompts for the glibc data directory once (Enter accepts `~/pwnlibc`), persists your choice, and then uses pipx when available (falling back to the legacy `.pth` method, cleaning up any old wrapper it previously created):

```bash
cd pwnlibc/
bash install.sh
```

Note: pipx installs the CLI, not the glibc data directory — `bash install.sh` (or `mkdir -p ~/pwnlibc`) sets that up. Alternatively, run directly without installing:

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

# Or grab the newest glibc per arch
sudo pwnlibc download latest

# Download multiple versions at once
sudo pwnlibc download 2.27 2.31 2.35

# Download everything available for amd64
sudo pwnlibc download-all --arch amd64

# List what you have
pwnlibc list

# Patch a CTF binary (creates vuln.patched)
pwnlibc patch ./vuln -v 2.31

# Done — run it
./vuln.patched

# Clean up
pwnlibc restore ./vuln

# Build from source with full debug symbols
sudo pwnlibc build 2.31 --arch amd64
```

Run `pwnlibc --version` to print the tool version, `pwnlibc --help` (or
`pwnlibc help`) for the full command list.

## Commands

### `pwnlibc list`

Show all installed glibc versions with their variants.

```bash
pwnlibc list                    # table of installed versions
pwnlibc list --arch amd64       # filter by architecture
```

Each row shows version, architecture, variant (`deb`, `deb(dbg)`, `built`, `built(dbg)`), and source availability.

### `pwnlibc available`

List all glibc versions available for download from Ubuntu mirrors.

```bash
pwnlibc available                          # show all arches, all mirrors
pwnlibc available --arch amd64             # just amd64
pwnlibc available --arch arm64             # just arm64 (from ports.ubuntu.com)
pwnlibc available --arch powerpc           # just powerpc (from old-releases)
pwnlibc available --mirror old-ubuntu      # only old-releases mirror
```

Shows a numbered table with version, arch, mirror, debug .deb availability, GNU source availability, and installed variant. In auto mode each arch is listed from its own mirror chain (x86 and non-x86 from Ubuntu mirrors, mips from Debian), so the table shows exactly what `pwnlibc download` would fetch for that entry; use `--mirror` to inspect a specific mirror outside the chain. Source availability is checked against ftp.gnu.org (use `--no-check-source` to skip). The "Debug .deb" column shows whether the mirror has a matching `libc6-dbg` package. The "Installed" column shows what's locally installed — `deb(dbg)` means installed with debug symbols, `deb` means installed without. The "Mirror" column shows the mirror the package was actually found on (e.g. EOL versions show `old-ubuntu`).

### `pwnlibc download VERSION [VERSION ...]`

Download one or more glibc versions from Ubuntu mirrors.

```bash
pwnlibc download 2.31                          # amd64+i686, with debug
pwnlibc download 2.27 2.31 2.35                # multiple versions at once
pwnlibc download latest                        # newest glibc per arch
pwnlibc download 2.31 latest                   # mixes with explicit versions
pwnlibc download 2.39 --arch arm64             # arm64 only
pwnlibc download 2.39 --no-dbg                 # skip debug symbols
pwnlibc download 2.39 --source                 # also grab GNU source
pwnlibc download 2.23 --mirror old-ubuntu      # EOL Ubuntu releases
pwnlibc download 2.19 --arch powerpc --mirror old-ubuntu  # old powerpc
```

Downloads `libc6` and `libc6-dbg` `.deb` packages, extracts them, and installs to `<glibc-dir>/<version>/<arch>/lib/`.

`latest` is a token, not a version: it resolves per target arch to the newest glibc in that arch's own mirror chain, announcing each resolution (`latest (amd64) → 2.39`) before downloading. It respects `--arch` and `--mirror` (with an explicit mirror, `latest` is the newest version in that mirror's catalog) and dedupes against explicit versions, so `download 2.39 latest` installs 2.39 once. An arch whose package list came back empty reports `latest (arch): no packages found on mirrors (...)` and counts as a failure.

Mirror auto-selection: x86 from `archive.ubuntu.com`, non-x86 from `ports.ubuntu.com`, powerpc from `old-releases.ubuntu.com`. Automatically tries fallback mirrors (e.g. `old-releases` for EOL versions). Override with `--mirror`. Each installed line reports the mirror it came from, and Ubuntu/Debian package revisions are never compared across distributions — the origin shown by `available` is the origin `download` uses and `verify` checks against.

Integrity: every downloaded `.deb` is checked against the SHA256 recorded in the owning suite's `Packages` index (`<mirror>/dists/<suite>/main/binary-<arch>/Packages.xz`); a mismatch deletes the file and aborts that version. Indices are cached under `<glibc-dir>/.cache/indices/` for 7 days. Files no index lists (EOL leftovers like trusty-era debs, or superseded revisions) are downloaded without verification. All mirrors are fetched over HTTPS.

Signature verification (opt-in): `--verify-signatures` adds a layer above the deb hashes — after the run, each cached `Packages` index it used is compared against the SHA256 listed in the suite's GPG-signed `InRelease` (or `Release` + `Release.gpg`) file, which is itself verified with `gpgv` against the distro archive keyring. Requires `gpgv` (`sudo apt install gnupg`) and a keyring (`ubuntu-archive-keyring` / `debian-archive-keyring`, or `--keyring PATH`, or `$PWNLIBC_KEYRING`); a missing tool or keyring only downgrades that check to a warning, but an actual index/signature mismatch exits with status 1.

```bash
pwnlibc download 2.31 --verify-signatures              # also check the signed Release
pwnlibc download 2.31 --verify-signatures --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg
```

### `pwnlibc download-all`

Download all available glibc versions for specified architecture(s).

```bash
pwnlibc download-all                        # all versions for amd64+i686
pwnlibc download-all --arch arm64           # all versions for arm64
pwnlibc download-all --arch powerpc         # all powerpc versions
pwnlibc download-all --check                # dry run: show what would be downloaded
pwnlibc download-all --source               # also download GNU source per version
```

Skips versions already installed. GNU source is off by default here — unlike `pwnlibc download`, where `--source` is on by default — because a bulk run would otherwise pull ~30 MB of source per version; pass `--source` to opt in.

### `pwnlibc build VERSION [VERSION ...] --arch ARCH`

Build glibc from GNU source with full debug symbols (`-g3 -O1`).

```bash
pwnlibc build 2.31 --arch amd64              # native build
pwnlibc build 2.27 2.31 --arch arm64         # cross-compile for arm64
pwnlibc build 2.19 --arch powerpc            # cross-compile for powerpc
pwnlibc build 2.31 --arch amd64 --timeout 0  # no make timeout
```

If `<glibc-dir>/<version>/source/` already holds a real source tree (one with
a `configure` script — e.g. from `pwnlibc source download` or a previous
build), it is reused in place and the ftp.gnu.org tarball download is skipped,
so builds work fully offline. `--timeout SECONDS` caps the `make` step
(default 1800; `0` disables the cap).

Creates a separate `<arch>-built` variant under `<glibc-dir>/<version>/`. This coexists with deb-installed versions — use `pwnlibc patch --variant built` to select it, or let `--variant auto` (default) pick the deb first.

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
| mipsel | `gcc-mipsel-linux-gnu` |
| mips64el | `gcc-mips64el-linux-gnuabi64` |

Plus: `make`, `gawk`, `bison`, `python3`.

**Two variants** of glibc can coexist per version/arch:
- **deb**: Extracted from Ubuntu `libc6` package (prebuilt, optimized). Debug symbols from `libc6-dbg` are added to `.debug/` subdir — shown as `deb(dbg)` in `pwnlibc list`.
- **built**: Compiled from source with `-g3` (full debug info baked into the binary itself) — shown as `built(dbg)` in `pwnlibc list`.

Use `--no-dbg` with `pwnlibc download` to skip debug symbols. Re-run `pwnlibc download` without `--no-dbg` to add them later.

### `pwnlibc patch BINARY`

Patch an ELF binary to use a specific glibc version. Creates `<binary>.patched` — the original is never modified.

```bash
pwnlibc patch ./vuln -v 2.31                         # inplace mode (default)
pwnlibc patch ./vuln -v 2.27 -m copy                 # copy mode
pwnlibc patch ./vuln -v 2.27 -a i686                 # force 32-bit
pwnlibc patch ./vuln -v 2.31 --variant built          # use source-built variant
```

**Variant selection** (`--variant auto|deb|built`):
- `auto` (default): prefers debug-enabled variants for source-level debugging. Resolution order:
  1. deb with debug symbols (`deb(dbg)`) — best case
  2. built with debug symbols (`built(dbg)`) — falls back automatically
  3. deb without debug — prompts the user:
     - `1)` Build from source with `-g3` debug symbols (recommended, default)
     - `2)` Use deb without debug (no source-level debugging)
     - `3)` Cancel
  If build fails (missing deps, no source on ftp.gnu.org), automatically falls back to deb without debug.
- `deb`: use the deb-extracted variant directly (no prompt).
- `built`: use the source-built variant directly (no prompt).

**Inplace mode** (default): Sets the ELF interpreter and RPATH to absolute paths pointing at `<glibc-dir>/<ver>/<arch>/lib/`. No files copied. The binary can be run from anywhere. GDB finds debug symbols automatically via `.debug/` in the glibc install.

**Copy mode**: Copies `libc-<ver>.so`, `ld-<ver>.so`, debug symbols, and any other NEEDED libraries to the binary's directory. Patches the binary with relative paths. The binary must be run from its directory.

Architecture is auto-detected from the ELF header. When source is available, outputs the GDB `set substitute-path` command to map Ubuntu build paths to local source.

### `pwnlibc restore BINARY`

Remove the `.patched` file created by `pwnlibc patch`. Also supports legacy `.bak` backups.
Copy-mode patching records a `<binary>.patched.manifest`, and `restore` removes the copied libs and `.debug` files listed there (plus the `.debug` directory once it is empty).

```bash
pwnlibc restore ./vuln
```

### `pwnlibc remove VERSION [VERSION ...]`

Remove installed glibc versions.

```bash
pwnlibc remove 2.31                        # remove everything for 2.31
pwnlibc remove 2.27 --arch amd64           # remove only amd64
pwnlibc remove 2.31 --variant source       # remove only source
pwnlibc remove 2.27 --variant built        # remove only source-built
pwnlibc remove 2.31 --keep-cache           # keep cached .deb files
```

Cleans up empty version directories automatically. Cached `.deb` files are removed by default (use `--keep-cache` to keep them).

### `pwnlibc verify`

Compare installed glibc files against official Ubuntu `.deb` packages (SHA256). Every file under the installed `lib/` is compared against the reference deb, recursively — symlinks by target, the `.debug/` dir (from the separate `libc6-dbg` package) excluded — so "All N files verified OK" covers the whole tree, not a few key files.

```bash
pwnlibc verify                # check all deb-installed versions
pwnlibc verify -v             # also show MATCH entries
pwnlibc verify --fix          # re-download mismatched/missing files
```

Only verifies `deb` variant installs (not source-built ones). By default only shows problems (MISSING/MISMATCH); use `-v` to see all entries. Exits with status 1 when problems are found (or, with `--fix`, when a fix attempt fails) so scripts and CI can detect failures. The cached reference `.deb` is also validated against the dists SHA256 before file contents are compared — a tampered or truncated cache entry is reported as an error (and removed) instead of silently producing MISMATCH rows; when no index pins the deb, verification falls back to content comparison as before.

`--verify-signatures` (opt-in) additionally checks each `Packages` index used against the GPG-signed `InRelease`/`Release` of its suite (`gpgv` + distro archive keyring; see `pwnlibc download`). Missing `gpgv`/keyring downgrades the check to a warning; an index hash or signature mismatch makes `verify` exit 1 like any other problem. `--keyring PATH` selects the trusted keyring (`$PWNLIBC_KEYRING` also works).

```bash
pwnlibc verify --verify-signatures      # also check signed Release files
```

### `pwnlibc source`

Manage glibc source code for GDB debugging.

```bash
pwnlibc source                        # show source status for all versions
pwnlibc source check                  # verify local source dirs (OK/missing)
pwnlibc source available              # check ftp.gnu.org for ALL mirror versions
pwnlibc source available 2.19 2.31    # check specific versions
pwnlibc source download 2.31          # download source
pwnlibc source download 2.27 2.35     # download multiple
pwnlibc source remove 2.31            # remove source
```

Source is shared across architectures at `<glibc-dir>/<version>/source/`. Auto-downloaded by `download` and `build` commands. Auto-removed by `remove` when no deb/built variant remains. Tries `.tar.xz`, `.tar.gz`, `.tar.bz2` formats from `https://ftp.gnu.org/gnu/glibc/`. Debian `.ds1` versions (e.g. `2.3.2.ds1`) map to the base GNU source (e.g. `glibc-2.3.2`).

### `pwnlibc setup ARCHIVE_DIR`

Extract existing `.tar.gz` archives to the glibc directory. Automatically detects whether archives contain source-built glibc (`.a` static libraries, `libexec/` directories) and places them in the correct variant directory (`<arch>-built/` for source-built, `<arch>/` for deb-style).

```bash
pwnlibc setup ./debug_glibc                           # auto-detect variant
pwnlibc setup ./debug_glibc --variant built            # force built variant
pwnlibc setup /path/to/archives --target-dir /opt/glibc   # any writable dir
```

### `pwnlibc info BINARY`

Show ELF info: architecture, interpreter, RPATH, and NEEDED libraries.

```bash
pwnlibc info ./vuln
```

## Glibc directory layout

Default location: `~/pwnlibc/` (chosen at install time; see Configuration).

```
~/pwnlibc/
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
| MIPS 32-bit LE | `mipsel` | deb.debian.org | cross | 2.28+ (Debian) |
| MIPS 64-bit LE | `mips64el` | deb.debian.org | cross | 2.28+ (Debian) |

Older versions (2.3.x, 2.4, 2.5, 2.7, 2.9, 2.19, 2.21) are available on `old-releases.ubuntu.com` for x86 and powerpc. Use `--mirror old-ubuntu` to access them.

**MIPS from Debian**: mipsel/mips64el packages come from Debian mirrors (same .deb format). Use `--mirror debian` or `--mirror old-debian` for EOL releases. Bookworm (2.36) is the last Debian release with native MIPS.

**Cross-architecture patching**: `patchelf` works on any architecture from any host — it manipulates ELF headers without executing the binary.

**Running non-x86 binaries**:
```bash
sudo apt install qemu-user qemu-user-static
qemu-aarch64 ./arm_binary      # after patching with pwnlibc
qemu-mipsel ./mips_binary      # MIPS little-endian
```

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
   pwnlibc patch ./vuln -v 2.31    # creates vuln.patched
   ```

4. Need full debug symbols for heap analysis? Build from source:
   ```bash
   pwnlibc build 2.31 --arch amd64
   pwnlibc patch ./vuln -v 2.31 --variant built
   ```

5. Debug with GDB + source:
   ```bash
   gdb ./vuln.patched
   # Source at ~/pwnlibc/2.31/source/glibc-2.31/malloc/malloc.c
   ```

## Configuration

**Glibc directory**: Default `~/pwnlibc/`. Resolution order: `--glibc-dir` flag, `$PWNLIBC_DIR`, the config file written by `install.sh` (`~/.config/pwnlibc/glibc_dir`), then the default. Set the env var to override:
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
├── tests/                 # pytest suite (650+ tests)
├── pyproject.toml         # packaging metadata + pwnlibc console script
├── requirements.txt
├── install.sh
└── README.md
```

### Adding new architectures

1. Add entry to `ARCH_INFO` in `config.py`: `elf_machine`, `elf_class`, `ld_soname`, `deb_arch`, `deb_lib_dir`, `mirror`, `cross_gcc`, `cross_triplet`
2. Add `(elf_machine, elf_class)` to `_MACHINE_MAP` in `elfutil.py`
3. Everything else is data-driven
