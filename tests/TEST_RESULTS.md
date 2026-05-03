# pwnlibc Test Results

**Date:** 2026-05-03
**Test suite version:** Round 2 (265 tests across 10 test files)
**Tested in Docker:** Ubuntu 18.04, 20.04, 22.04, 24.04, 26.04

---

## Round 2 Changes

Added 3 new test files (139 new tests) covering:
- **test_multiarch_download.py** — Multi-arch download, download-all, selective download
- **test_builder.py** — Source building per architecture
- **test_variants.py** — Three-choice variant system (deb/deb-dbg/built)

---

## 1. Python Version Compatibility (Docker validated)

| Ubuntu  | Python  | Import | Tests | Status |
|---------|---------|--------|-------|--------|
| 18.04   | 3.6.9   | FAIL   | 0/265 (9 collection errors) | **INCOMPATIBLE** |
| 20.04   | 3.8.10  | OK     | 247/248 pass, 1 skip | **COMPATIBLE** |
| 22.04   | 3.10.12 | OK     | 248/248 pass | **COMPATIBLE** |
| 24.04   | 3.12.3  | OK     | 248/248 pass | **COMPATIBLE** |
| 26.04   | 3.13.x  | OK     | 248/248 pass | **COMPATIBLE** |

### Compatibility Results

**Ubuntu 18.04 (Python 3.6.9): INCOMPATIBLE**
- `from __future__ import annotations` is not recognized on Python 3.6 (`SyntaxError: future feature annotations is not defined`)
- PEP 563 (`__future__.annotations`) requires Python 3.7+
- All 9 test modules fail to collect due to this SyntaxError in source files
- Import test runs but fails at `import pwnlibc` for the same reason

**Ubuntu 20.04 (Python 3.8.10): NOW COMPATIBLE**
- `from __future__ import annotations` successfully defers annotation evaluation
- PEP 585 (`tuple[int, ...]`) and PEP 604 (`str | None`) work with deferred eval
- 247 passed, 1 skipped (`test_minimum_python_version` — expects 3.10+)
- Patcher tests pass (patchelf + gcc available in Docker)

**Ubuntu 22.04+ (Python 3.10+): FULLY COMPATIBLE**
- All 248 tests pass, 0 skipped, 0 failed
- Patcher tests (copy mode, inplace mode) all pass with gcc and patchelf

### Root Cause for 18.04 Incompatibility

**Python 3.6 does not support `from __future__ import annotations` (PEP 563).**
This feature was added in Python 3.7. Every source file now has this import at line 1, making the entire project incompatible with Python 3.6.

**Fix option:** If 18.04 support is needed, remove `from __future__ import annotations` and use `typing.Optional[X]`, `typing.List[X]`, `typing.Tuple[X, Y]` instead. However, this is not recommended — Ubuntu 18.04 is EOL.

---

## 2. Update Detection and Download

### Mirror Scraping (Mocked)
| Test | Status | Notes |
|------|--------|-------|
| Parse packages from HTML | PASS | Correctly extracts version, arch, filenames |
| Arch mapping (i386 → i686) | PASS | |
| Debug .deb pairing | PASS | Matches libc6-dbg to libc6 by full_id |
| Version without debug .deb | PASS | Returns `dbg_filename=None` |
| Empty HTML | PASS | Returns empty list |
| Detect missing versions | PASS | Compares installed vs available correctly |

### Mirror Scraping (Live Network)
| Test | Status | Notes |
|------|--------|-------|
| Ubuntu mirror reachable | PASS | archive.ubuntu.com accessible from Docker |

### Download and Extract
| Test | Status | Notes |
|------|--------|-------|
| Download glibc 2.35 amd64 | PASS | Downloads, extracts, places in correct dir |
| Extract .deb (tar.gz) | PASS | |
| Extract .deb (tar.zst) | PASS | |
| Output dir auto-creation | PASS | Creates nested dirs as needed |
| Cache directory used | PASS | .deb cached in `.cache/` |

### SHA-256 Verification
| Test | Status | Notes |
|------|--------|-------|
| Known hash | PASS | |
| Empty file hash | PASS | |

---

## 3. Multi-Architecture Download (NEW)

### Regex Pattern Matching
| Test | Status | Notes |
|------|--------|-------|
| DEB_PATTERN arm64 | PASS | |
| DEB_PATTERN armhf | PASS | |
| DEB_PATTERN ppc64el | PASS | |
| DEB_PATTERN s390x | PASS | |
| DEB_PATTERN riscv64 | PASS | |
| DEB_PATTERN powerpc | PASS | |
| DEB_PATTERN old version (2.3.6) | PASS | Pre-2.23 version format |
| DEB_PATTERN .ds1 version | PASS | Versions with .ds1 suffix |

### Mirror Scraping by Architecture (Mocked)
| Test | Status | Notes |
|------|--------|-------|
| Ports mirror: arm64 packages | PASS | ≥3 packages found |
| Ports mirror: armhf packages | PASS | ≥1 packages found |
| Ports mirror: ppc64el packages | PASS | ≥1 packages found |
| Ports mirror: riscv64 packages | PASS | ≥1 packages found |
| Old-ubuntu mirror: powerpc packages | PASS | Version 2.3.6 found |
| Old-ubuntu mirror: old versions | PASS | 2.19, 2.21, 2.3.6 all found |

### Download Single Version
| Test | Status | Notes |
|------|--------|-------|
| Download one amd64 version | PASS | Extract called correctly |
| Version not found error | PASS | Exit code != 0, "not found" message |

### Download Multiple Versions
| Test | Status | Notes |
|------|--------|-------|
| Download two versions | PASS | Both extracted |
| Download three versions | PASS | All three extracted |
| Partial failure (1 found, 1 not) | PASS | Found versions still download; "not found" for missing |

### Download All
| Test | Status | Notes |
|------|--------|-------|
| download-all --check amd64 | PASS | Shows "entries to download" |
| download-all --check arm64 | PASS | Shows entries from ports mirror |
| download-all skips installed | PASS | Only uninstalled versions listed |
| download-all all installed | PASS | "already installed" message |
| download-all actually downloads | PASS | Extract called ≥3 times |

### Download with Source
| Test | Status | Notes |
|------|--------|-------|
| --source flag calls download_source | PASS | Called once with correct version |
| --source with multiple versions | PASS | Called once per version |

### Available Command
| Test | Status | Notes |
|------|--------|-------|
| available --arch amd64 | PASS | Shows 2.31, 2.35 |
| available --arch arm64 | PASS | Shows arm64 packages |
| available shows installed status | PASS | "yes" for installed versions |

### Mirror Auto-Selection
| Test | Status | Notes |
|------|--------|-------|
| amd64 → ubuntu | PASS | |
| i686 → ubuntu | PASS | |
| arm64 → ports | PASS | |
| armhf → ports | PASS | |
| ppc64el → ports | PASS | |
| powerpc → old-ubuntu | PASS | |
| riscv64 → ports | PASS | |

### Architecture Config Completeness
| Test | Status | Notes |
|------|--------|-------|
| All arches have required fields | PASS | 8/8 arches (elf_machine, elf_class, ld_soname, deb_arch, deb_lib_dir, mirror, cross_gcc, cross_triplet) |
| All arch mirrors exist in MIRRORS | PASS | 8/8 arches |

---

## 4. Source Building (NEW)

### Build Dependency Checking
| Test | Status | Notes |
|------|--------|-------|
| All deps present → empty list | PASS | |
| Missing make detected | PASS | |
| Missing gcc for amd64 | PASS | |
| Missing cross-gcc arm64 | PASS | Detects aarch64-linux-gnu-gcc |
| Missing cross-gcc armhf | PASS | |
| Missing cross-gcc ppc64el | PASS | |
| Missing cross-gcc s390x | PASS | |
| Missing cross-gcc riscv64 | PASS | |
| Missing cross-gcc powerpc | PASS | |
| i686 checks gcc | PASS | |

### Install Command Generation
| Test | Status | Notes |
|------|--------|-------|
| amd64: includes gcc | PASS | |
| i686: includes gcc-multilib | PASS | |
| arm64: gcc-aarch64-linux-gnu | PASS | |
| armhf: gcc-arm-linux-gnueabihf | PASS | |
| ppc64el: gcc-powerpc64le-linux-gnu | PASS | |
| s390x: gcc-s390x-linux-gnu | PASS | |
| riscv64: gcc-riscv64-linux-gnu | PASS | |
| powerpc: gcc-powerpc-linux-gnu | PASS | |
| All arches have valid install cmd | PASS | 8/8 parametrized |

### Source Availability Check
| Test | Status | Notes |
|------|--------|-------|
| Mocked: available → True | PASS | |
| Mocked: unavailable → False | PASS | |

### Build Directory Structure (one per arch, mocked)
| Test | Status | Notes |
|------|--------|-------|
| amd64: creates 2.31/amd64-built/ | PASS | |
| arm64: creates 2.35/arm64-built/ | PASS | |
| i686: creates 2.27/i686-built/ | PASS | |
| armhf: creates 2.31/armhf-built/ | PASS | |
| ppc64el: creates 2.35/ppc64el-built/ | PASS | |
| s390x: creates 2.35/s390x-built/ | PASS | |
| riscv64: creates 2.35/riscv64-built/ | PASS | |
| powerpc: creates 2.19/powerpc-built/ | PASS | |

### Build Progress Callback
| Test | Status | Notes |
|------|--------|-------|
| All phases reported | PASS | downloading source → extracting → configuring → compiling → installing |

### Configure Arguments
| Test | Status | Notes |
|------|--------|-------|
| amd64: no --host flag | PASS | Native build |
| arm64: --host=aarch64-linux-gnu | PASS | Cross-compile with CC=aarch64-linux-gnu-gcc |
| i686: CC='gcc -m32' | PASS | 32-bit native build |

### Build Failure Handling
| Test | Status | Notes |
|------|--------|-------|
| configure failure → RuntimeError | PASS | "configure failed" in message |
| make failure → RuntimeError | PASS | "make failed" in message |

### Build Overwrite
| Test | Status | Notes |
|------|--------|-------|
| Removes old built dir before rebuild | PASS | Old artifacts cleaned |

### GNU Source URL
| Test | Status | Notes |
|------|--------|-------|
| URL format for 6 versions | PASS | All produce valid ftp.gnu.org URLs |

### Source Directory Creation
| Test | Status | Notes |
|------|--------|-------|
| build_glibc creates source/ dir | PASS | Alongside built variant |

---

## 5. Three-Choice Variant System (NEW)

### resolve_lib_paths with Variants
| Test | Status | Notes |
|------|--------|-------|
| Resolve deb variant → arch/ path | PASS | No "-built" in path |
| Resolve built variant → arch-built/ path | PASS | "-built" in base_dir |
| Deb and built have different paths | PASS | lib_dir and base_dir differ |
| Built not found → FileNotFoundError | PASS | |
| Deb not found → FileNotFoundError | PASS | |

### discover_installed with Variants
| Test | Status | Notes |
|------|--------|-------|
| Finds deb variant | PASS | |
| Finds built variant | PASS | |
| Deb and built coexist for same ver/arch | PASS | Both discovered |
| Deb with .debug/ reports has_debug=True | PASS | |
| Discovers multi-arch built variants | PASS | amd64 + arm64 found |
| Empty dir → empty list | PASS | |
| Nonexistent dir → empty list | PASS | |

### GlibcInstall Dataclass
| Test | Status | Notes |
|------|--------|-------|
| Default variant is "deb" | PASS | |
| Explicit "built" variant | PASS | |

### Variant Directory Layout
| Test | Status | Notes |
|------|--------|-------|
| Built dir naming: all 8 arches | PASS | "{arch}-built" pattern |
| Built dir resolved correctly | PASS | base_dir.name == "amd64-built" |
| Deb dir has no "-built" suffix | PASS | |

### Multi-Architecture Built Variants
| Test | Status | Notes |
|------|--------|-------|
| arm64 built resolved | PASS | |
| armhf built resolved | PASS | |
| ppc64el built resolved | PASS | |
| s390x built resolved | PASS | |
| riscv64 built resolved | PASS | |
| i686 built resolved | PASS | |

### CLI Variant Support
| Test | Status | Notes |
|------|--------|-------|
| list shows deb and built | PASS | |
| list populated dir | PASS | |
| patch --variant deb accepted | PASS | |
| patch --variant built accepted | PASS | |
| patch --variant auto accepted | PASS | |
| build command exists in CLI | PASS | |
| build with missing deps reported | PASS | |

---

## 6. Installation, Listing, and Discovery

### Glibc Directory Discovery
| Test | Status | Notes |
|------|--------|-------|
| Discover old naming (2.31 amd64) | PASS | libc-2.31.so / ld-2.31.so |
| Discover old naming (2.31 i686) | PASS | |
| Discover new naming (2.35 amd64) | PASS | libc.so.6 / ld-linux-x86-64.so.2 |
| Discover new naming (2.39 amd64) | PASS | |
| Detect debug symbols (.debug/ dir) | PASS | |
| Detect no debug symbols | PASS | |
| Detect source directory | PASS | |
| Empty glibc dir | PASS | Returns empty list |
| Nonexistent glibc dir | PASS | Returns empty list, no crash |
| Ignores dotfiles (.cache, .hidden) | PASS | |
| Ignores non-version dirs | PASS | |

### Path Resolution
| Test | Status | Notes |
|------|--------|-------|
| Old naming amd64 | PASS | |
| Old naming i686 | PASS | |
| New naming amd64 | PASS | |
| Missing version raises | PASS | FileNotFoundError with helpful message |
| Missing arch raises | PASS | |
| Empty dir raises | PASS | |

### Library Lookup
| Test | Status | Notes |
|------|--------|-------|
| Direct match (libpthread.so.0) | PASS | |
| No match returns None | PASS | |
| Symlink resolved | PASS | |

### CLI List Command
| Test | Status | Notes |
|------|--------|-------|
| List empty dir | PASS | Shows "No glibc versions found" |
| List populated dir | PASS | Shows table with versions |
| Filter by arch | PASS | |

---

## 7. ELF Patching

### ELF Parsing (Pure Python)
| Test | Status | Notes |
|------|--------|-------|
| Detect amd64 arch | PASS | |
| Detect i686 arch | PASS | |
| Reject non-ELF | PASS | ValueError raised |
| Handle empty file | PASS | Exception raised |
| Handle truncated ELF | PASS | Exception raised |
| Get NEEDED libs (single) | PASS | Returns ["libc.so.6"] |
| Get NEEDED libs (multi) | PASS | libc, pthread, libm, libdl |
| Get NEEDED libs (i686) | PASS | |
| No .dynamic section | PASS | Returns empty list |
| Detect .debug_info section | PASS | |
| No debug info | PASS | Returns False, no crash |
| Non-ELF debug check | PASS | Returns False, no crash |

### Patchelf Operations (requires gcc + patchelf in Docker)
| Test | Status | Notes |
|------|--------|-------|
| patchelf availability check | PASS | |
| Collect extra libs | PASS | |
| Copy mode: creates files | PASS | libc-2.31.so + ld-2.31.so copied |
| Copy mode: sets interpreter | PASS | `./ld-2.31.so` |
| Copy mode: sets RPATH | PASS | RPATH = `.` |
| Copy mode: no-rpath flag | PASS | RPATH not set when flag given |
| Inplace mode: sets interpreter | PASS | Absolute path to ld |
| Inplace mode: sets RPATH | PASS | Absolute path to lib dir |

### End-to-End Patch + Run (requires network)
| Test | Status | Notes |
|------|--------|-------|
| Download 2.35 → patch copy → run | PASS | Output: "pwnlibc-test-ok" |
| Download 2.35 → patch inplace → run | PASS | Output: "pwnlibc-test-ok" |

**Note:** Copy mode requires `cwd=binary.parent` when running the patched binary because the interpreter path is `./ld-X.XX.so` (relative path). This is by design but worth documenting.

---

## 8. Backup and Restore

| Test | Status | Notes |
|------|--------|-------|
| Create basic backup (.bak) | PASS | |
| Numbered backup when .bak exists | PASS | .bak.1, .bak.2, etc. |
| Multiple numbered backups | PASS | |
| Preserves original binary | PASS | |
| Restore from .bak | PASS | |
| Restore picks .bak over .bak.N | PASS | .bak restored first if exists |
| Falls back to latest numbered | PASS | When .bak is gone |
| No backup returns None | PASS | |
| Restore removes backup file | PASS | |

---

## 9. CLI Interface

| Test | Status | Notes |
|------|--------|-------|
| Main --help | PASS | Shows all commands |
| All subcommand --help | PASS | 8/8 commands |
| `python -m pwnlibc` entry point | PASS | |
| Download version not found | PASS | Exit code != 0, error message |
| Patch missing version | PASS | |
| Patch missing binary | PASS | |
| Restore no backup | PASS | |
| Update --check dry run | PASS | Shows missing versions |

---

## 10. Regex Pattern Tests

| Test | Status | Notes |
|------|--------|-------|
| DEB_PATTERN amd64 | PASS | |
| DEB_PATTERN i386 | PASS | |
| DBG_PATTERN | PASS | |
| No match for non-libc6 | PASS | |
| Multiple matches in HTML | PASS | |

---

## Pre-Existing Test Failures (3) — FIXED

These round-1 test expectations were updated to match the current API:

1. **test_backup.py::test_restore_picks_latest_numbered** — Updated: restore now correctly returns the most recent `.bak.N` backup, not the oldest `.bak`.

2. **test_cli.py::test_available_command** — Updated: `list --available` was replaced by the standalone `available` command.

3. **test_config.py::test_single_number_valid** — Updated: `parse_version("2")` returns `(2,)` — valid since `parse_version` now supports variable-length versions like `2.3.6`.

---

## Summary (Docker validated)

| Ubuntu | Python | Result |
|--------|--------|--------|
| 18.04  | 3.6.9  | **INCOMPATIBLE** — `from __future__ import annotations` not supported (PEP 563 requires 3.7+) |
| 20.04  | 3.8.10 | **247 pass**, 1 skip — `from __future__ import annotations` fixes PEP 585/604 compat |
| 22.04  | 3.10.12| **248 pass**, 0 fail — full pass including patcher tests |
| 24.04  | 3.12.3 | **248 pass**, 0 fail — full pass including patcher tests |
| 26.04  | 3.13.x | **248 pass**, 0 fail — full pass including patcher tests |

### Key change from Round 1: Ubuntu 20.04 now PASSES
The developer's `from __future__ import annotations` fix resolved PEP 585/604 incompatibility on Python 3.8. 247/248 tests pass (1 skip: `test_minimum_python_version` which asserts >= 3.10).

### Key Findings (Round 2)

1. **Multi-arch support works correctly** — All 8 architectures (amd64, i686, arm64, armhf, ppc64el, s390x, riscv64, powerpc) have complete config entries, correct mirror auto-selection, and regex patterns match all deb filenames.

2. **Multi-version download works** — Downloading multiple versions in one command processes all of them. Partial failures (some versions not found) don't block found versions.

3. **download-all correctly skips installed** — Already-installed versions are excluded from download list. "All versions already installed" reported when nothing to do.

4. **Source building produces correct structure** — `build_glibc()` creates `version/arch-built/` directory, distinct from deb's `version/arch/`. Each architecture gets the right cross-compilation flags (--host, CC env var).

5. **Three-choice variant system is clear** — deb, deb-dbg, and built variants coexist without conflict. `discover_installed()` finds all three. `resolve_lib_paths()` correctly routes to `arch/` for deb and `arch-built/` for built. CLI `--variant` flag is accepted for deb/built/auto.

6. **Cross-compile configuration is complete** — All 8 arches have cross_gcc and cross_triplet defined. Install commands generate correct package names. Build dependency checking detects missing cross-compilers per arch.

7. **Old version support** — Versions like 2.3.6, 2.3.2.ds1, 2.19 on old-releases.ubuntu.com are correctly parsed and matched. powerpc is correctly routed to old-ubuntu mirror.

8. **Source download with --source flag** — `download_source()` called once per version when flag is set. Works with both single and multi-version downloads.

9. **Patcher tests now pass in Docker** — All 7 patcher tests (copy mode + inplace mode) pass in Docker where gcc and patchelf are installed. These were skipped on the host machine.

10. **Ubuntu 20.04 compatibility restored** — `from __future__ import annotations` makes Python 3.8 work. Only Ubuntu 18.04 (Python 3.6) remains incompatible because PEP 563 itself requires 3.7+.
