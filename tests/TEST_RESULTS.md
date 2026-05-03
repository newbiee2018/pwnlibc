# pwnlibc Test Results

**Date:** 2026-05-03
**Test suite version:** Initial (113 tests across 7 test files)

---

## 1. Python Version Compatibility

| Ubuntu  | Python  | Import | Tests | Status |
|---------|---------|--------|-------|--------|
| 18.04   | 3.6.9   | FAIL   | N/A   | **INCOMPATIBLE** |
| 20.04   | 3.8.10  | FAIL   | N/A   | **INCOMPATIBLE** |
| 22.04   | 3.10.12 | OK     | 109/109 pass | **COMPATIBLE** |
| 24.04   | 3.12.3  | OK     | 109/109 pass | **COMPATIBLE** |
| 26.04   | 3.13.x  | OK     | 109/109 pass | **COMPATIBLE** |

### Root Causes for Incompatibility

**Python < 3.10 (Ubuntu 18.04 + 20.04):**
- `tuple[int, int]` — PEP 585 lowercase generics (requires Python 3.9+)
- `list[str]`, `dict[str, ...]` — same PEP 585 issue
- `str | None` — PEP 604 union types (requires Python 3.10+)
- `list[tuple[str, str, str]]` — nested PEP 585 generics

**Affected files and lines:**
- `config.py:33` — `def parse_version(version: str) -> tuple[int, int]:`
- `elfutil.py:126` — `def get_needed_libs(path: Path) -> list[str]:`
- `downloader.py:28` — `dbg_filename: str | None` (dataclass field)
- `downloader.py:176` — `cache_dir: Path | None = None`
- `glibc.py:96` — `def find_library(...) -> Path | None:`
- `backup.py:21` — `def restore_backup(binary: Path) -> Path | None:`
- `cli.py:58` — `versions: dict[str, dict] = {}`

**Additional dependency issue on Ubuntu 18.04:**
- `rich>=13.0` requires Python 3.7+. The latest `rich` installable on Python 3.6 is `12.6.0`.
- `click>=8.0` installs `8.0.4` on Python 3.6 (last version supporting 3.6).

**Fix options:**
1. Use `from __future__ import annotations` at the top of each file (defers annotation evaluation, works on 3.7+)
2. Use `typing.Optional[X]`, `typing.List[X]`, `typing.Tuple[X, Y]` for 3.6-3.8
3. Declare minimum Python version as 3.10 (recommended if targeting Ubuntu 22.04+)

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

## 3. Installation, Listing, and Discovery

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
| List --available (mocked) | PASS | Shows "Available for download" table |

---

## 4. ELF Patching

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
| No debug info | PASS | |
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

**Note:** Copy mode requires `cwd=binary.parent` when running the patched binary because the interpreter is set to `./ld-X.XX.so` (relative path). This is by design but worth documenting.

---

## 5. Backup and Restore

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

## 6. CLI Interface

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

## 7. Regex Pattern Tests

| Test | Status | Notes |
|------|--------|-------|
| DEB_PATTERN amd64 | PASS | |
| DEB_PATTERN i386 | PASS | |
| DBG_PATTERN | PASS | |
| No match for non-libc6 | PASS | |
| Multiple matches in HTML | PASS | |

---

## Summary

### Passing: 109/109 unit+integration tests on Ubuntu 22.04, 24.04, 26.04
### Passing: 4/4 E2E network tests on Ubuntu 24.04 (Docker)
### Failing: All tests on Ubuntu 18.04 (Python 3.6) and 20.04 (Python 3.8)

### Key Findings

1. **Python version requirement is 3.10+** — Code uses PEP 585 (lowercase generics) and PEP 604 (`X | Y` union types) which are not available on Python < 3.10. Ubuntu 18.04 and 20.04 are incompatible.

2. **Dependency version bounds** — `rich>=13.0` requires Python 3.7+. Even if the syntax issue is fixed, `rich 13+` won't install on Python 3.6.

3. **Copy mode cwd requirement** — Binaries patched in copy mode must be run from their own directory because the interpreter path is `./ld-X.XX.so`. This is correct behavior but should be documented.

4. **No build support** — The project downloads pre-built binaries from Ubuntu mirrors. There is no compile-from-source functionality for getting debug symbols when the official `.deb` lacks them.

5. **Old-naming/new-naming boundary works correctly** — glibc < 2.34 uses `libc-{ver}.so`/`ld-{ver}.so`, >= 2.34 uses `libc.so.6`/`ld-linux-x86-64.so.2`. The code handles both correctly, including fallback resolution.

6. **Backup restoration order** — `restore_backup()` always prefers `.bak` over `.bak.N` when both exist. This means restoring always gives you the first backup, not the latest. This may be surprising to users.
