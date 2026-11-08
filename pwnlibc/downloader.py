from __future__ import annotations

import gzip
import hashlib
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .config import ARCH_INFO, MIRRORS, MIRROR_FAMILY

_ALL_DEB_ARCHES = "|".join(info["deb_arch"] for info in ARCH_INFO.values())

# Match versions like 2.31, 2.3.6, 2.3.2.ds1
DEB_PATTERN = re.compile(
    r'libc6_(?P<full>(?P<ver>2\.\d+(?:\.\d+)?(?:\.ds1)?)-[^"_]+_(?P<arch>' + _ALL_DEB_ARCHES + r'))\.deb'
)
DBG_PATTERN = re.compile(
    r'libc6-dbg_(?P<full>(?P<ver>2\.\d+(?:\.\d+)?(?:\.ds1)?)-[^"_]+_(?P<arch>' + _ALL_DEB_ARCHES + r'))\.deb'
)

_DEB_TO_PWNLIBC = {info["deb_arch"]: name for name, info in ARCH_INFO.items()}

# glibc version -> Ubuntu/Debian suite whose Packages index pins it.
# Versions/suites not listed here skip hash verification, announced once
# per version by _warn_unverifiable_version so a stale map is visible.
# 2.42/2.43 on Ubuntu verified 2026-11-07 via Launchpad; Debian's 2.43
# verified live via dists/forky/main/binary-amd64/Packages.xz.
_UBUNTU_SUITES = {
    "2.19": "trusty", "2.23": "xenial", "2.27": "bionic", "2.31": "focal",
    "2.35": "jammy", "2.37": "lunar", "2.38": "mantic", "2.39": "noble",
    "2.40": "oracular", "2.41": "plucky", "2.42": "questing",
    "2.43": "resolute",
}
_DEBIAN_SUITES = {
    "2.24": "stretch", "2.28": "buster", "2.31": "bullseye",
    "2.36": "bookworm", "2.41": "trixie", "2.43": "forky",
}

# glibc versions already announced as unmapped this process: the warning
# fires once per version, not once per downloaded file.
_unknown_suite_versions: set[str] = set()

# mirror key -> package origin (shared MIRROR_FAMILY), decides the suite
# table above. Mirrors not listed there skip hash verification entirely.
_MIRROR_ORIGIN = MIRROR_FAMILY

# Cached dists indices (and miss markers) older than this are refreshed.
_INDEX_TTL_SECONDS = 7 * 86464


@dataclass
class DebPackage:
    version: str
    full_id: str
    arch: str
    filename: str
    dbg_filename: str | None
    mirror: str = "ubuntu"


def _is_transient(exc: BaseException) -> bool:
    """Whether an exception looks like a temporary network condition worth
    retrying: connection/SSL/timeout errors and 5xx HTTP errors. 4xx errors
    (404 etc.) are permanent and must fail immediately."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500
    return isinstance(exc, (urllib.error.URLError, ConnectionError, TimeoutError, OSError))


def _retry_transient(fn, attempts: int = 3, delay: float = 1.5):
    """Run fn(), retrying transient network failures with linear backoff.
    Permanent errors and non-network exceptions propagate immediately."""
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:
            if attempt == attempts - 1 or not _is_transient(exc):
                raise
            time.sleep(delay * (attempt + 1))


def _fetch_bytes(url: str) -> bytes:
    def attempt() -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": "pwnlibc/0.1"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()

    return _retry_transient(attempt)


def _fetch_index(url: str) -> str:
    return _fetch_bytes(url).decode("utf-8", errors="replace")


def scrape_available(mirror: str = "ubuntu") -> list[DebPackage]:
    url = MIRRORS[mirror]
    html = _fetch_index(url)

    debs: dict[str, str] = {}
    for m in DEB_PATTERN.finditer(html):
        key = m.group("full")
        debs[key] = f"libc6_{key}.deb"

    dbgs: dict[str, str] = {}
    for m in DBG_PATTERN.finditer(html):
        key = m.group("full")
        dbgs[key] = f"libc6-dbg_{key}.deb"

    packages = []
    for key, filename in sorted(debs.items()):
        parts = key.rsplit("_", 1)
        ver_rev = parts[0]
        arch_deb = parts[1]
        version = ver_rev.split("-")[0]

        arch = _DEB_TO_PWNLIBC.get(arch_deb, arch_deb)

        packages.append(DebPackage(
            version=version,
            full_id=key,
            arch=arch,
            filename=filename,
            dbg_filename=dbgs.get(key),
            mirror=mirror,
        ))

    return packages


def _download_file(url: str, dest: Path, progress_cb=None):
    # Download to a .part file and rename on success: a Ctrl-C mid-download
    # must not leave a truncated file that callers would treat as complete.
    # Transient network errors are retried; each attempt restarts the .part.
    part = dest.with_name(dest.name + ".part")

    def attempt():
        req = urllib.request.Request(url, headers={"User-Agent": "pwnlibc/0.1"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            with open(part, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_cb:
                        progress_cb(downloaded, total)

    try:
        _retry_transient(attempt)
        os.replace(part, dest)
    except BaseException:
        try:
            part.unlink()
        except OSError:
            pass
        raise


def _extract_deb(deb_path: Path, out_dir: Path, arch: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        subprocess.run(["ar", "x", str(deb_path)], cwd=tmp, check=True,
                        capture_output=True)

        data_tars = list(tmp.glob("data.tar.*"))
        if not data_tars:
            raise RuntimeError(f"No data.tar.* found in {deb_path}")
        data_tar = data_tars[0]

        if data_tar.suffix == ".zst":
            subprocess.run(["tar", "-I", "zstd", "-xf", str(data_tar)],
                            cwd=tmp, check=True, capture_output=True)
        else:
            subprocess.run(["tar", "xf", str(data_tar)],
                            cwd=tmp, check=True, capture_output=True)

        deb_lib_dir = ARCH_INFO[arch]["deb_lib_dir"]
        search_paths = [
            tmp / "lib" / deb_lib_dir,
            tmp / "usr" / "lib" / deb_lib_dir,
            tmp / "lib64",
            tmp / "lib",
        ]
        src_lib = None
        for p in search_paths:
            if p.is_dir():
                src_lib = p
                break

        if src_lib is None:
            raise RuntimeError(
                f"Could not find library directory in .deb. "
                f"Searched: {[str(p) for p in search_paths]}"
            )

        out_dir.mkdir(parents=True, exist_ok=True)
        for item in src_lib.iterdir():
            dest = out_dir / item.name
            if item.is_symlink():
                if dest.exists() or dest.is_symlink():
                    dest.unlink()
                # os.readlink, not Path.readlink: the latter needs Python 3.9
                dest.symlink_to(os.readlink(item))
            elif item.is_file():
                shutil.copy2(item, dest)
            elif item.is_dir():
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(item, dest, symlinks=True)


def _extract_dbg_deb(deb_path: Path, out_dir: Path, arch: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        subprocess.run(["ar", "x", str(deb_path)], cwd=tmp, check=True,
                        capture_output=True)

        data_tars = list(tmp.glob("data.tar.*"))
        if not data_tars:
            return
        data_tar = data_tars[0]

        if data_tar.suffix == ".zst":
            subprocess.run(["tar", "-I", "zstd", "-xf", str(data_tar)],
                            cwd=tmp, check=True, capture_output=True)
        else:
            subprocess.run(["tar", "xf", str(data_tar)],
                            cwd=tmp, check=True, capture_output=True)

        deb_lib_dir = ARCH_INFO[arch]["deb_lib_dir"]
        search_paths = [
            tmp / "usr" / "lib" / "debug" / "lib" / deb_lib_dir,
            tmp / "usr" / "lib" / "debug" / ".build-id",
            tmp / "usr" / "lib" / "debug",
        ]

        debug_out = out_dir / ".debug"
        debug_out.mkdir(parents=True, exist_ok=True)

        # Flatten .build-id/xx/hash.debug into .debug/hash.debug: Ubuntu libc's
        # .gnu_debuglink names the bare hash file, and GDB's default
        # <objdir>/.debug/<name> lookup finds it flat (verified with real GDB).
        # Do not "clean this up" into a nested layout — it breaks symbol resolution.
        for p in search_paths:
            if p.is_dir():
                for item in p.rglob("*"):
                    if item.is_file():
                        dest = debug_out / item.name
                        shutil.copy2(item, dest)
                break


def download_glibc(
    pkg: DebPackage,
    glibc_dir: Path,
    mirror: str = "ubuntu",
    include_dbg: bool = True,
    cache_dir: Path | None = None,
    progress_cb=None,
) -> Path:
    mirror_url = MIRRORS[mirror]
    out_dir = glibc_dir / pkg.version / pkg.arch / "lib"

    if cache_dir is None:
        cache_dir = glibc_dir / ".cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    deb_url = mirror_url + pkg.filename
    deb_path = cache_dir / pkg.filename
    if not deb_path.exists():
        _download_file(deb_url, deb_path, progress_cb)
    _verify_deb(pkg.filename, pkg, cache_dir, "libc6")

    _extract_deb(deb_path, out_dir, pkg.arch)

    if include_dbg and pkg.dbg_filename:
        dbg_url = mirror_url + pkg.dbg_filename
        dbg_path = cache_dir / pkg.dbg_filename
        if not dbg_path.exists():
            _download_file(dbg_url, dbg_path, progress_cb)
        _verify_deb(pkg.dbg_filename, pkg, cache_dir, "libc6-dbg")
        _extract_dbg_deb(dbg_path, out_dir, pkg.arch)

    return out_dir.parent


def download_source(version: str, glibc_dir: Path, progress_cb=None,
                    url: str | None = None) -> Path:
    from .builder import check_source_available
    from .config import gnu_source_version

    if url is None:
        url = check_source_available(version)
    if url is None:
        src_ver = gnu_source_version(version)
        raise RuntimeError(f"Source not available on ftp.gnu.org for glibc-{src_ver}")

    source_dir = glibc_dir / version / "source"

    # Extract into a temp dir and swap into place only on success: a
    # truncated tarball or Ctrl-C mid-extraction must not leave a partial
    # tree that every presence gate would then treat as installed. The
    # rmtree just before the swap only ever removes pwnlibc-managed state
    # (<version>/source is written exclusively by this tool and by
    # builder.build_glibc's save step).
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        tarball = tmp / url.rsplit("/", 1)[-1]
        _download_file(url, tarball, progress_cb)
        extract_dir = tmp / "extract"
        extract_dir.mkdir()
        subprocess.run(
            ["tar", "xf", str(tarball), "-C", str(extract_dir)],
            check=True, capture_output=True,
        )
        if source_dir.exists():
            shutil.rmtree(source_dir)
        source_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(extract_dir), str(source_dir))

    return source_dir


# The debug_glibc repo stores its prebuilt tarballs as Git-LFS objects: the
# raw URL serves a small text pointer (which conveniently carries the sha256
# and size of the real blob), and the media URL serves the blob itself —
# so a single version can be fetched and verified without cloning the repo.
DEBUG_GLIBC_REPO = "newbiee2018/debug_glibc"


def _parse_lfs_pointer(raw: bytes) -> tuple[str, int] | None:
    """(sha256, size) from a Git-LFS pointer stub, or None if raw isn't one."""
    if not raw.startswith(b"version https://git-lfs"):
        return None
    sha = None
    size = None
    for line in raw.decode("ascii", errors="replace").splitlines():
        if line.startswith("oid sha256:"):
            sha = line.split(":", 1)[1].strip()
        elif line.startswith("size "):
            try:
                size = int(line.split()[1])
            except (IndexError, ValueError):
                return None
    if sha is None or size is None or len(sha) != 64:
        return None
    return sha, size


def debug_glibc_fetch(version: str, dest: Path) -> Path:
    """Download one prebuilt debug-glibc tarball from the debug_glibc repo
    without cloning it: fetch the LFS pointer (sha256 + size of the blob),
    fetch the blob from the media endpoint, verify both, write to dest.

    Raises RuntimeError when the raw URL stops serving an LFS pointer (repo
    layout change) or the blob does not match the pointer's hash/size.
    """
    pointer_url = (f"https://raw.githubusercontent.com/{DEBUG_GLIBC_REPO}"
                   f"/main/{version}.tar.gz")
    blob_url = (f"https://media.githubusercontent.com/media/{DEBUG_GLIBC_REPO}"
                f"/main/{version}.tar.gz")
    parsed = _parse_lfs_pointer(_fetch_bytes(pointer_url))
    if parsed is None:
        raise RuntimeError(
            f"{version}.tar.gz on debug_glibc is not a Git-LFS pointer — "
            f"the repo layout may have changed"
        )
    expected_sha, expected_size = parsed
    blob = _fetch_bytes(blob_url)
    if (len(blob) != expected_size
            or hashlib.sha256(blob).hexdigest() != expected_sha):
        raise RuntimeError(
            f"SHA256 mismatch for debug_glibc {version}.tar.gz: "
            f"expected {expected_sha[:16]}… "
            f"got {hashlib.sha256(blob).hexdigest()[:16]}…"
        )
    dest.write_bytes(blob)
    return dest


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _candidate_suites(pkg: DebPackage) -> list[str]:
    """Dists suites whose Packages index may pin this package, in try order.

    Only each suite's CURRENT revision is indexed (e.g. 2.31-0ubuntu9.18
    lives in focal-updates, 2.31-0ubuntu9 in focal), so all pockets of the
    release are tried. An empty result means the file is not verifiable
    (unknown version or mirror) and verification is skipped.
    """
    origin = _MIRROR_ORIGIN.get(pkg.mirror)
    if origin == "ubuntu":
        suite = _UBUNTU_SUITES.get(pkg.version)
        if suite is not None:
            return [f"{suite}-updates", f"{suite}-security", suite]
    elif origin == "debian":
        suite = _DEBIAN_SUITES.get(pkg.version)
        if suite is not None:
            return [f"{suite}-updates", suite]
    return []


def _mirror_dists_base(mirror: str) -> str:
    """HTTPS base of the mirror's dists tree (host root before /pool/).

    The dists tree hangs off the same host as the pool; the base is forced
    to https so hash metadata is never fetched over plain http even while
    MIRRORS entries are http.
    """
    pool_url = MIRRORS[mirror]
    if "/pool/" in pool_url:
        base = pool_url.split("/pool/")[0]
    else:
        base = pool_url.rstrip("/")
    if base.startswith("http://"):
        base = "https://" + base[len("http://"):]
    return base


def _index_urls(mirror: str, suite: str, deb_arch: str) -> list[str]:
    """Packages index URLs for one suite: .xz first, .gz fallback."""
    base = _mirror_dists_base(mirror)
    path = f"/dists/{suite}/main/binary-{deb_arch}/Packages"
    return [base + path + ".xz", base + path + ".gz"]


def _decompress_index(raw: bytes) -> bytes:
    # Sniff the magic bytes rather than trusting the filename, so a
    # mislabeled cache entry still decompresses.
    if raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw)
    return lzma.decompress(raw)


def _parse_packages_sha256(raw: bytes, deb_filename: str) -> str | None:
    """SHA256 of deb_filename from raw (compressed) Packages index bytes.

    Returns None when the index does not list the file; raises on corrupt
    compressed data so callers can drop the bad cache entry.
    """
    text = _decompress_index(raw).replace(b"\r\n", b"\n")
    want = b"/" + deb_filename.encode("utf-8")
    for stanza in text.split(b"\n\n"):
        filename = None
        sha256 = None
        for line in stanza.split(b"\n"):
            if line.startswith(b"Filename:"):
                filename = line[len(b"Filename:"):].strip()
            elif line.startswith(b"SHA256:"):
                sha256 = line[len(b"SHA256:"):].strip()
        if filename is not None and filename.endswith(want):
            if sha256 is not None and len(sha256) == 64:
                return sha256.decode("ascii", errors="replace").lower()
            return None
    return None


def _cache_fresh(path: Path) -> bool:
    try:
        return time.time() - path.stat().st_mtime <= _INDEX_TTL_SECONDS
    except OSError:
        return False


def _miss_marker_matches(marker: Path, deb_filename: str) -> bool:
    try:
        return deb_filename in marker.read_text("ascii").split()
    except (OSError, UnicodeDecodeError):
        return False


class _IndexUnavailable(Exception):
    """No dists index for a suite could be fetched or parsed.

    Distinct from "a valid index does not list the file": an unavailable
    index is evidence of nothing and must never be negative-cached.
    """


def _write_miss_marker(index_dir: Path, deb_filename: str) -> None:
    # One filename per line, so libc6 and libc6-dbg misses coexist.
    try:
        index_dir.mkdir(parents=True, exist_ok=True)
        marker = index_dir / "Packages.miss"
        try:
            known = marker.read_text("ascii").split()
        except OSError:
            known = []
        if deb_filename not in known:
            marker.write_text("\n".join(known + [deb_filename]) + "\n", "ascii")
    except OSError:
        pass


def _suite_lookup(index_dir: Path, mirror: str, suite: str,
                  deb_arch: str, deb_filename: str) -> str | None:
    """Search one suite's Packages index (cache-first) for deb_filename.

    Returns None when the file is provably absent: a valid index parsed
    without a hit, or the mirror answered 404 (the index does not exist —
    e.g. EOL pockets on old-releases). Raises _IndexUnavailable when the
    lookup was inconclusive (network errors, unparseable responses) —
    callers must not negative-cache that.
    """
    absence_settled = False
    for url in _index_urls(mirror, suite, deb_arch):
        cached = index_dir / url.rsplit("/", 1)[-1]
        if cached.exists() and _cache_fresh(cached):
            try:
                # A valid index settles the suite either way; the .gz twin
                # holds the same stanzas, so don't fall through to it.
                return _parse_packages_sha256(cached.read_bytes(), deb_filename)
            except (OSError, EOFError, lzma.LZMAError):
                try:  # corrupt cache entry: drop it and refetch below
                    cached.unlink()
                except OSError:
                    pass
        try:
            raw = _fetch_bytes(url)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                absence_settled = True  # the mirror says: no such index
            # any other HTTP status is inconclusive: fall through without
            # settling absence, so the suite ends up _IndexUnavailable
            continue
        except Exception:
            continue
        try:
            index_dir.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(raw)
        except OSError:
            pass  # cache write failure is non-fatal
        try:
            # A valid index settles the suite either way: a hit returns the
            # sha, a miss returns None — only after this line is the file
            # provably absent from this suite.
            return _parse_packages_sha256(raw, deb_filename)
        except (OSError, EOFError, lzma.LZMAError):
            continue
    if absence_settled:
        return None
    raise _IndexUnavailable(suite)


def _warn_unverifiable_version(pkg: DebPackage) -> None:
    """Announce on stderr (once per glibc version) that no suite maps it.

    Without this, a suite map gone stale after a new release silently
    degrades every download of that version to "no verification". The
    dedupe keeps runs with many arches/files per version readable.
    """
    if pkg.version in _unknown_suite_versions:
        return
    _unknown_suite_versions.add(pkg.version)
    print(
        f"warning: no suite mapping for glibc {pkg.version} ({pkg.mirror}); "
        f"downloading WITHOUT SHA256 verification — the suite map may be "
        f"stale for new releases",
        file=sys.stderr,
    )


def _expected_sha256_detail(pkg: DebPackage, deb_filename: str,
                            cache_dir: Path) -> tuple[str | None, bool]:
    """Core lookup: (expected SHA256, index_fetch_failed).

    sha is None when no index lists the file (EOL leftovers, superseded
    revisions). index_fetch_failed is True when at least one candidate
    suite's index could not be fetched — the caller should warn instead of
    letting the download pass silently as "unverifiable".
    """
    suites = _candidate_suites(pkg)
    if not suites:
        _warn_unverifiable_version(pkg)
        return None, False
    deb_arch = ARCH_INFO.get(pkg.arch, {}).get("deb_arch")
    if deb_arch is None:
        return None, False

    settled_misses: list[str] = []  # suites with a valid index that don't list it
    fetch_failed = False
    for suite in suites:
        index_dir = cache_dir / "indices" / pkg.mirror / suite / deb_arch
        marker = index_dir / "Packages.miss"
        if _cache_fresh(marker) and _miss_marker_matches(marker, deb_filename):
            settled_misses.append(suite)  # already established genuine miss
            continue
        try:
            sha256 = _suite_lookup(index_dir, pkg.mirror, suite, deb_arch,
                                   deb_filename)
        except _IndexUnavailable:
            fetch_failed = True  # no marker: the network may just be down
            continue
        if sha256 is not None:
            return sha256, False
        settled_misses.append(suite)

    # Only suites whose index was seen (or already cached as a miss) count:
    # a fetched-nothing suite proves nothing and must not poison the cache
    # for the next 7 days.
    for suite in settled_misses:
        _write_miss_marker(
            cache_dir / "indices" / pkg.mirror / suite / deb_arch, deb_filename)
    return None, fetch_failed


def _expected_sha256(pkg: DebPackage, deb_filename: str,
                     cache_dir: Path) -> str | None:
    """Backward-compatible wrapper around _expected_sha256_detail."""
    return _expected_sha256_detail(pkg, deb_filename, cache_dir)[0]


def deb_sha256_expected(pkg: DebPackage, cache_dir: Path) -> str | None:
    """Expected SHA256 from the owning suite's Packages index, or None when
    no index lists the file (EOL leftovers, superseded revisions)."""
    return _expected_sha256(pkg, pkg.filename, cache_dir)


def expected_sha256_status(pkg: DebPackage,
                           cache_dir: Path) -> tuple[str | None, bool]:
    """Like deb_sha256_expected, but also reports whether the lookup was
    inconclusive because a dists index could not be fetched."""
    return _expected_sha256_detail(pkg, pkg.filename, cache_dir)


def _verify_deb(pkg_filename: str, pkg: DebPackage, cache_dir: Path,
                label: str) -> None:
    """Verify a cached .deb against the SHA256 pinned in the dists index.

    Unverifiable files (no index lists them — EOL leftovers, superseded
    revisions) are skipped by design. When the index itself could not be
    fetched, the skip is announced on stderr instead of passing silently.
    A mismatch deletes the file and raises so callers surface it instead
    of extracting tampered bytes.
    """
    expected, fetch_failed = _expected_sha256_detail(pkg, pkg_filename,
                                                     cache_dir)
    if expected is None:
        if fetch_failed:
            print(
                f"warning: could not fetch the Packages index for {label} "
                f"{pkg_filename}; proceeding WITHOUT SHA256 verification "
                f"this run (network failure is not cached)",
                file=sys.stderr,
            )
        return
    path = cache_dir / pkg_filename
    actual = sha256_file(path)
    if actual != expected:
        try:
            path.unlink()
        except OSError:
            pass
        raise RuntimeError(
            f"SHA256 mismatch for {label} {pkg_filename}: "
            f"expected {expected[:16]}… got {actual[:16]}…"
        )


def _compare_tree(ref_dir: Path, inst_dir: Path) -> list[tuple[str, str, str]]:
    """Recursively compare every file under ref_dir against inst_dir.

    Returns rows of (rel_path, status, detail) with `/`-separated names
    relative to the lib root (e.g. "gconv/gconv-modules"), sorted by name
    for deterministic output. Statuses: MATCH | MISSING | MISMATCH |
    BROKEN_SYMLINK.

    Ref symlinks must exist on the installed side as symlinks with an
    identical os.readlink target string (MATCH); a different target or a
    non-symlink is a MISMATCH. The `.debug/` subtree (installed by the
    separate libc6-dbg deb) is never compared.
    """
    results: list[tuple[str, str, str]] = []

    # os.walk, not Path.walk: the latter needs Python 3.13.
    for root, dirs, files in os.walk(ref_dir):
        # Prune .debug/ from the walk and keep dir order deterministic.
        dirs[:] = sorted(d for d in dirs if d != ".debug")

        # os.walk puts symlinks-to-files (and dangling ones) in `files`;
        # symlinks-to-dirs land in `dirs` and are not descended into, so
        # surface them here to get their readlink comparison too.
        entries = sorted(files) + sorted(
            d for d in dirs if (Path(root) / d).is_symlink())

        for name in entries:
            ref_path = Path(root) / name
            rel = ref_path.relative_to(ref_dir).as_posix()
            inst_path = inst_dir / rel

            if not os.path.lexists(inst_path):
                results.append((rel, "MISSING", ""))
                continue

            if ref_path.is_symlink():
                # os.readlink, not Path.readlink: the latter needs Python 3.9
                ref_target = os.readlink(ref_path)
                if not inst_path.is_symlink():
                    results.append(
                        (rel, "MISMATCH", f"expected symlink to {ref_target}"))
                elif not inst_path.resolve().exists():
                    results.append(
                        (rel, "BROKEN_SYMLINK", os.readlink(inst_path)))
                else:
                    inst_target = os.readlink(inst_path)
                    if inst_target == ref_target:
                        results.append((rel, "MATCH", f"symlink to {ref_target}"))
                    else:
                        results.append((rel, "MISMATCH",
                                        f"expected={ref_target} got={inst_target}"))
                continue

            # Regular ref file: the installed side may still be a (valid)
            # symlink to the same bytes; a dangling one is broken.
            if inst_path.is_symlink() and not inst_path.resolve().exists():
                results.append((rel, "BROKEN_SYMLINK", os.readlink(inst_path)))
                continue

            ref_hash = sha256_file(ref_path)
            inst_hash = sha256_file(inst_path)
            if ref_hash == inst_hash:
                results.append((rel, "MATCH", ref_hash[:16]))
            else:
                results.append((rel, "MISMATCH",
                                f"expected={ref_hash[:16]} got={inst_hash[:16]}"))

    results.sort(key=lambda row: row[0])
    return results


def verify_against_deb(
    pkg: DebPackage,
    glibc_dir: Path,
    mirror: str | None = None,
    cache_dir: Path | None = None,
) -> list[tuple[str, str, str]]:
    # Default to the mirror the package was actually scraped from — the
    # reference .deb may not exist on the primary mirror (EOL versions).
    mirror = mirror or pkg.mirror
    mirror_url = MIRRORS[mirror]
    if cache_dir is None:
        cache_dir = glibc_dir / ".cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    deb_path = cache_dir / pkg.filename
    if not deb_path.exists():
        _download_file(mirror_url + pkg.filename, deb_path)
    _verify_deb(pkg.filename, pkg, cache_dir, "libc6")

    with tempfile.TemporaryDirectory() as tmpdir:
        ref_dir = Path(tmpdir) / "ref"
        ref_dir.mkdir()
        _extract_deb(deb_path, ref_dir, pkg.arch)

        installed_lib = glibc_dir / pkg.version / pkg.arch / "lib"
        return _compare_tree(ref_dir, installed_lib)
