from __future__ import annotations

import gzip
import hashlib
import lzma
import os
import re
import shutil
import subprocess
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
# Versions/suites not listed here simply skip hash verification.
_UBUNTU_SUITES = {
    "2.19": "trusty", "2.23": "xenial", "2.27": "bionic", "2.31": "focal",
    "2.35": "jammy", "2.37": "lunar", "2.38": "mantic", "2.39": "noble",
    "2.40": "oracular", "2.41": "plucky",
}
_DEBIAN_SUITES = {
    "2.24": "stretch", "2.28": "buster", "2.31": "bullseye",
    "2.36": "bookworm", "2.41": "trixie",
}

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

    # Record the install in the database so list/verify/remove know exactly
    # which .deb this came from, even after the mirror moves on.
    from .store import InstallRecord, InstallStore
    store = InstallStore(glibc_dir)
    store.upsert(InstallRecord(
        version=pkg.version, arch=pkg.arch, variant="deb", mirror=mirror,
        filename=pkg.filename, full_id=pkg.full_id,
        dbg_filename=pkg.dbg_filename if include_dbg else None,
        has_dbg=include_dbg and bool(pkg.dbg_filename),
    ))
    store.save()

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
    source_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tarball = Path(tmpdir) / url.rsplit("/", 1)[-1]
        _download_file(url, tarball, progress_cb)
        subprocess.run(
            ["tar", "xf", str(tarball), "-C", str(source_dir)],
            check=True, capture_output=True,
        )

    from .store import InstallStore
    store = InstallStore(glibc_dir)
    store.add_source(version)
    store.save()

    return source_dir


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


def _index_urls(mirror: str, suite: str, deb_arch: str) -> list[str]:
    """Packages index URLs for one suite: .xz first, .gz fallback.

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
    """Search one suite's Packages index (cache-first) for deb_filename."""
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
        except Exception:
            continue
        try:
            index_dir.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(raw)
        except OSError:
            pass  # cache write failure is non-fatal
        try:
            return _parse_packages_sha256(raw, deb_filename)
        except (OSError, EOFError, lzma.LZMAError):
            continue
    return None


def _expected_sha256(pkg: DebPackage, deb_filename: str,
                     cache_dir: Path) -> str | None:
    """Core lookup: expected SHA256 for one pool filename, or None when no
    index lists it (EOL leftovers, superseded revisions)."""
    suites = _candidate_suites(pkg)
    if not suites:
        return None
    deb_arch = ARCH_INFO.get(pkg.arch, {}).get("deb_arch")
    if deb_arch is None:
        return None

    for suite in suites:
        index_dir = cache_dir / "indices" / pkg.mirror / suite / deb_arch
        marker = index_dir / "Packages.miss"
        if _cache_fresh(marker) and _miss_marker_matches(marker, deb_filename):
            continue  # already known: this suite does not list the file
        sha256 = _suite_lookup(index_dir, pkg.mirror, suite, deb_arch,
                               deb_filename)
        if sha256 is not None:
            return sha256

    # Nothing lists the file. Negative-cache per suite so repeated downloads
    # don't refetch multi-megabyte indices for permanently unverifiable
    # files (e.g. trusty leftovers that no dists index ever referenced).
    for suite in suites:
        _write_miss_marker(
            cache_dir / "indices" / pkg.mirror / suite / deb_arch, deb_filename)
    return None


def deb_sha256_expected(pkg: DebPackage, cache_dir: Path) -> str | None:
    """Expected SHA256 from the owning suite's Packages index, or None when
    no index lists the file (EOL leftovers, superseded revisions)."""
    return _expected_sha256(pkg, pkg.filename, cache_dir)


def _verify_deb(pkg_filename: str, pkg: DebPackage, cache_dir: Path,
                label: str) -> None:
    """Verify a cached .deb against the SHA256 pinned in the dists index.

    Unverifiable files (no index lists them — EOL leftovers, superseded
    revisions) are skipped by design. A mismatch deletes the file and
    raises so callers surface it instead of extracting tampered bytes.
    """
    expected = _expected_sha256(pkg, pkg_filename, cache_dir)
    if expected is None:
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
        results = []

        ld_soname = ARCH_INFO.get(pkg.arch, {}).get("ld_soname", "ld-linux-x86-64.so.2")
        key_files = ["libc.so.6", ld_soname, "libpthread.so.0", "libm.so.6"]
        for name in key_files:
            ref_file = ref_dir / name
            inst_file = installed_lib / name

            if not ref_file.exists():
                continue

            # For old glibc (≤2.33), key names are symlinks to versioned files.
            # Resolve to compare the real binaries.
            if ref_file.is_symlink():
                # os.readlink, not Path.readlink: the latter needs Python 3.9
                target_name = os.readlink(ref_file)
                ref_file = ref_dir / target_name
                if not ref_file.exists():
                    continue
                inst_file = installed_lib / target_name

            if not inst_file.exists():
                results.append((name, "MISSING", ""))
                continue

            if inst_file.is_symlink():
                target = inst_file.resolve()
                if not target.exists():
                    results.append((name, "BROKEN_SYMLINK", ""))
                    continue
                inst_file = target

            ref_hash = sha256_file(ref_file)
            inst_hash = sha256_file(inst_file)

            if ref_hash == inst_hash:
                results.append((name, "MATCH", ref_hash[:16]))
            else:
                results.append((name, "MISMATCH", f"expected={ref_hash[:16]} got={inst_hash[:16]}"))

        return results
