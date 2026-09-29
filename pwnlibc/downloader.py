from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .config import ARCH_INFO, MIRRORS

_ALL_DEB_ARCHES = "|".join(info["deb_arch"] for info in ARCH_INFO.values())

# Match versions like 2.31, 2.3.6, 2.3.2.ds1
DEB_PATTERN = re.compile(
    r'libc6_(?P<full>(?P<ver>2\.\d+(?:\.\d+)?(?:\.ds1)?)-[^"_]+_(?P<arch>' + _ALL_DEB_ARCHES + r'))\.deb'
)
DBG_PATTERN = re.compile(
    r'libc6-dbg_(?P<full>(?P<ver>2\.\d+(?:\.\d+)?(?:\.ds1)?)-[^"_]+_(?P<arch>' + _ALL_DEB_ARCHES + r'))\.deb'
)

_DEB_TO_PWNLIBC = {info["deb_arch"]: name for name, info in ARCH_INFO.items()}


@dataclass
class DebPackage:
    version: str
    full_id: str
    arch: str
    filename: str
    dbg_filename: str | None
    mirror: str = "ubuntu"


def _fetch_index(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "pwnlibc/0.1"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


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
    req = urllib.request.Request(url, headers={"User-Agent": "pwnlibc/0.1"})
    part = dest.with_name(dest.name + ".part")
    try:
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
                dest.symlink_to(item.readlink())
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

    _extract_deb(deb_path, out_dir, pkg.arch)

    if include_dbg and pkg.dbg_filename:
        dbg_url = mirror_url + pkg.dbg_filename
        dbg_path = cache_dir / pkg.dbg_filename
        if not dbg_path.exists():
            _download_file(dbg_url, dbg_path, progress_cb)
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
    source_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tarball = Path(tmpdir) / url.rsplit("/", 1)[-1]
        _download_file(url, tarball, progress_cb)
        subprocess.run(
            ["tar", "xf", str(tarball), "-C", str(source_dir)],
            check=True, capture_output=True,
        )

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
                target_name = ref_file.readlink()
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
