from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import ARCH_INFO, BUILD_DEPS, GNU_SOURCE_BASE, GNU_SOURCE_FORMATS, gnu_source_version


def check_build_deps(arch: str) -> list[str]:
    missing = []
    for dep in BUILD_DEPS:
        if not shutil.which(dep):
            missing.append(dep)

    info = ARCH_INFO[arch]
    cross_gcc = info["cross_gcc"]

    if arch in ("amd64", "i686"):
        if not shutil.which("gcc"):
            missing.append("gcc")
    else:
        bin_name = info["cross_triplet"] + "-gcc"
        if not shutil.which(bin_name):
            missing.append(f"{cross_gcc} (provides {bin_name})")

    return missing


def get_install_cmd(arch: str) -> str:
    info = ARCH_INFO[arch]
    pkgs = list(BUILD_DEPS)
    if arch in ("amd64", "i686"):
        pkgs.append("gcc")
        if arch == "i686":
            pkgs.append("gcc-multilib")
    else:
        pkgs.append(info["cross_gcc"])
    return "sudo apt install " + " ".join(pkgs)


def check_source_available(version: str) -> str | None:
    """Check ftp.gnu.org for source. Returns URL if found, None otherwise.

    Tries .tar.xz, .tar.gz, .tar.bz2. Handles .ds1 versions (2.3.2.ds1 → 2.3.2).
    """
    import urllib.request
    src_ver = gnu_source_version(version)
    for fmt in GNU_SOURCE_FORMATS:
        url = GNU_SOURCE_BASE + fmt.format(version=src_ver)
        try:
            req = urllib.request.Request(url, method="HEAD",
                                         headers={"User-Agent": "pwnlibc/0.1"})
            with urllib.request.urlopen(req, timeout=10):
                return url
        except Exception:
            continue
    return None


def build_glibc(
    version: str,
    arch: str,
    glibc_dir: Path,
    progress_cb=None,
) -> Path:
    import urllib.request

    info = ARCH_INFO[arch]
    triplet = info["cross_triplet"]
    out_prefix = glibc_dir / version / f"{arch}-built"

    if out_prefix.exists():
        shutil.rmtree(out_prefix)
    out_prefix.mkdir(parents=True)

    src_ver = gnu_source_version(version)
    url = check_source_available(version)
    if url is None:
        raise RuntimeError(f"Source not found on ftp.gnu.org for glibc-{src_ver}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        tarball = tmp / url.rsplit("/", 1)[-1]

        if progress_cb:
            progress_cb("downloading source", 0, 0)
        req = urllib.request.Request(url, headers={"User-Agent": "pwnlibc/0.1"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            with open(tarball, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_cb:
                        progress_cb("downloading source", downloaded, total)

        if progress_cb:
            progress_cb("extracting source", 0, 0)
        subprocess.run(["tar", "xf", str(tarball), "-C", str(tmp)],
                        check=True, capture_output=True)

        src_dir = tmp / f"glibc-{src_ver}"
        if not src_dir.is_dir():
            candidates = [d for d in tmp.iterdir() if d.is_dir() and d.name.startswith("glibc")]
            if candidates:
                src_dir = candidates[0]
            else:
                raise RuntimeError(f"Source directory not found after extracting {tarball}")

        build_dir = tmp / "build"
        build_dir.mkdir()

        env = dict(os.environ)

        configure_args = [
            str(src_dir / "configure"),
            "--prefix=/",
            "--disable-werror",
            "--enable-debug=yes",
        ]

        if arch == "i686":
            env["CC"] = "gcc -m32"
            env["CXX"] = "g++ -m32"
            configure_args.append("--host=i686-linux-gnu")
            configure_args.append("--build=i686-linux-gnu")
            env["CFLAGS"] = "-g3 -O1 -U_FORTIFY_SOURCE"
        elif arch == "amd64":
            env["CFLAGS"] = "-g3 -O1 -U_FORTIFY_SOURCE"
        else:
            cc = f"{triplet}-gcc"
            env["CC"] = cc
            env["CXX"] = f"{triplet}-g++"
            configure_args.append(f"--host={triplet}")
            configure_args.append(f"--build=x86_64-linux-gnu")
            env["CFLAGS"] = "-g3 -O1 -U_FORTIFY_SOURCE"

        if progress_cb:
            progress_cb("configuring", 0, 0)
        result = subprocess.run(
            configure_args,
            cwd=build_dir,
            env=env,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"configure failed:\n{result.stderr[-2000:]}")

        if progress_cb:
            progress_cb("compiling (this takes a while)", 0, 0)
        nproc = os.cpu_count() or 1
        result = subprocess.run(
            ["make", f"-j{nproc}"],
            cwd=build_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if result.returncode != 0:
            raise RuntimeError(f"make failed:\n{result.stderr[-2000:]}")

        if progress_cb:
            progress_cb("installing", 0, 0)
        result = subprocess.run(
            ["make", "install", f"DESTDIR={out_prefix}"],
            cwd=build_dir,
            env=env,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            result2 = subprocess.run(
                ["make", f"install_root={out_prefix}", "install"],
                cwd=build_dir,
                env=env,
                capture_output=True,
                text=True,
            )
            if result2.returncode != 0:
                raise RuntimeError(f"make install failed:\n{result2.stderr[-2000:]}")

        # Save source for GDB before temp dir is cleaned up
        save_source = glibc_dir / version / "source"
        if not save_source.exists():
            save_source.mkdir(parents=True, exist_ok=True)
            if src_dir.is_dir():
                shutil.copytree(src_dir, save_source / src_dir.name)

    return out_prefix
