from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import ARCH_INFO, BUILD_DEPS, GNU_SOURCE_BASE, GNU_SOURCE_FORMATS, gnu_source_version
from .downloader import _download_file


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
        elif arch == "i686":
            # gcc -m32 needs the multilib set; gcc prints the bare name when it's missing
            r = subprocess.run(["gcc", "-m32", "-print-file-name=libgcc.a"],
                               capture_output=True, text=True)
            if r.returncode != 0 or r.stdout.strip() == "libgcc.a":
                missing.append("gcc-multilib (gcc cannot compile 32-bit)")
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


def _local_source_dir(glibc_dir: Path, version: str) -> Path | None:
    """Find a reusable extracted source tree under <glibc_dir>/<version>/source/.

    Prefers glibc-<gnu_source_version(version)>, else the first directory
    there (sorted, for determinism) that contains a `configure` file. A dir
    without `configure` is an incomplete extraction and is NOT reusable —
    None is returned so the caller falls back to downloading the tarball.
    """
    source_root = glibc_dir / version / "source"
    if not source_root.is_dir():
        return None
    preferred = source_root / f"glibc-{gnu_source_version(version)}"
    if (preferred / "configure").is_file():
        return preferred
    for d in sorted(source_root.iterdir()):
        if d.is_dir() and (d / "configure").is_file():
            return d
    return None


def build_glibc(
    version: str,
    arch: str,
    glibc_dir: Path,
    progress_cb=None,
    timeout: int = 1800,
) -> Path:
    info = ARCH_INFO[arch]
    triplet = info["cross_triplet"]
    out_prefix = glibc_dir / version / f"{arch}-built"

    src_ver = gnu_source_version(version)
    local_src = _local_source_dir(glibc_dir, version)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        # Stage the install inside the temp dir and swap it into place only
        # after the whole build succeeds, so a failed rebuild never destroys
        # the user's existing (expensive-to-recreate) built variant.
        install_dir = tmp / "install"

        if local_src is not None:
            # Reuse the already-extracted source tree in place (saved by
            # `source download` or a previous build). The build dir below is
            # a separate temp dir and out-of-tree builds never write into
            # the source, so no copy is made.
            src_dir = local_src
            if progress_cb:
                progress_cb("using local source", 0, 0)
        else:
            url = check_source_available(version)
            if url is None:
                raise RuntimeError(f"Source not found on ftp.gnu.org for glibc-{src_ver}")

            tarball = tmp / url.rsplit("/", 1)[-1]

            if progress_cb:
                progress_cb("downloading source", 0, 0)
                dl_cb = lambda d, t: progress_cb("downloading source", d, t)
            else:
                dl_cb = None
            _download_file(url, tarball, dl_cb)

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

        # No --enable-debug: glibc's configure has no such AC_ARG_ENABLE
        # option (it hardcodes enable_option_checking=no, so the flag would
        # be a silent no-op). Debug info comes from CFLAGS="-g3" below.
        configure_args = [
            str(src_dir / "configure"),
            "--prefix=/",
            "--disable-werror",
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
            # --build is auto-detected by config.guess, so cross builds work from any host
            configure_args.append(f"--host={triplet}")
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
            timeout=(timeout if timeout and timeout > 0 else None),
        )
        if result.returncode != 0:
            raise RuntimeError(f"make failed:\n{result.stderr[-2000:]}")

        if progress_cb:
            progress_cb("installing", 0, 0)
        result = subprocess.run(
            ["make", "install", f"DESTDIR={install_dir}"],
            cwd=build_dir,
            env=env,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            result2 = subprocess.run(
                ["make", f"install_root={install_dir}", "install"],
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

        # Whole build succeeded: swap the staged install into place (still
        # inside the temp-dir scope — the staging dir lives there). Only now
        # is the previous variant (if any) discarded. A make install that
        # produced nothing (fully mocked runs) keeps the old empty-variant
        # behavior instead of failing the swap.
        if out_prefix.exists():
            shutil.rmtree(out_prefix)
        out_prefix.parent.mkdir(parents=True, exist_ok=True)
        if install_dir.exists():
            shutil.move(str(install_dir), str(out_prefix))
        else:
            out_prefix.mkdir(parents=True)

    return out_prefix
