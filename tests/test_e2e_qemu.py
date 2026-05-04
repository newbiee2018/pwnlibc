"""End-to-end tests: cross-compile, patch, and run under qemu-user.

These tests actually download a real glibc, cross-compile a test binary,
patch it, and verify it runs correctly under qemu-user emulation.

Marked @pytest.mark.network and @pytest.mark.slow — skipped by default.
Tests pick random glibc versions from the mirror rather than hardcoding.
"""

import os
import random
import shutil
import subprocess
from pathlib import Path

import pytest

from pwnlibc.config import ARCH_INFO

# Map pwnlibc arch -> qemu binary base name (try both static and non-static)
_QEMU_BASE = {
    "arm64": "qemu-aarch64",
    "armhf": "qemu-arm",
    "ppc64el": "qemu-ppc64le",
    "s390x": "qemu-s390x",
    "riscv64": "qemu-riscv64",
    "mipsel": "qemu-mipsel",
    "mips64el": "qemu-mips64el",
}


def _find_qemu(arch):
    """Find qemu binary — try non-static first, fall back to -static."""
    base = _QEMU_BASE.get(arch)
    if base is None:
        return None
    for name in [base, f"{base}-static"]:
        if shutil.which(name):
            return name
    return None


QEMU_MAP = {}
for _arch, _base in _QEMU_BASE.items():
    _found = _find_qemu(_arch)
    QEMU_MAP[_arch] = _found if _found else _base

# Arches we can test (have both cross-compiler and qemu)
CROSS_ARCHES = list(QEMU_MAP.keys())


def _has_tool(name):
    return shutil.which(name) is not None


def _cross_compile(tmp_path, arch):
    """Cross-compile a minimal test binary. Returns path or None."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    triplet = ARCH_INFO[arch]["cross_triplet"]
    gcc = f"{triplet}-gcc"
    if not _has_tool(gcc):
        return None

    src = tmp_path / "hello.c"
    src.write_text('#include <stdio.h>\nint main(){puts("pwnlibc-test-ok");return 0;}\n')
    out = tmp_path / f"hello_{arch}"

    try:
        subprocess.run(
            [gcc, "-o", str(out), str(src), "-static-libgcc"],
            check=True, capture_output=True, text=True,
        )
        os.chmod(str(out), 0o755)
        return out
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _get_min_glibc_version(binary):
    """Get minimum glibc version required by a binary from its version symbols."""
    try:
        result = subprocess.run(
            ["readelf", "-V", str(binary)],
            capture_output=True, text=True, timeout=10,
        )
        import re
        versions = re.findall(r"GLIBC_(\d+\.\d+)", result.stdout)
        if versions:
            return max(versions, key=lambda v: tuple(int(x) for x in v.split(".")))
    except Exception:
        pass
    return "2.17"


def _pick_random_version(packages, arch, min_version=None, exclude=None):
    """Pick a random version from available packages for the given arch.

    Filters to versions >= min_version if specified.
    """
    from pwnlibc.config import parse_version
    candidates = [p for p in packages if p.arch == arch]
    if min_version:
        min_tuple = parse_version(min_version)
        candidates = [p for p in candidates if parse_version(p.version) >= min_tuple]
    if exclude:
        candidates = [p for p in candidates if p.version not in exclude]
    if not candidates:
        return None
    return random.choice(candidates)


def _run_qemu(binary, arch):
    """Run a binary under qemu-user. Returns subprocess result."""
    qemu = QEMU_MAP.get(arch)
    if qemu is None:
        return None

    triplet = ARCH_INFO[arch]["cross_triplet"]
    sysroot = f"/usr/{triplet}"

    cmd = [qemu, "-L", sysroot, str(binary)]

    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=30,
    )


class TestQemuAvailability:
    """Verify which qemu-user binaries and cross-compilers are available."""

    @pytest.mark.parametrize("arch", CROSS_ARCHES)
    def test_qemu_binary_check(self, arch):
        """Report which qemu-user binaries are installed (informational)."""
        qemu = QEMU_MAP[arch]
        available = _has_tool(qemu)
        print(f"{arch}: {qemu} = {'yes' if available else 'NO'}")

    @pytest.mark.parametrize("arch", CROSS_ARCHES)
    def test_cross_compiler_check(self, arch):
        """Report which cross-compilers are installed (informational)."""
        triplet = ARCH_INFO[arch]["cross_triplet"]
        gcc = f"{triplet}-gcc"
        available = _has_tool(gcc)
        print(f"{arch}: {gcc} = {'yes' if available else 'NO'}")


needs_patchelf = pytest.mark.skipif(
    not _has_tool("patchelf"), reason="patchelf not installed"
)


class TestCrossCompileAndRunUnpatched:
    """Verify cross-compile + qemu works BEFORE patching (baseline)."""

    @pytest.mark.parametrize("arch", CROSS_ARCHES)
    def test_unpatched_cross_binary(self, tmp_path, arch):
        """Cross-compile and run unpatched under qemu to verify toolchain works."""
        qemu = QEMU_MAP[arch]
        if not _has_tool(qemu):
            pytest.skip(f"{qemu} not installed")

        binary = _cross_compile(tmp_path / arch, arch)
        if binary is None:
            pytest.skip(f"cross-compiler for {arch} not installed")

        result = _run_qemu(binary, arch)
        assert result.returncode == 0, f"Unpatched {arch} binary failed: {result.stderr}"
        assert "pwnlibc-test-ok" in result.stdout


class TestPatchAndRunQemu:
    """Download real glibc, patch cross-compiled binary, run under qemu."""

    @pytest.mark.network
    @pytest.mark.slow
    @needs_patchelf
    @pytest.mark.parametrize("arch", CROSS_ARCHES)
    def test_inplace_patch_random_version(self, tmp_path, arch):
        """Pick a random glibc version, patch inplace, run under qemu."""
        qemu = QEMU_MAP[arch]
        if not _has_tool(qemu):
            pytest.skip(f"{qemu} not installed")

        binary = _cross_compile(tmp_path / f"work_{arch}", arch)
        if binary is None:
            pytest.skip(f"cross-compiler for {arch} not installed")

        from pwnlibc.downloader import download_glibc, scrape_available
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import patch_inplace

        min_ver = _get_min_glibc_version(binary)
        mirror = ARCH_INFO[arch]["mirror"]
        packages = scrape_available(mirror)
        pkg = _pick_random_version(packages, arch, min_version=min_ver)
        if pkg is None:
            pytest.skip(f"no packages >= {min_ver} for {arch} on {mirror}")

        print(f"Testing {arch} with randomly selected glibc {pkg.version} (min={min_ver})")

        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        download_glibc(pkg, glibc_dir, mirror=mirror, include_dbg=False)
        glibc = resolve_lib_paths(pkg.version, arch, glibc_dir)

        patched = patch_inplace(binary, glibc)

        result = subprocess.run(
            [qemu, "-L", str(glibc.lib_dir.parent), str(patched)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, (
            f"Patched {arch} binary (glibc {pkg.version}) failed: {result.stderr}"
        )
        assert "pwnlibc-test-ok" in result.stdout

    @pytest.mark.network
    @pytest.mark.slow
    @needs_patchelf
    @pytest.mark.parametrize("arch", CROSS_ARCHES)
    def test_copy_patch_random_version(self, tmp_path, arch):
        """Pick a random glibc version, patch in copy mode, run under qemu."""
        qemu = QEMU_MAP[arch]
        if not _has_tool(qemu):
            pytest.skip(f"{qemu} not installed")

        binary = _cross_compile(tmp_path / f"copy_{arch}", arch)
        if binary is None:
            pytest.skip(f"cross-compiler for {arch} not installed")

        from pwnlibc.downloader import download_glibc, scrape_available
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import patch_copy

        min_ver = _get_min_glibc_version(binary)
        mirror = ARCH_INFO[arch]["mirror"]
        packages = scrape_available(mirror)
        pkg = _pick_random_version(packages, arch, min_version=min_ver)
        if pkg is None:
            pytest.skip(f"no packages >= {min_ver} for {arch} on {mirror}")

        print(f"Testing {arch} copy mode with randomly selected glibc {pkg.version} (min={min_ver})")

        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        download_glibc(pkg, glibc_dir, mirror=mirror, include_dbg=False)
        glibc = resolve_lib_paths(pkg.version, arch, glibc_dir)

        patched, copied = patch_copy(binary, glibc)

        # Copy mode uses ./ld — run from the binary's directory
        result = subprocess.run(
            [qemu, "-L", str(patched.parent), str(patched)],
            capture_output=True, text=True, timeout=30,
            cwd=str(patched.parent),
        )
        assert result.returncode == 0, (
            f"Patched {arch} copy-mode (glibc {pkg.version}) failed: {result.stderr}"
        )
        assert "pwnlibc-test-ok" in result.stdout


class TestNativeX86PatchAndRun:
    """Test x86 (amd64/i686) with random version selection."""

    @pytest.mark.network
    @pytest.mark.slow
    def test_amd64_inplace_random(self, tmp_path):
        """Download a random amd64 glibc, patch, run natively."""
        if not _has_tool("gcc"):
            pytest.skip("gcc not installed")
        if not _has_tool("patchelf"):
            pytest.skip("patchelf not installed")

        from pwnlibc.downloader import download_glibc, scrape_available
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import patch_inplace

        src = tmp_path / "hello.c"
        src.write_text('#include <stdio.h>\nint main(){puts("pwnlibc-test-ok");return 0;}\n')
        binary = tmp_path / "hello"
        subprocess.run(["gcc", "-o", str(binary), str(src)], check=True, capture_output=True)
        os.chmod(str(binary), 0o755)

        min_ver = _get_min_glibc_version(binary)
        packages = scrape_available("ubuntu")
        pkg = _pick_random_version(packages, "amd64", min_version=min_ver)
        if pkg is None:
            pytest.skip(f"no amd64 packages >= {min_ver}")

        print(f"Testing amd64 with randomly selected glibc {pkg.version} (min={min_ver})")

        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        download_glibc(pkg, glibc_dir, mirror="ubuntu", include_dbg=False)
        glibc = resolve_lib_paths(pkg.version, "amd64", glibc_dir)

        patched = patch_inplace(binary, glibc)

        result = subprocess.run([str(patched)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, f"Failed with glibc {pkg.version}: {result.stderr}"
        assert "pwnlibc-test-ok" in result.stdout

    @pytest.mark.network
    @pytest.mark.slow
    def test_amd64_copy_random(self, tmp_path):
        """Download a random amd64 glibc, patch in copy mode, run."""
        if not _has_tool("gcc"):
            pytest.skip("gcc not installed")
        if not _has_tool("patchelf"):
            pytest.skip("patchelf not installed")

        from pwnlibc.downloader import download_glibc, scrape_available
        from pwnlibc.glibc import resolve_lib_paths
        from pwnlibc.patcher import patch_copy

        workdir = tmp_path / "work"
        workdir.mkdir()
        src = workdir / "hello.c"
        src.write_text('#include <stdio.h>\nint main(){puts("pwnlibc-test-ok");return 0;}\n')
        binary = workdir / "hello"
        subprocess.run(["gcc", "-o", str(binary), str(src)], check=True, capture_output=True)
        os.chmod(str(binary), 0o755)

        min_ver = _get_min_glibc_version(binary)
        packages = scrape_available("ubuntu")
        pkg = _pick_random_version(packages, "amd64", min_version=min_ver)
        if pkg is None:
            pytest.skip(f"no amd64 packages >= {min_ver}")

        print(f"Testing amd64 copy mode with randomly selected glibc {pkg.version} (min={min_ver})")

        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        download_glibc(pkg, glibc_dir, mirror="ubuntu", include_dbg=False)
        glibc = resolve_lib_paths(pkg.version, "amd64", glibc_dir)

        patched, copied = patch_copy(binary, glibc)

        result = subprocess.run(
            [str(patched)], capture_output=True, text=True, timeout=10,
            cwd=str(patched.parent),
        )
        assert result.returncode == 0, f"Failed with glibc {pkg.version}: {result.stderr}"
        assert "pwnlibc-test-ok" in result.stdout
