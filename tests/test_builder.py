"""Tests for source building functionality.

Test points:
- check_build_deps returns correct missing deps per arch
- get_install_cmd generates correct apt install command per arch
- check_source_available validates GNU mirror for known versions
- build_glibc produces correct directory structure (arch-built/)
- At least one build test per architecture (mocked)
- Progress callback invoked with correct phases
- Built variant is distinct from deb variant
"""

from pathlib import Path
from unittest.mock import MagicMock, patch, call
import os
import shutil

import pytest

from pwnlibc.builder import (
    build_glibc,
    check_build_deps,
    check_source_available,
    get_install_cmd,
)
from pwnlibc.config import ALL_ARCHES, ARCH_INFO, BUILD_DEPS, GNU_SOURCE_URL


class TestCheckBuildDeps:
    """check_build_deps detects missing tools per architecture."""

    @patch("shutil.which")
    def test_all_present_amd64(self, mock_which):
        mock_which.return_value = "/usr/bin/fake"
        missing = check_build_deps("amd64")
        assert missing == []

    @patch("shutil.which")
    def test_missing_make(self, mock_which):
        def which_side_effect(name):
            if name == "make":
                return None
            return "/usr/bin/fake"
        mock_which.side_effect = which_side_effect
        missing = check_build_deps("amd64")
        assert "make" in missing

    @patch("shutil.which")
    def test_missing_gcc_for_amd64(self, mock_which):
        def which_side_effect(name):
            if name == "gcc":
                return None
            return "/usr/bin/fake"
        mock_which.side_effect = which_side_effect
        missing = check_build_deps("amd64")
        assert "gcc" in missing

    @patch("shutil.which")
    def test_missing_cross_gcc_arm64(self, mock_which):
        def which_side_effect(name):
            if name == "aarch64-linux-gnu-gcc":
                return None
            return "/usr/bin/fake"
        mock_which.side_effect = which_side_effect
        missing = check_build_deps("arm64")
        assert any("aarch64" in m or "arm64" in m for m in missing)

    @patch("shutil.which")
    def test_missing_cross_gcc_armhf(self, mock_which):
        def which_side_effect(name):
            if name == "arm-linux-gnueabihf-gcc":
                return None
            return "/usr/bin/fake"
        mock_which.side_effect = which_side_effect
        missing = check_build_deps("armhf")
        assert any("arm" in m for m in missing)

    @patch("shutil.which")
    def test_missing_cross_gcc_ppc64el(self, mock_which):
        def which_side_effect(name):
            if name == "powerpc64le-linux-gnu-gcc":
                return None
            return "/usr/bin/fake"
        mock_which.side_effect = which_side_effect
        missing = check_build_deps("ppc64el")
        assert any("powerpc64le" in m for m in missing)

    @patch("shutil.which")
    def test_missing_cross_gcc_s390x(self, mock_which):
        def which_side_effect(name):
            if name == "s390x-linux-gnu-gcc":
                return None
            return "/usr/bin/fake"
        mock_which.side_effect = which_side_effect
        missing = check_build_deps("s390x")
        assert any("s390x" in m for m in missing)

    @patch("shutil.which")
    def test_missing_cross_gcc_riscv64(self, mock_which):
        def which_side_effect(name):
            if name == "riscv64-linux-gnu-gcc":
                return None
            return "/usr/bin/fake"
        mock_which.side_effect = which_side_effect
        missing = check_build_deps("riscv64")
        assert any("riscv64" in m for m in missing)

    @patch("shutil.which")
    def test_missing_cross_gcc_powerpc(self, mock_which):
        def which_side_effect(name):
            if name == "powerpc-linux-gnu-gcc":
                return None
            return "/usr/bin/fake"
        mock_which.side_effect = which_side_effect
        missing = check_build_deps("powerpc")
        assert any("powerpc" in m for m in missing)

    @patch("shutil.which")
    def test_i686_checks_gcc(self, mock_which):
        def which_side_effect(name):
            if name == "gcc":
                return None
            return "/usr/bin/fake"
        mock_which.side_effect = which_side_effect
        missing = check_build_deps("i686")
        assert "gcc" in missing


class TestGetInstallCmd:
    """get_install_cmd generates correct apt install commands."""

    def test_amd64_install_cmd(self):
        cmd = get_install_cmd("amd64")
        assert "sudo apt install" in cmd
        assert "gcc" in cmd
        for dep in BUILD_DEPS:
            assert dep in cmd

    def test_i686_install_cmd(self):
        cmd = get_install_cmd("i686")
        assert "gcc-multilib" in cmd
        assert "gcc" in cmd

    def test_arm64_install_cmd(self):
        cmd = get_install_cmd("arm64")
        assert "gcc-aarch64-linux-gnu" in cmd

    def test_armhf_install_cmd(self):
        cmd = get_install_cmd("armhf")
        assert "gcc-arm-linux-gnueabihf" in cmd

    def test_ppc64el_install_cmd(self):
        cmd = get_install_cmd("ppc64el")
        assert "gcc-powerpc64le-linux-gnu" in cmd

    def test_s390x_install_cmd(self):
        cmd = get_install_cmd("s390x")
        assert "gcc-s390x-linux-gnu" in cmd

    def test_riscv64_install_cmd(self):
        cmd = get_install_cmd("riscv64")
        assert "gcc-riscv64-linux-gnu" in cmd

    def test_powerpc_install_cmd(self):
        cmd = get_install_cmd("powerpc")
        assert "gcc-powerpc-linux-gnu" in cmd

    @pytest.mark.parametrize("arch", ALL_ARCHES)
    def test_all_arches_have_install_cmd(self, arch):
        cmd = get_install_cmd(arch)
        assert cmd.startswith("sudo apt install")
        assert len(cmd.split()) > 3


class TestCheckSourceAvailable:
    """check_source_available verifies GNU mirror availability."""

    @pytest.mark.network
    def test_known_version_available(self):
        assert check_source_available("2.31") is True

    @pytest.mark.network
    def test_known_version_235_available(self):
        assert check_source_available("2.35") is True

    @pytest.mark.network
    def test_nonexistent_version(self):
        assert check_source_available("9.99") is False

    @patch("urllib.request.urlopen")
    def test_mocked_available(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        assert check_source_available("2.31") is True

    @patch("urllib.request.urlopen")
    def test_mocked_unavailable(self, mock_urlopen):
        mock_urlopen.side_effect = Exception("404 Not Found")
        assert check_source_available("9.99") is False


def _make_build_run_side_effect(version):
    """Create a subprocess.run side effect that mocks tar extraction for build_glibc."""
    def run_side_effect(cmd, **kwargs):
        if cmd[0] == "tar":
            # tar uses -C <dir> to specify where to extract
            try:
                c_idx = cmd.index("-C")
                target_dir = Path(cmd[c_idx + 1])
            except (ValueError, IndexError):
                target_dir = Path(kwargs.get("cwd", "."))
                if isinstance(target_dir, str):
                    target_dir = Path(target_dir)
            src_dir = target_dir / f"glibc-{version}"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "configure").write_text("#!/bin/sh\nexit 0\n")
        return MagicMock(returncode=0, stdout="", stderr="")
    return run_side_effect


def _make_mock_urlopen():
    """Create a mock urlopen that returns empty content."""
    mock_resp = MagicMock()
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.headers = {"Content-Length": "0"}
    mock_resp.read = MagicMock(return_value=b"")
    return mock_resp


class TestBuildGlibcStructure:
    """build_glibc creates correct output directory structure.

    These tests mock subprocess/network to verify the flow without
    actually compiling glibc (which takes 10+ minutes).
    """

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_build_amd64_creates_dir(self, mock_urlopen, mock_run, tmp_path):
        """Build for amd64 creates version/amd64-built/ directory."""
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()
        mock_run.side_effect = _make_build_run_side_effect("2.31")

        result = build_glibc("2.31", "amd64", glibc_dir)
        assert result == glibc_dir / "2.31" / "amd64-built"
        assert result.is_dir()

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_build_arm64_creates_dir(self, mock_urlopen, mock_run, tmp_path):
        """Build for arm64 creates version/arm64-built/ directory."""
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()
        mock_run.side_effect = _make_build_run_side_effect("2.35")

        result = build_glibc("2.35", "arm64", glibc_dir)
        assert result == glibc_dir / "2.35" / "arm64-built"
        assert result.is_dir()

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_build_i686_creates_dir(self, mock_urlopen, mock_run, tmp_path):
        """Build for i686 creates version/i686-built/ directory."""
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()
        mock_run.side_effect = _make_build_run_side_effect("2.27")

        result = build_glibc("2.27", "i686", glibc_dir)
        assert result == glibc_dir / "2.27" / "i686-built"
        assert result.is_dir()

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_build_ppc64el_creates_dir(self, mock_urlopen, mock_run, tmp_path):
        """Build for ppc64el creates version/ppc64el-built/ directory."""
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()
        mock_run.side_effect = _make_build_run_side_effect("2.35")

        result = build_glibc("2.35", "ppc64el", glibc_dir)
        assert result == glibc_dir / "2.35" / "ppc64el-built"
        assert result.is_dir()

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_build_s390x_creates_dir(self, mock_urlopen, mock_run, tmp_path):
        """Build for s390x creates version/s390x-built/ directory."""
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()
        mock_run.side_effect = _make_build_run_side_effect("2.35")

        result = build_glibc("2.35", "s390x", glibc_dir)
        assert result == glibc_dir / "2.35" / "s390x-built"
        assert result.is_dir()

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_build_riscv64_creates_dir(self, mock_urlopen, mock_run, tmp_path):
        """Build for riscv64 creates version/riscv64-built/ directory."""
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()
        mock_run.side_effect = _make_build_run_side_effect("2.35")

        result = build_glibc("2.35", "riscv64", glibc_dir)
        assert result == glibc_dir / "2.35" / "riscv64-built"
        assert result.is_dir()

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_build_powerpc_creates_dir(self, mock_urlopen, mock_run, tmp_path):
        """Build for powerpc creates version/powerpc-built/ directory."""
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()
        mock_run.side_effect = _make_build_run_side_effect("2.19")

        result = build_glibc("2.19", "powerpc", glibc_dir)
        assert result == glibc_dir / "2.19" / "powerpc-built"
        assert result.is_dir()

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_build_armhf_creates_dir(self, mock_urlopen, mock_run, tmp_path):
        """Build for armhf creates version/armhf-built/ directory."""
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()
        mock_run.side_effect = _make_build_run_side_effect("2.31")

        result = build_glibc("2.31", "armhf", glibc_dir)
        assert result == glibc_dir / "2.31" / "armhf-built"
        assert result.is_dir()


class TestBuildProgressCallback:
    """Progress callback receives correct phase names."""

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_progress_phases(self, mock_urlopen, mock_run, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()
        mock_run.side_effect = _make_build_run_side_effect("2.31")

        progress_calls = []
        def progress_cb(phase, current, total):
            progress_calls.append(phase)

        build_glibc("2.31", "amd64", glibc_dir, progress_cb=progress_cb)

        assert "downloading source" in progress_calls
        assert "extracting source" in progress_calls
        assert "configuring" in progress_calls
        assert "compiling (this takes a while)" in progress_calls
        assert "installing" in progress_calls


class TestBuildConfigureArgs:
    """Configure is called with correct cross-compile arguments."""

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_amd64_no_host_flag(self, mock_urlopen, mock_run, tmp_path):
        """amd64 build should NOT have --host flag."""
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()

        configure_cmd = None
        base_effect = _make_build_run_side_effect("2.31")

        def run_side_effect(cmd, **kwargs):
            nonlocal configure_cmd
            if "configure" in str(cmd[0]):
                configure_cmd = cmd
            return base_effect(cmd, **kwargs)

        mock_run.side_effect = run_side_effect

        build_glibc("2.31", "amd64", glibc_dir)
        assert configure_cmd is not None
        assert not any("--host" in arg for arg in configure_cmd)

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_arm64_has_host_flag(self, mock_urlopen, mock_run, tmp_path):
        """arm64 cross-build should have --host=aarch64-linux-gnu."""
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()

        configure_cmd = None
        configure_env = None
        base_effect = _make_build_run_side_effect("2.35")

        def run_side_effect(cmd, **kwargs):
            nonlocal configure_cmd, configure_env
            if "configure" in str(cmd[0]):
                configure_cmd = cmd
                configure_env = kwargs.get("env", {})
            return base_effect(cmd, **kwargs)

        mock_run.side_effect = run_side_effect

        build_glibc("2.35", "arm64", glibc_dir)
        assert configure_cmd is not None
        assert "--host=aarch64-linux-gnu" in configure_cmd
        assert configure_env.get("CC") == "aarch64-linux-gnu-gcc"

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_i686_has_m32_flag(self, mock_urlopen, mock_run, tmp_path):
        """i686 build should set CC='gcc -m32'."""
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()

        configure_env = None
        base_effect = _make_build_run_side_effect("2.27")

        def run_side_effect(cmd, **kwargs):
            nonlocal configure_env
            if "configure" in str(cmd[0]):
                configure_env = kwargs.get("env", {})
            return base_effect(cmd, **kwargs)

        mock_run.side_effect = run_side_effect

        build_glibc("2.27", "i686", glibc_dir)
        assert configure_env is not None
        assert configure_env.get("CC") == "gcc -m32"


class TestBuildFailure:
    """Build failures raise RuntimeError with useful messages."""

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_configure_failure(self, mock_urlopen, mock_run, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()
        base_effect = _make_build_run_side_effect("2.31")

        def run_side_effect(cmd, **kwargs):
            if "configure" in str(cmd[0]):
                return MagicMock(returncode=1, stdout="", stderr="configure: error: something broke")
            return base_effect(cmd, **kwargs)

        mock_run.side_effect = run_side_effect

        with pytest.raises(RuntimeError, match="configure failed"):
            build_glibc("2.31", "amd64", glibc_dir)

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_make_failure(self, mock_urlopen, mock_run, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_urlopen.return_value = _make_mock_urlopen()
        base_effect = _make_build_run_side_effect("2.31")

        def run_side_effect(cmd, **kwargs):
            if cmd[0] == "make" and "install" not in cmd:
                return MagicMock(returncode=1, stdout="", stderr="make: *** Error 2")
            return base_effect(cmd, **kwargs)

        mock_run.side_effect = run_side_effect

        with pytest.raises(RuntimeError, match="make failed"):
            build_glibc("2.31", "amd64", glibc_dir)


class TestBuildOverwrite:
    """build_glibc removes existing built dir before building."""

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_overwrites_existing(self, mock_urlopen, mock_run, tmp_path):
        glibc_dir = tmp_path / "glibc"
        built_dir = glibc_dir / "2.31" / "amd64-built"
        built_dir.mkdir(parents=True)
        (built_dir / "old_artifact").write_text("old")

        mock_urlopen.return_value = _make_mock_urlopen()
        mock_run.side_effect = _make_build_run_side_effect("2.31")

        build_glibc("2.31", "amd64", glibc_dir)
        assert not (built_dir / "old_artifact").exists()


class TestGNUSourceURL:
    """GNU_SOURCE_URL formats correctly for all tested versions."""

    @pytest.mark.parametrize("version", ["2.19", "2.23", "2.27", "2.31", "2.35", "2.39"])
    def test_url_format(self, version):
        url = GNU_SOURCE_URL.format(version=version)
        assert version in url
        assert url.startswith("https://ftp.gnu.org/gnu/glibc/")
        assert url.endswith(".tar.xz")


class TestLiveBuild:
    """Integration tests — actually check source availability per arch.

    These don't compile (too slow) but verify the GNU mirror has the tarballs.
    """

    @pytest.mark.network
    @pytest.mark.parametrize("version", ["2.23", "2.27", "2.31", "2.35"])
    def test_source_exists_on_gnu(self, version):
        """Key versions should be available on ftp.gnu.org."""
        assert check_source_available(version) is True

    @pytest.mark.network
    def test_old_version_219_available(self):
        assert check_source_available("2.19") is True

    @pytest.mark.network
    def test_very_old_version_unavailable(self):
        """Versions before ~2.3 are typically not on the mirror."""
        assert check_source_available("1.0") is False
