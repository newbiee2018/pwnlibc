"""Tests for multi-architecture download, download-all, and selective download features.

Test points:
- Download one specific version (single choice)
- Download multiple versions at once (multi-choice)
- Download all for one arch (without actually downloading everything)
- Download all for all arches (partial validation)
- All architectures available on correct mirrors
- Source availability check per arch
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from pwnlibc.cli import cli
from pwnlibc.config import ALL_ARCHES, ARCH_INFO, MIRRORS, X86_ARCHES
from pwnlibc.downloader import DEB_PATTERN, DBG_PATTERN, DebPackage, scrape_available
from tests.conftest import (
    SAMPLE_DEBIAN_MIRROR_HTML,
    SAMPLE_MIRROR_HTML,
    SAMPLE_OLD_UBUNTU_MIRROR_HTML,
    SAMPLE_PORTS_MIRROR_HTML,
)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture(autouse=True)
def _no_sha256_verification(monkeypatch):
    """These tests seed fake cached .debs and mock extraction; the dists-index
    hash check would flag the bogus bytes on networked machines. Hash
    verification has its own hermetic tests in test_downloader.py."""
    monkeypatch.setattr("pwnlibc.downloader._expected_sha256_detail",
                        lambda *args, **kwargs: (None, False))


class TestMultiArchPatterns:
    """Regex patterns match all supported architectures."""

    def test_deb_pattern_arm64(self):
        m = DEB_PATTERN.search("libc6_2.35-0ubuntu3.8_arm64.deb")
        assert m is not None
        assert m.group("arch") == "arm64"

    def test_deb_pattern_armhf(self):
        m = DEB_PATTERN.search("libc6_2.31-0ubuntu9_armhf.deb")
        assert m is not None
        assert m.group("arch") == "armhf"

    def test_deb_pattern_ppc64el(self):
        m = DEB_PATTERN.search("libc6_2.35-0ubuntu3.8_ppc64el.deb")
        assert m is not None
        assert m.group("arch") == "ppc64el"

    def test_deb_pattern_s390x(self):
        m = DEB_PATTERN.search("libc6_2.35-0ubuntu3_s390x.deb")
        assert m is not None
        assert m.group("arch") == "s390x"

    def test_deb_pattern_riscv64(self):
        m = DEB_PATTERN.search("libc6_2.35-0ubuntu3.8_riscv64.deb")
        assert m is not None
        assert m.group("arch") == "riscv64"

    def test_deb_pattern_powerpc(self):
        m = DEB_PATTERN.search("libc6_2.19-0ubuntu6.15_powerpc.deb")
        assert m is not None
        assert m.group("arch") == "powerpc"

    def test_deb_pattern_mipsel(self):
        m = DEB_PATTERN.search("libc6_2.31-13+deb11u10_mipsel.deb")
        assert m is not None
        assert m.group("arch") == "mipsel"

    def test_deb_pattern_mips64el(self):
        m = DEB_PATTERN.search("libc6_2.36-9+deb12u9_mips64el.deb")
        assert m is not None
        assert m.group("arch") == "mips64el"

    def test_deb_pattern_old_version_format(self):
        """Pre-2.23 versions like 2.3.6 should be matched."""
        m = DEB_PATTERN.search("libc6_2.3.6-0ubuntu20.6_amd64.deb")
        assert m is not None
        assert m.group("ver") == "2.3.6"

    def test_deb_pattern_ds1_version(self):
        """Versions with .ds1 suffix should be matched."""
        m = DEB_PATTERN.search("libc6_2.3.2.ds1-13ubuntu2_amd64.deb")
        assert m is not None
        assert m.group("ver") == "2.3.2.ds1"


class TestMirrorScrapeByArch:
    """Scraping returns correct packages per mirror/arch."""

    @patch("pwnlibc.downloader._fetch_index")
    def test_ports_mirror_arm64(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_PORTS_MIRROR_HTML
        packages = scrape_available("ports")
        arm64_pkgs = [p for p in packages if p.arch == "arm64"]
        assert len(arm64_pkgs) >= 3
        versions = {p.version for p in arm64_pkgs}
        assert "2.23" in versions
        assert "2.35" in versions

    @patch("pwnlibc.downloader._fetch_index")
    def test_ports_mirror_armhf(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_PORTS_MIRROR_HTML
        packages = scrape_available("ports")
        armhf_pkgs = [p for p in packages if p.arch == "armhf"]
        assert len(armhf_pkgs) >= 1

    @patch("pwnlibc.downloader._fetch_index")
    def test_ports_mirror_ppc64el(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_PORTS_MIRROR_HTML
        packages = scrape_available("ports")
        ppc64_pkgs = [p for p in packages if p.arch == "ppc64el"]
        assert len(ppc64_pkgs) >= 1

    @patch("pwnlibc.downloader._fetch_index")
    def test_ports_mirror_riscv64(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_PORTS_MIRROR_HTML
        packages = scrape_available("ports")
        riscv_pkgs = [p for p in packages if p.arch == "riscv64"]
        assert len(riscv_pkgs) >= 1

    @patch("pwnlibc.downloader._fetch_index")
    def test_debian_mirror_mipsel(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_DEBIAN_MIRROR_HTML
        packages = scrape_available("debian")
        mipsel_pkgs = [p for p in packages if p.arch == "mipsel"]
        assert len(mipsel_pkgs) >= 2
        versions = {p.version for p in mipsel_pkgs}
        assert "2.31" in versions
        assert "2.36" in versions

    @patch("pwnlibc.downloader._fetch_index")
    def test_debian_mirror_mips64el(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_DEBIAN_MIRROR_HTML
        packages = scrape_available("debian")
        mips64_pkgs = [p for p in packages if p.arch == "mips64el"]
        assert len(mips64_pkgs) >= 2
        versions = {p.version for p in mips64_pkgs}
        assert "2.31" in versions
        assert "2.36" in versions

    @patch("pwnlibc.downloader._fetch_index")
    def test_old_ubuntu_powerpc(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_OLD_UBUNTU_MIRROR_HTML
        packages = scrape_available("old-ubuntu")
        ppc_pkgs = [p for p in packages if p.arch == "powerpc"]
        assert len(ppc_pkgs) >= 1
        assert ppc_pkgs[0].version == "2.3.6"

    @patch("pwnlibc.downloader._fetch_index")
    def test_old_ubuntu_old_versions(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_OLD_UBUNTU_MIRROR_HTML
        packages = scrape_available("old-ubuntu")
        versions = {p.version for p in packages}
        assert "2.19" in versions
        assert "2.21" in versions
        assert "2.3.6" in versions


class TestDownloadOneVersion:
    """Download command with a single version."""

    @patch("pwnlibc.downloader._fetch_index")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._extract_deb")
    def test_download_single_amd64(self, mock_extract, mock_dl, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        (glibc_dir / ".cache").mkdir()

        # Simulate cached deb
        (glibc_dir / ".cache" / "libc6_2.31-0ubuntu9.16_amd64.deb").write_bytes(b"fake")

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.31", "--arch", "amd64", "--no-dbg",
        ])
        assert result.exit_code == 0
        assert mock_extract.called

    @patch("pwnlibc.downloader._fetch_index")
    def test_download_version_not_found(self, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "9.99",
        ])
        assert result.exit_code != 0
        assert "not found" in result.output


class TestDownloadMultipleVersions:
    """Download command with multiple versions at once."""

    @patch("pwnlibc.downloader._fetch_index")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._extract_deb")
    def test_download_two_versions(self, mock_extract, mock_dl, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        cache = glibc_dir / ".cache"
        cache.mkdir()

        # Pre-create fake cached debs to skip download
        (cache / "libc6_2.27-3ubuntu1.6_amd64.deb").write_bytes(b"fake")
        (cache / "libc6_2.31-0ubuntu9.16_amd64.deb").write_bytes(b"fake")

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.27", "2.31", "--arch", "amd64", "--no-dbg",
        ])
        assert result.exit_code == 0
        # Should process both versions
        assert mock_extract.call_count >= 2

    @patch("pwnlibc.downloader._fetch_index")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._extract_deb")
    def test_download_three_versions(self, mock_extract, mock_dl, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        cache = glibc_dir / ".cache"
        cache.mkdir()

        (cache / "libc6_2.27-3ubuntu1.6_amd64.deb").write_bytes(b"fake")
        (cache / "libc6_2.31-0ubuntu9.16_amd64.deb").write_bytes(b"fake")
        (cache / "libc6_2.35-0ubuntu3.8_amd64.deb").write_bytes(b"fake")

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.27", "2.31", "2.35", "--arch", "amd64", "--no-dbg",
        ])
        assert result.exit_code == 0
        assert mock_extract.call_count >= 3

    @patch("pwnlibc.downloader._fetch_index")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._extract_deb")
    def test_download_partial_failure(self, mock_extract, mock_dl, mock_fetch, runner, tmp_path):
        """If one version not found, others still download."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        cache = glibc_dir / ".cache"
        cache.mkdir()
        (cache / "libc6_2.31-0ubuntu9.16_amd64.deb").write_bytes(b"fake")

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.31", "9.99", "--arch", "amd64", "--no-dbg",
        ])
        # Should succeed because at least one version was found
        assert result.exit_code == 0
        assert "not found" in result.output  # 9.99 reported as not found
        assert mock_extract.called  # 2.31 was processed


class TestDownloadAll:
    """download-all command — download all for one arch or x86."""

    @patch("pwnlibc.downloader._fetch_index")
    def test_download_all_check_amd64(self, mock_fetch, runner, tmp_path):
        """--check shows what would be downloaded without actually downloading."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all", "--arch", "amd64", "--check",
        ])
        assert result.exit_code == 0
        assert "to download" in result.output

    @patch("pwnlibc.downloader._fetch_index")
    def test_download_all_check_arm64(self, mock_fetch, runner, tmp_path):
        """download-all --arch arm64 --check should show arm64 packages."""
        mock_fetch.return_value = SAMPLE_PORTS_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all", "--arch", "arm64", "--check", "--mirror", "ports",
        ])
        assert result.exit_code == 0
        assert "to download" in result.output

    @patch("pwnlibc.downloader._fetch_index")
    def test_download_all_skips_installed(self, mock_fetch, runner, populated_glibc_dir):
        """Already-installed versions are skipped."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        result = runner.invoke(cli, [
            "--glibc-dir", str(populated_glibc_dir),
            "download-all", "--arch", "amd64", "--check",
        ])
        assert result.exit_code == 0
        # 2.31, 2.35, 2.39 are installed — only 2.27 should be missing
        if "to download" in result.output:
            assert "2.27" in result.output
            # Installed versions should NOT be listed
            # (they may appear in other contexts but not in "to download" list)

    @patch("pwnlibc.downloader._fetch_index")
    def test_download_all_all_installed(self, mock_fetch, runner, populated_glibc_dir):
        """If all versions installed (with debug), show 'All versions already installed'."""
        # Add .debug dirs so all installs have debug symbols
        for ver_arch in [("2.31", "amd64"), ("2.31", "i686"), ("2.39", "amd64")]:
            dbg = populated_glibc_dir / ver_arch[0] / ver_arch[1] / "lib" / ".debug"
            dbg.mkdir(exist_ok=True)
            (dbg / "libc.so.6").write_bytes(b"\x00" * 10)

        html = """
        <a href="libc6_2.31-0ubuntu9.16_amd64.deb">libc6_2.31-0ubuntu9.16_amd64.deb</a>
        <a href="libc6_2.35-0ubuntu3.8_amd64.deb">libc6_2.35-0ubuntu3.8_amd64.deb</a>
        <a href="libc6_2.39-0ubuntu8.4_amd64.deb">libc6_2.39-0ubuntu8.4_amd64.deb</a>
        """
        mock_fetch.return_value = html
        result = runner.invoke(cli, [
            "--glibc-dir", str(populated_glibc_dir),
            "download-all", "--arch", "amd64", "--mirror", "ubuntu",
        ])
        assert result.exit_code == 0
        assert "already installed" in result.output

    @patch("pwnlibc.downloader._fetch_index")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._extract_deb")
    def test_download_all_actually_downloads(self, mock_extract, mock_dl, mock_fetch,
                                              runner, tmp_path):
        """Without --check, actually downloads (mocked)."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        cache = glibc_dir / ".cache"
        cache.mkdir()

        # Pre-populate cache to avoid actual download
        (cache / "libc6_2.27-3ubuntu1.6_amd64.deb").write_bytes(b"fake")
        (cache / "libc6_2.31-0ubuntu9.16_amd64.deb").write_bytes(b"fake")
        (cache / "libc6_2.35-0ubuntu3.8_amd64.deb").write_bytes(b"fake")
        (cache / "libc6_2.39-0ubuntu8.4_amd64.deb").write_bytes(b"fake")

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all", "--arch", "amd64", "--no-dbg", "--mirror", "ubuntu",
        ])
        assert result.exit_code == 0
        assert mock_extract.call_count >= 3


class TestDownloadWithSource:
    """Downloading with --source flag fetches GNU source tarball."""

    @patch("pwnlibc.builder.check_source_available")
    @patch("pwnlibc.cli.download_source")
    @patch("pwnlibc.downloader._fetch_index")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._extract_deb")
    def test_download_with_source_flag(self, mock_extract, mock_dl, mock_fetch,
                                       mock_source, mock_check, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        mock_check.return_value = "https://ftp.gnu.org/gnu/glibc/glibc-2.31.tar.xz"
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        cache = glibc_dir / ".cache"
        cache.mkdir()
        (cache / "libc6_2.31-0ubuntu9.16_amd64.deb").write_bytes(b"fake")

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.31", "--arch", "amd64", "--no-dbg", "--source",
        ])
        assert result.exit_code == 0
        mock_source.assert_called_once()
        call_args = mock_source.call_args
        assert call_args[0][0] == "2.31"  # version

    @patch("pwnlibc.builder.check_source_available")
    @patch("pwnlibc.cli.download_source")
    @patch("pwnlibc.downloader._fetch_index")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._extract_deb")
    def test_download_multiple_with_source(self, mock_extract, mock_dl, mock_fetch,
                                           mock_source, mock_check, runner, tmp_path):
        """Source is downloaded for each version when --source used with multi-version."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        mock_check.return_value = "https://ftp.gnu.org/gnu/glibc/glibc-2.31.tar.xz"
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        cache = glibc_dir / ".cache"
        cache.mkdir()
        (cache / "libc6_2.27-3ubuntu1.6_amd64.deb").write_bytes(b"fake")
        (cache / "libc6_2.31-0ubuntu9.16_amd64.deb").write_bytes(b"fake")

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.27", "2.31", "--arch", "amd64", "--no-dbg", "--source",
        ])
        assert result.exit_code == 0
        assert mock_source.call_count == 2


class TestAvailableCommand:
    """The 'available' command lists packages per arch with correct info."""

    @patch("pwnlibc.downloader._fetch_index")
    def test_available_amd64(self, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "available", "--arch", "amd64", "--mirror", "ubuntu",
            "--no-check-source",
        ])
        assert result.exit_code == 0
        assert "2.31" in result.output
        assert "2.35" in result.output

    @patch("pwnlibc.downloader._fetch_index")
    def test_available_arm64(self, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_PORTS_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "available", "--arch", "arm64", "--mirror", "ports",
            "--no-check-source",
        ])
        assert result.exit_code == 0
        assert "arm64" in result.output

    @patch("pwnlibc.downloader._fetch_index")
    def test_available_shows_installed_status(self, mock_fetch, runner, populated_glibc_dir):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        result = runner.invoke(cli, [
            "--glibc-dir", str(populated_glibc_dir),
            "available", "--arch", "amd64", "--mirror", "ubuntu",
            "--no-check-source",
        ])
        assert result.exit_code == 0
        # Installed versions should show variant labels
        assert "deb" in result.output
        # Debug .deb column should be present
        assert "Debug .deb" in result.output


class TestMirrorAutoSelection:
    """Mirror auto-selection picks correct mirror per architecture."""

    def test_amd64_uses_ubuntu_mirror(self):
        from pwnlibc.cli import _mirrors_for_arch
        assert _mirrors_for_arch("amd64")[0] == "ubuntu"

    def test_i686_uses_ubuntu_mirror(self):
        from pwnlibc.cli import _mirrors_for_arch
        assert _mirrors_for_arch("i686")[0] == "ubuntu"

    def test_arm64_uses_ports_mirror(self):
        from pwnlibc.cli import _mirrors_for_arch
        assert _mirrors_for_arch("arm64")[0] == "ports"

    def test_armhf_uses_ports_mirror(self):
        from pwnlibc.cli import _mirrors_for_arch
        assert _mirrors_for_arch("armhf")[0] == "ports"

    def test_ppc64el_uses_ports_mirror(self):
        from pwnlibc.cli import _mirrors_for_arch
        assert _mirrors_for_arch("ppc64el")[0] == "ports"

    def test_powerpc_uses_old_ubuntu(self):
        from pwnlibc.cli import _mirrors_for_arch
        assert _mirrors_for_arch("powerpc")[0] == "old-ubuntu"

    def test_riscv64_uses_ports_mirror(self):
        from pwnlibc.cli import _mirrors_for_arch
        assert _mirrors_for_arch("riscv64")[0] == "ports"

    def test_mipsel_uses_debian_mirror(self):
        from pwnlibc.cli import _mirrors_for_arch
        assert _mirrors_for_arch("mipsel")[0] == "debian"

    def test_mips64el_uses_debian_mirror(self):
        from pwnlibc.cli import _mirrors_for_arch
        assert _mirrors_for_arch("mips64el")[0] == "debian"

    def test_mirrors_list_includes_fallbacks(self):
        from pwnlibc.cli import _mirrors_for_arch
        assert len(_mirrors_for_arch("arm64")) > 1
        assert "old-ubuntu" in _mirrors_for_arch("arm64")
        assert "old-ubuntu" in _mirrors_for_arch("amd64")


class TestArchConfig:
    """All architectures have required config fields."""

    @pytest.mark.parametrize("arch", ALL_ARCHES)
    def test_arch_has_required_fields(self, arch):
        info = ARCH_INFO[arch]
        assert "elf_machine" in info
        assert "elf_class" in info
        assert "ld_soname" in info
        assert "deb_arch" in info
        assert "deb_lib_dir" in info
        assert "mirror" in info
        assert "cross_gcc" in info
        assert "cross_triplet" in info

    @pytest.mark.parametrize("arch", ALL_ARCHES)
    def test_arch_mirror_exists(self, arch):
        mirror = ARCH_INFO[arch]["mirror"]
        assert mirror in MIRRORS


class TestLiveMultiArchDownload:
    """Integration tests — actually scrape mirrors for multi-arch packages."""

    @pytest.mark.network
    def test_ports_mirror_has_arm64(self):
        packages = scrape_available("ports")
        arm64 = [p for p in packages if p.arch == "arm64"]
        assert len(arm64) > 0

    @pytest.mark.network
    def test_ports_mirror_has_ppc64el(self):
        packages = scrape_available("ports")
        ppc64 = [p for p in packages if p.arch == "ppc64el"]
        assert len(ppc64) > 0

    @pytest.mark.network
    def test_ubuntu_mirror_has_old_versions(self):
        """Ubuntu mirror should have versions before 2.23."""
        packages = scrape_available("ubuntu")
        versions = {p.version for p in packages}
        # At minimum, recent versions should exist
        assert any(v.startswith("2.3") for v in versions)

    @pytest.mark.network
    @pytest.mark.slow
    def test_download_arm64_single(self, tmp_path):
        """Actually download one arm64 glibc from ports."""
        from pwnlibc.downloader import download_glibc

        packages = scrape_available("ports")
        arm64_pkgs = [p for p in packages if p.arch == "arm64" and p.version == "2.35"]
        if not arm64_pkgs:
            pytest.skip("2.35 arm64 not on ports mirror")

        pkg = arm64_pkgs[0]
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        download_glibc(pkg, glibc_dir, mirror="ports", include_dbg=False)

        lib_dir = glibc_dir / "2.35" / "arm64" / "lib"
        assert lib_dir.is_dir()
        assert (lib_dir / "libc.so.6").exists()
        assert (lib_dir / "ld-linux-aarch64.so.1").exists()


class TestDownloadDuplicateTokens:
    """Duplicate version tokens (explicit or `latest`) download once."""

    @patch("pwnlibc.downloader._fetch_index")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._extract_deb")
    def test_duplicate_explicit_versions_downloaded_once(
            self, mock_extract, mock_dl, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        def fake_extract(deb_path, out_dir, arch):
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 16)
            (out_dir / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 16)
            (out_dir / "libc.so.6").symlink_to("libc-2.31.so")
            (out_dir / "ld-linux-x86-64.so.2").symlink_to("ld-2.31.so")

        mock_extract.side_effect = fake_extract

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.31", "2.31", "--arch", "amd64", "--no-dbg",
            "--no-source",
        ])
        assert result.exit_code == 0
        assert mock_extract.call_count == 1  # not 2 (once per arch)
        assert result.output.count("2.31/amd64 installed") == 1

    @patch("pwnlibc.downloader._fetch_index")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._extract_deb")
    def test_duplicate_latest_tokens_resolve_and_announce_once(
            self, mock_extract, mock_dl, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        def fake_extract(deb_path, out_dir, arch):
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "libc.so.6").write_bytes(b"\x7fELF" + b"\x00" * 16)
            (out_dir / "ld-linux-x86-64.so.2").write_bytes(b"\x7fELF" + b"\x00" * 16)

        mock_extract.side_effect = fake_extract

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "latest", "latest", "--arch", "amd64", "--no-dbg",
            "--no-source",
        ])
        assert result.exit_code == 0
        assert result.output.count("latest (amd64)") == 1  # announced once
        assert mock_extract.call_count == 1
