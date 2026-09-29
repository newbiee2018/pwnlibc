"""Tests for pwnlibc.downloader — mirror scraping, download, extraction, verification."""

import hashlib
import os
import re
import subprocess
import tempfile
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pwnlibc.config import MIRRORS
from pwnlibc.downloader import (
    DEB_PATTERN,
    DBG_PATTERN,
    DebPackage,
    _download_file,
    _extract_deb,
    _extract_dbg_deb,
    _fetch_index,
    download_source,
    scrape_available,
    sha256_file,
    verify_against_deb,
)
from tests.conftest import SAMPLE_MIRROR_HTML, SAMPLE_OLD_UBUNTU_MIRROR_HTML


class TestDebPatterns:
    def test_deb_pattern_amd64(self):
        m = DEB_PATTERN.search("libc6_2.31-0ubuntu9.16_amd64.deb")
        assert m is not None
        assert m.group("ver") == "2.31"
        assert m.group("arch") == "amd64"

    def test_deb_pattern_i386(self):
        m = DEB_PATTERN.search("libc6_2.27-3ubuntu1.6_i386.deb")
        assert m is not None
        assert m.group("ver") == "2.27"
        assert m.group("arch") == "i386"

    def test_dbg_pattern(self):
        m = DBG_PATTERN.search("libc6-dbg_2.35-0ubuntu3.8_amd64.deb")
        assert m is not None
        assert m.group("ver") == "2.35"

    def test_deb_pattern_no_match(self):
        assert DEB_PATTERN.search("libfoo_1.0_amd64.deb") is None

    def test_deb_pattern_in_html(self):
        matches = list(DEB_PATTERN.finditer(SAMPLE_MIRROR_HTML))
        assert len(matches) >= 4


class TestScrapeAvailableMocked:
    @patch("pwnlibc.downloader._fetch_index")
    def test_parses_packages(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        packages = scrape_available("ubuntu")

        versions = {p.version for p in packages}
        assert "2.27" in versions
        assert "2.31" in versions
        assert "2.35" in versions
        assert "2.39" in versions

    @patch("pwnlibc.downloader._fetch_index")
    def test_arch_mapping(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        packages = scrape_available("ubuntu")

        archs = {p.arch for p in packages}
        assert "amd64" in archs
        assert "i686" in archs
        assert "i386" not in archs

    @patch("pwnlibc.downloader._fetch_index")
    def test_dbg_pairing(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        packages = scrape_available("ubuntu")

        v231_amd64 = [p for p in packages if p.version == "2.31" and p.arch == "amd64"]
        assert len(v231_amd64) >= 1
        assert v231_amd64[0].dbg_filename is not None
        assert "dbg" in v231_amd64[0].dbg_filename

    @patch("pwnlibc.downloader._fetch_index")
    def test_version_without_dbg(self, mock_fetch):
        html = '<a href="libc6_2.17-0ubuntu5_amd64.deb">libc6_2.17-0ubuntu5_amd64.deb</a>'
        mock_fetch.return_value = html
        packages = scrape_available("ubuntu")
        assert len(packages) == 1
        assert packages[0].dbg_filename is None

    @patch("pwnlibc.downloader._fetch_index")
    def test_empty_html(self, mock_fetch):
        mock_fetch.return_value = "<html></html>"
        packages = scrape_available("ubuntu")
        assert packages == []


class TestScrapeAvailableLive:
    @pytest.mark.network
    def test_ubuntu_mirror_reachable(self):
        """Integration: actually scrape the Ubuntu mirror."""
        packages = scrape_available("ubuntu")
        assert len(packages) > 0
        versions = {p.version for p in packages}
        # These versions should always exist on the Ubuntu mirror
        assert "2.35" in versions or "2.31" in versions or len(versions) > 5


class TestDebPackageMirror:
    """The mirror field must survive scrape → pick → download."""

    def test_mirror_default(self):
        pkg = DebPackage(
            version="2.31",
            full_id="2.31-0ubuntu9_amd64",
            arch="amd64",
            filename="libc6_2.31-0ubuntu9_amd64.deb",
            dbg_filename=None,
        )
        assert pkg.mirror == "ubuntu"

    @patch("pwnlibc.downloader._fetch_index")
    def test_scrape_records_mirror(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_OLD_UBUNTU_MIRROR_HTML
        packages = scrape_available("old-ubuntu")
        assert packages
        assert all(p.mirror == "old-ubuntu" for p in packages)

    @patch("pwnlibc.downloader._fetch_index")
    def test_scrape_records_explicit_mirror(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        packages = scrape_available("ubuntu")
        assert packages
        assert all(p.mirror == "ubuntu" for p in packages)


class _FakeResponse:
    """urlopen() response yielding fixed chunks, then b'' or an exception."""

    def __init__(self, chunks, final_exc=None):
        self.headers = {"Content-Length": "100"}
        self._chunks = list(chunks)
        self._final_exc = final_exc

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, n=-1):
        if self._chunks:
            return self._chunks.pop(0)
        if self._final_exc is not None:
            raise self._final_exc
        return b""


class TestDownloadFileAtomic:
    """Interrupted downloads must not leave truncated files in the cache."""

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_success_replaces_dest(self, mock_urlopen, tmp_path):
        mock_urlopen.return_value = _FakeResponse([b"ab", b"cd"])
        dest = tmp_path / "libc6_2.31-0ubuntu9.16_amd64.deb"
        seen = []
        _download_file("http://example.com/x.deb", dest,
                       progress_cb=lambda d, t: seen.append((d, t)))
        assert dest.read_bytes() == b"abcd"
        assert not dest.with_name(dest.name + ".part").exists()
        assert seen == [(2, 100), (4, 100)]

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_interrupt_mid_download_leaves_no_partial(self, mock_urlopen, tmp_path):
        """Ctrl-C after partial writes: neither dest nor .part remains."""
        mock_urlopen.return_value = _FakeResponse([b"ab", b"cd"], final_exc=KeyboardInterrupt())
        dest = tmp_path / "libc6_2.31-0ubuntu9.16_amd64.deb"
        with pytest.raises(KeyboardInterrupt):
            _download_file("http://example.com/x.deb", dest)
        assert not dest.exists()
        assert not dest.with_name(dest.name + ".part").exists()

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_http_error_leaves_no_partial(self, mock_urlopen, tmp_path):
        mock_urlopen.side_effect = urllib.error.URLError("boom")
        dest = tmp_path / "libc6_2.31-0ubuntu9.16_amd64.deb"
        with pytest.raises(urllib.error.URLError):
            _download_file("http://example.com/x.deb", dest)
        assert not dest.exists()
        assert not dest.with_name(dest.name + ".part").exists()

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_existing_dest_not_clobbered_on_failure(self, mock_urlopen, tmp_path):
        """A failed re-download must not corrupt an already cached file."""
        dest = tmp_path / "libc6_2.31-0ubuntu9.16_amd64.deb"
        dest.write_bytes(b"good")
        mock_urlopen.return_value = _FakeResponse([b"bad"], final_exc=RuntimeError("reset"))
        with pytest.raises(RuntimeError):
            _download_file("http://example.com/x.deb", dest)
        assert dest.read_bytes() == b"good"
        assert not dest.with_name(dest.name + ".part").exists()


class TestDownloadSourceUrl:
    """download_source(url=...) must skip its internal availability check."""

    URL = "https://ftp.gnu.org/gnu/glibc/glibc-2.31.tar.xz"

    @patch("pwnlibc.builder.check_source_available")
    @patch("pwnlibc.downloader.subprocess.run")
    @patch("pwnlibc.downloader._download_file")
    def test_url_passthrough_skips_check(self, mock_dl, mock_run, mock_check, tmp_path):
        download_source("2.31", tmp_path, url=self.URL)
        mock_check.assert_not_called()
        mock_dl.assert_called_once()
        assert mock_dl.call_args[0][0] == self.URL
        assert mock_run.call_args[0][0][:2] == ["tar", "xf"]
        assert (tmp_path / "2.31" / "source").is_dir()

    @patch("pwnlibc.downloader.subprocess.run")
    @patch("pwnlibc.downloader._download_file")
    def test_url_used_for_tarball_name(self, mock_dl, mock_run, tmp_path):
        download_source("2.31", tmp_path, url=self.URL)
        tarball = mock_run.call_args[0][0][2]
        assert Path(tarball).name == "glibc-2.31.tar.xz"

    @patch("pwnlibc.builder.check_source_available", return_value=None)
    def test_no_url_does_internal_check(self, mock_check, tmp_path):
        with pytest.raises(RuntimeError, match="not available"):
            download_source("2.31", tmp_path)
        mock_check.assert_called_once_with("2.31")


class TestVerifyAgainstDebMirror:
    """verify_against_deb defaults to pkg.mirror so EOL .debs resolve."""

    def _pkg(self):
        return DebPackage(
            version="2.19",
            full_id="2.19-0ubuntu6.15_amd64",
            arch="amd64",
            filename="libc6_2.19-0ubuntu6.15_amd64.deb",
            dbg_filename=None,
            mirror="old-ubuntu",
        )

    @staticmethod
    def _install(glibc_dir):
        lib = glibc_dir / "2.19" / "amd64" / "lib"
        lib.mkdir(parents=True, exist_ok=True)
        (lib / "libc.so.6").write_bytes(b"contents")

    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._download_file")
    def test_defaults_to_pkg_mirror(self, mock_dl, mock_extract, tmp_path):
        glibc_dir = tmp_path / "glibc"
        self._install(glibc_dir)

        def fake_extract(deb_path, out_dir, arch):
            (out_dir / "libc.so.6").write_bytes(b"contents")
        mock_extract.side_effect = fake_extract

        results = verify_against_deb(self._pkg(), glibc_dir)
        mock_dl.assert_called_once()
        assert mock_dl.call_args[0][0] == MIRRORS["old-ubuntu"] + "libc6_2.19-0ubuntu6.15_amd64.deb"
        assert any(status == "MATCH" for _, status, _ in results)

    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._download_file")
    def test_explicit_mirror_still_wins(self, mock_dl, mock_extract, tmp_path):
        glibc_dir = tmp_path / "glibc"
        self._install(glibc_dir)
        mock_extract.side_effect = lambda p, out, a: None

        verify_against_deb(self._pkg(), glibc_dir, mirror="ubuntu")
        mock_dl.assert_called_once()
        assert mock_dl.call_args[0][0].startswith(MIRRORS["ubuntu"])


class TestSha256File:
    def test_known_hash(self, tmp_path):
        f = tmp_path / "testfile"
        f.write_bytes(b"hello world\n")
        expected = hashlib.sha256(b"hello world\n").hexdigest()
        assert sha256_file(f) == expected

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty"
        f.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert sha256_file(f) == expected


class TestExtractDeb:
    def _make_fake_deb(self, tmp_path, arch="amd64", use_zst=False):
        """Create a minimal .deb (ar archive containing data.tar.gz)."""
        from pwnlibc.config import ARCH_INFO

        deb_lib_dir = ARCH_INFO[arch]["deb_lib_dir"]

        # Create the data tree
        data_root = tmp_path / "data_build"
        lib_dir = data_root / "lib" / deb_lib_dir
        lib_dir.mkdir(parents=True)
        (lib_dir / "libc.so.6").write_bytes(b"\x7fELF-fake-libc")
        (lib_dir / "ld-linux-x86-64.so.2").write_bytes(b"\x7fELF-fake-ld")

        # Create data.tar.gz
        if use_zst:
            data_tar = tmp_path / "data.tar.zst"
            tar_proc = subprocess.run(
                ["tar", "-cf", "-", "-C", str(data_root), "."],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["zstd", "-o", str(data_tar)],
                input=tar_proc.stdout,
                capture_output=True, check=True,
            )
        else:
            data_tar = tmp_path / "data.tar.gz"
            subprocess.run(
                ["tar", "czf", str(data_tar), "-C", str(data_root), "."],
                check=True, capture_output=True,
            )

        # Create the .deb as an ar archive
        deb_path = tmp_path / "test.deb"
        subprocess.run(
            ["ar", "r", str(deb_path), str(data_tar)],
            check=True, capture_output=True,
        )
        return deb_path

    def test_extract_basic(self, tmp_path):
        deb = self._make_fake_deb(tmp_path / "build", arch="amd64")
        out = tmp_path / "output"
        _extract_deb(deb, out, "amd64")

        assert (out / "libc.so.6").exists()
        assert (out / "libc.so.6").read_bytes() == b"\x7fELF-fake-libc"

    def test_extract_zst(self, tmp_path):
        try:
            deb = self._make_fake_deb(tmp_path / "build_zst", arch="amd64", use_zst=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("zstd not available")
        out = tmp_path / "output_zst"
        _extract_deb(deb, out, "amd64")
        assert (out / "libc.so.6").exists()

    def test_extract_creates_output_dir(self, tmp_path):
        deb = self._make_fake_deb(tmp_path / "build2", arch="amd64")
        out = tmp_path / "nonexistent" / "deep" / "path"
        _extract_deb(deb, out, "amd64")
        assert out.is_dir()
        assert (out / "libc.so.6").exists()


class TestDownloadGlibcLive:
    @pytest.mark.network
    @pytest.mark.slow
    def test_download_single_version(self, tmp_path):
        """Integration: download a real glibc version."""
        from pwnlibc.downloader import download_glibc

        packages = scrape_available("ubuntu")
        # Find a small/common version
        pkg = None
        for p in packages:
            if p.version == "2.35" and p.arch == "amd64":
                pkg = p
                break
        if pkg is None:
            pytest.skip("glibc 2.35 amd64 not found on mirror")

        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = download_glibc(pkg, glibc_dir, include_dbg=False)
        assert result.is_dir()

        lib_dir = glibc_dir / "2.35" / "amd64" / "lib"
        assert lib_dir.is_dir()
        assert (lib_dir / "libc.so.6").exists()
        assert (lib_dir / "ld-linux-x86-64.so.2").exists()


class TestUpdateDetection:
    @patch("pwnlibc.downloader._fetch_index")
    def test_detects_missing_versions(self, mock_fetch, populated_glibc_dir):
        """Simulate update check: compare installed vs available."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        packages = scrape_available("ubuntu")

        from pwnlibc.glibc import discover_installed
        installed = {i.version for i in discover_installed(populated_glibc_dir)}

        available = {p.version for p in packages}
        missing = available - installed
        assert "2.27" in missing
        assert "2.39" not in missing  # 2.39 is installed
