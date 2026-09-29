"""Tests for pwnlibc.downloader — mirror scraping, download, extraction, verification."""

import gzip
import hashlib
import lzma
import os
import re
import subprocess
import tempfile
import time
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pwnlibc.config import MIRRORS
from pwnlibc.downloader import (
    DEB_PATTERN,
    DBG_PATTERN,
    DebPackage,
    _candidate_suites,
    _download_file,
    _extract_deb,
    _extract_dbg_deb,
    _fetch_index,
    _index_urls,
    deb_sha256_expected,
    download_glibc,
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


class TestRetryTransient:
    """Transient network errors retry with backoff; permanent ones don't."""

    @patch("pwnlibc.downloader.time.sleep")
    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_transient_then_success(self, mock_urlopen, mock_sleep, tmp_path):
        from urllib.error import URLError
        mock_urlopen.side_effect = [
            URLError("connection reset"), _FakeResponse([b"ok"]),
        ]
        dest = tmp_path / "f.deb"
        _download_file("http://example.com/f.deb", dest)
        assert dest.read_bytes() == b"ok"
        assert mock_urlopen.call_count == 2
        mock_sleep.assert_called_once()  # linear backoff between attempts

    @patch("pwnlibc.downloader.time.sleep")
    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_exhausted_retries_raise_and_clean_up(self, mock_urlopen, mock_sleep, tmp_path):
        from urllib.error import URLError
        mock_urlopen.side_effect = URLError("down")
        dest = tmp_path / "f.deb"
        with pytest.raises(URLError):
            _download_file("http://example.com/f.deb", dest)
        assert mock_urlopen.call_count == 3
        assert not dest.exists()
        assert not dest.with_name(dest.name + ".part").exists()

    @patch("pwnlibc.downloader.time.sleep")
    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_http_404_not_retried(self, mock_urlopen, mock_sleep, tmp_path):
        from urllib.error import HTTPError
        mock_urlopen.side_effect = HTTPError("u", 404, "Not Found", None, None)
        dest = tmp_path / "f.deb"
        with pytest.raises(HTTPError):
            _download_file("http://example.com/f.deb", dest)
        assert mock_urlopen.call_count == 1
        mock_sleep.assert_not_called()

    @patch("pwnlibc.downloader.time.sleep")
    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_http_503_retried(self, mock_urlopen, mock_sleep):
        from urllib.error import HTTPError
        mock_urlopen.side_effect = [
            HTTPError("u", 503, "Service Unavailable", None, None),
            _FakeResponse([b"idx"]),
        ]
        from pwnlibc.downloader import _fetch_bytes
        assert _fetch_bytes("https://example.com/Packages.xz") == b"idx"
        assert mock_urlopen.call_count == 2

    @patch("pwnlibc.downloader.time.sleep")
    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_keyboard_interrupt_not_retried(self, mock_urlopen, mock_sleep, tmp_path):
        mock_urlopen.side_effect = KeyboardInterrupt
        dest = tmp_path / "f.deb"
        with pytest.raises(KeyboardInterrupt):
            _download_file("http://example.com/f.deb", dest)
        assert mock_urlopen.call_count == 1
        mock_sleep.assert_not_called()
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
    @patch("pwnlibc.downloader._fetch_bytes",
           side_effect=urllib.error.URLError("offline"))
    def test_defaults_to_pkg_mirror(self, mock_fetch, mock_dl, mock_extract, tmp_path):
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
    @patch("pwnlibc.downloader._fetch_bytes",
           side_effect=urllib.error.URLError("offline"))
    def test_explicit_mirror_still_wins(self, mock_fetch, mock_dl, mock_extract, tmp_path):
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


# ---------------------------------------------------------------------------
# .deb SHA256 verification via dists Packages indices
# ---------------------------------------------------------------------------

def _verify_pkg(version="2.31", arch="amd64", mirror="ubuntu",
                filename="libc6_2.31-0ubuntu9.18_amd64.deb",
                dbg_filename="libc6-dbg_2.31-0ubuntu9.18_amd64.deb"):
    return DebPackage(
        version=version,
        full_id=filename[len("libc6_"):-len(".deb")],
        arch=arch,
        filename=filename,
        dbg_filename=dbg_filename,
        mirror=mirror,
    )


def _packages_index(stanzas):
    """Build a compressed Packages index from (Filename basename, sha256) pairs."""
    body = b""
    for fn, sha in stanzas:
        body += (
            b"Package: libc6\n"
            b"Filename: pool/main/g/glibc/" + fn.encode("ascii") + b"\n"
            b"SHA256: " + sha.encode("ascii") + b"\n"
            b"Size: 999\n"
            b"\n"
        )
    return lzma.compress(body)


def _fake_download(content):
    """_download_file side effect writing fixed bytes to the destination."""
    return lambda url, dest, cb=None: dest.write_bytes(content)


def _serve_indices(mock_urlopen, by_url):
    """Route mocked urlopen at pwnlibc.downloader by full URL.

    by_url maps URL suffix → bytes; anything else 404s.
    """
    def serve(req, timeout=None):
        for suffix, data in by_url.items():
            if req.full_url.endswith(suffix):
                return _FakeResponse([data])
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", None, None)
    mock_urlopen.side_effect = serve


class TestCandidateSuites:
    """Suite hints decide which dists indices can pin a given glibc."""

    def _pkg(self, version, mirror):
        return DebPackage(
            version=version,
            full_id=f"{version}-1_amd64",
            arch="amd64",
            filename=f"libc6_{version}-1_amd64.deb",
            dbg_filename=None,
            mirror=mirror,
        )

    def test_ubuntu_origin_try_order(self):
        suites = _candidate_suites(self._pkg("2.31", "ubuntu"))
        assert suites == ["focal-updates", "focal-security", "focal"]

    @pytest.mark.parametrize("mirror", ["tsinghua", "old-ubuntu", "ports"])
    def test_ubuntu_family_mirrors_use_ubuntu_table(self, mirror):
        suites = _candidate_suites(self._pkg("2.35", mirror))
        assert suites == ["jammy-updates", "jammy-security", "jammy"]

    def test_debian_origin_try_order(self):
        suites = _candidate_suites(self._pkg("2.36", "debian"))
        assert suites == ["bookworm-updates", "bookworm"]

    def test_old_debian_uses_debian_table(self):
        suites = _candidate_suites(self._pkg("2.24", "old-debian"))
        assert suites == ["stretch-updates", "stretch"]

    @pytest.mark.parametrize("version", ["2.21", "2.3.6", "9.99"])
    def test_unknown_version_has_no_suites(self, version):
        assert _candidate_suites(self._pkg(version, "ubuntu")) == []
        assert _candidate_suites(self._pkg(version, "old-ubuntu")) == []

    def test_unknown_mirror_has_no_suites(self):
        assert _candidate_suites(self._pkg("2.31", "nosuch-mirror")) == []


class TestIndexUrls:
    """The dists base is derived from the pool URL and forced to https."""

    @patch.dict("pwnlibc.downloader.MIRRORS",
                {"ubuntu": "http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/"})
    def test_http_mirror_base_forced_to_https(self):
        urls = _index_urls("ubuntu", "focal-updates", "amd64")
        assert urls == [
            "https://archive.ubuntu.com/ubuntu/dists/focal-updates/main/binary-amd64/Packages.xz",
            "https://archive.ubuntu.com/ubuntu/dists/focal-updates/main/binary-amd64/Packages.gz",
        ]

    @patch.dict("pwnlibc.downloader.MIRRORS",
                {"debian": "https://deb.debian.org/debian/pool/main/g/glibc/"})
    def test_https_mirror_base_unchanged(self):
        url = _index_urls("debian", "bookworm", "mipsel")[0]
        assert url == "https://deb.debian.org/debian/dists/bookworm/main/binary-mipsel/Packages.xz"


class TestDebSha256Expected:
    """Fetch + parse + caching of dists Packages indices."""

    FILENAME = "libc6_2.31-0ubuntu9.18_amd64.deb"
    OTHER = "libc6_2.35-0ubuntu3.8_amd64.deb"
    GOOD = hashlib.sha256(b"good-deb").hexdigest()

    def _index(self, include_target=True):
        stanzas = [(self.OTHER, hashlib.sha256(b"other").hexdigest())]
        if include_target:
            stanzas.append((self.FILENAME, self.GOOD))
        return _packages_index(stanzas)

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_extracts_sha256_for_matching_filename(self, mock_urlopen, tmp_path):
        _serve_indices(mock_urlopen, {"Packages.xz": self._index()})
        assert deb_sha256_expected(_verify_pkg(), tmp_path) == self.GOOD
        # focal-updates is tried first, over https
        url = mock_urlopen.call_args[0][0].full_url
        assert url.startswith("https://")
        assert "/dists/focal-updates/main/binary-amd64/Packages.xz" in url
        # raw compressed bytes are cached under indices/<mirror>/<suite>/<arch>/
        cached = tmp_path / "indices" / "ubuntu" / "focal-updates" / "amd64" / "Packages.xz"
        assert cached.is_file()
        assert lzma.decompress(cached.read_bytes())

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_gz_fallback_when_xz_missing(self, mock_urlopen, tmp_path):
        gz = gzip.compress(lzma.decompress(self._index()))
        _serve_indices(mock_urlopen, {"Packages.gz": gz})
        assert deb_sha256_expected(_verify_pkg(), tmp_path) == self.GOOD
        assert (tmp_path / "indices" / "ubuntu" / "focal-updates" / "amd64"
                / "Packages.gz").is_file()

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_debian_mirror_uses_debian_suites(self, mock_urlopen, tmp_path):
        pkg = _verify_pkg(arch="mipsel", mirror="debian",
                          filename="libc6_2.31-13+deb11u10_mipsel.deb",
                          dbg_filename=None)
        index = _packages_index([(pkg.filename, self.GOOD)])
        _serve_indices(mock_urlopen, {"Packages.xz": index})
        assert deb_sha256_expected(pkg, tmp_path) == self.GOOD
        url = mock_urlopen.call_args[0][0].full_url
        assert "/dists/bullseye-updates/main/binary-mipsel/Packages.xz" in url

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_missing_file_returns_none_after_all_suites(self, mock_urlopen, tmp_path):
        _serve_indices(mock_urlopen, {"Packages.xz": self._index(include_target=False)})
        assert deb_sha256_expected(_verify_pkg(), tmp_path) is None
        # all three focal pockets consulted
        fetched = [c[0][0].full_url for c in mock_urlopen.call_args_list]
        assert sum("focal-updates" in u for u in fetched) == 1
        assert sum("focal-security" in u for u in fetched) == 1
        assert sum("/dists/focal/" in u for u in fetched) == 1

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_no_suites_for_unknown_version_never_fetches(self, mock_urlopen, tmp_path):
        pkg = _verify_pkg(version="2.21",
                          filename="libc6_2.21-0ubuntu4.3_amd64.deb",
                          dbg_filename=None)
        assert deb_sha256_expected(pkg, tmp_path) is None
        mock_urlopen.assert_not_called()
        assert not (tmp_path / "indices").exists()

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_second_call_uses_cache_without_refetch(self, mock_urlopen, tmp_path):
        _serve_indices(mock_urlopen, {"Packages.xz": self._index()})
        assert deb_sha256_expected(_verify_pkg(), tmp_path) == self.GOOD
        assert mock_urlopen.call_count == 1
        assert deb_sha256_expected(_verify_pkg(), tmp_path) == self.GOOD
        assert mock_urlopen.call_count == 1  # served from disk cache

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_expired_index_cache_refetches(self, mock_urlopen, tmp_path):
        _serve_indices(mock_urlopen, {"Packages.xz": self._index()})
        assert deb_sha256_expected(_verify_pkg(), tmp_path) == self.GOOD
        cached = tmp_path / "indices" / "ubuntu" / "focal-updates" / "amd64" / "Packages.xz"
        stale = time.time() - 8 * 86400  # older than the 7-day TTL
        os.utime(str(cached), (stale, stale))
        assert deb_sha256_expected(_verify_pkg(), tmp_path) == self.GOOD
        assert mock_urlopen.call_count == 2  # refetched

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_corrupt_cached_index_dropped_and_refetched(self, mock_urlopen, tmp_path):
        _serve_indices(mock_urlopen, {"Packages.xz": self._index()})
        assert deb_sha256_expected(_verify_pkg(), tmp_path) == self.GOOD
        cached = tmp_path / "indices" / "ubuntu" / "focal-updates" / "amd64" / "Packages.xz"
        cached.write_bytes(b"not an xz stream")
        assert deb_sha256_expected(_verify_pkg(), tmp_path) == self.GOOD
        assert mock_urlopen.call_count == 2  # bad entry dropped, refetched

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_miss_marker_short_circuits_no_fetch(self, mock_urlopen, tmp_path):
        # All pockets 404: nothing lists the file (the old-releases case).
        _serve_indices(mock_urlopen, {})
        assert deb_sha256_expected(_verify_pkg(), tmp_path) is None
        assert mock_urlopen.call_count == 6  # 3 suites x (.xz + .gz)
        marker = tmp_path / "indices" / "ubuntu" / "focal-updates" / "amd64" / "Packages.miss"
        assert marker.is_file()
        assert self.FILENAME in marker.read_text("ascii")
        # All three pockets carry the miss marker.
        for suite in ("focal-updates", "focal-security", "focal"):
            assert (tmp_path / "indices" / "ubuntu" / suite / "amd64"
                    / "Packages.miss").is_file()

        mock_urlopen.reset_mock()
        assert deb_sha256_expected(_verify_pkg(), tmp_path) is None
        mock_urlopen.assert_not_called()  # markers alone decide

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_expired_miss_marker_refetches(self, mock_urlopen, tmp_path):
        _serve_indices(mock_urlopen, {})
        assert deb_sha256_expected(_verify_pkg(), tmp_path) is None
        marker = tmp_path / "indices" / "ubuntu" / "focal-updates" / "amd64" / "Packages.miss"
        stale = time.time() - 8 * 86400
        os.utime(str(marker), (stale, stale))
        deb_sha256_expected(_verify_pkg(), tmp_path)
        assert mock_urlopen.call_count > 6  # retried after marker expiry

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_miss_marker_for_one_file_does_not_block_another(self, mock_urlopen, tmp_path):
        # focal-updates 404s; focal (the release pocket) lists the file.
        # 2.31-0ubuntu9 (no point release) is only in focal, not focal-updates.
        old_rev = "libc6_2.31-0ubuntu9_amd64.deb"
        index = _packages_index([(old_rev, self.GOOD)])
        _serve_indices(mock_urlopen, {"focal/main/binary-amd64/Packages.xz": index})

        # First: a revision nobody lists -> miss markers everywhere.
        assert deb_sha256_expected(_verify_pkg(), tmp_path) is None
        mock_urlopen.reset_mock()

        # Second: a different revision from the same mirror/version pair
        # must NOT be short-circuited by the earlier miss markers.
        pkg = _verify_pkg(filename=old_rev, dbg_filename=None)
        assert deb_sha256_expected(pkg, tmp_path) == self.GOOD
        assert mock_urlopen.call_count > 0


class TestDownloadGlibcVerification:
    """download_glibc verifies both fresh and cached .debs before extracting."""

    def _pkg(self):
        return _verify_pkg()

    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._expected_sha256")
    @patch("pwnlibc.downloader._download_file")
    def test_matching_hash_proceeds_to_extraction(
            self, mock_dl, mock_expected, mock_extract, tmp_path):
        body = b"a perfectly good deb"
        mock_expected.return_value = hashlib.sha256(body).hexdigest()
        mock_dl.side_effect = _fake_download(body)
        glibc_dir = tmp_path / "glibc"

        result = download_glibc(self._pkg(), glibc_dir, include_dbg=False)

        mock_extract.assert_called_once()
        assert mock_extract.call_args[0][0] == glibc_dir / ".cache" / self._pkg().filename
        assert result == glibc_dir / "2.31" / "amd64"

    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._expected_sha256")
    @patch("pwnlibc.downloader._download_file")
    def test_mismatched_hash_raises_and_deletes_deb(
            self, mock_dl, mock_expected, mock_extract, tmp_path):
        mock_expected.return_value = hashlib.sha256(b"the real thing").hexdigest()
        mock_dl.side_effect = _fake_download(b"tampered bytes")
        glibc_dir = tmp_path / "glibc"

        with pytest.raises(RuntimeError, match="SHA256 mismatch"):
            download_glibc(self._pkg(), glibc_dir, include_dbg=False)

        assert not (glibc_dir / ".cache" / self._pkg().filename).exists()
        mock_extract.assert_not_called()

    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._expected_sha256")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_unverifiable_file_extracts_without_fetching(
            self, mock_urlopen, mock_dl, mock_expected, mock_extract, tmp_path):
        mock_expected.return_value = None  # not listed in any index
        mock_dl.side_effect = _fake_download(b"deb bytes")
        glibc_dir = tmp_path / "glibc"

        download_glibc(self._pkg(), glibc_dir, include_dbg=False)

        mock_extract.assert_called_once()
        mock_urlopen.assert_not_called()

    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._expected_sha256")
    @patch("pwnlibc.downloader._download_file")
    def test_cached_deb_is_verified_too(
            self, mock_dl, mock_expected, mock_extract, tmp_path):
        glibc_dir = tmp_path / "glibc"
        cached = glibc_dir / ".cache" / self._pkg().filename
        cached.parent.mkdir(parents=True)
        cached.write_bytes(b"stale tampered cache entry")
        mock_expected.return_value = hashlib.sha256(b"legit contents").hexdigest()
        mock_dl.side_effect = AssertionError("cached file must not be re-downloaded")

        with pytest.raises(RuntimeError, match="SHA256 mismatch"):
            download_glibc(self._pkg(), glibc_dir, include_dbg=False)

        assert not cached.exists()
        mock_extract.assert_not_called()

    @patch("pwnlibc.downloader._extract_dbg_deb")
    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_dbg_deb_verified_against_its_own_hash(
            self, mock_urlopen, mock_dl, mock_extract, mock_dbg_extract, tmp_path):
        pkg = self._pkg()
        libc_sha = hashlib.sha256(b"good libc").hexdigest()
        dbg_sha = hashlib.sha256(b"good dbg").hexdigest()

        index = _packages_index([
            (pkg.filename, libc_sha),
            (pkg.dbg_filename, dbg_sha),
        ])
        _serve_indices(mock_urlopen, {"Packages.xz": index})

        def fake_download(url, dest, cb=None):
            dest.write_bytes(b"good dbg" if "libc6-dbg_" in url else b"good libc")
        mock_dl.side_effect = fake_download
        glibc_dir = tmp_path / "glibc"

        download_glibc(pkg, glibc_dir, include_dbg=True)

        mock_extract.assert_called_once()
        mock_dbg_extract.assert_called_once()

    @patch("pwnlibc.downloader._extract_dbg_deb")
    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_dbg_mismatch_raises_and_deletes_dbg_deb(
            self, mock_urlopen, mock_dl, mock_extract, mock_dbg_extract, tmp_path):
        pkg = self._pkg()
        index = _packages_index([
            (pkg.filename, hashlib.sha256(b"good libc").hexdigest()),
            (pkg.dbg_filename, hashlib.sha256(b"good dbg").hexdigest()),
        ])
        _serve_indices(mock_urlopen, {"Packages.xz": index})

        def fake_download(url, dest, cb=None):
            dest.write_bytes(b"tampered dbg" if "libc6-dbg_" in url else b"good libc")
        mock_dl.side_effect = fake_download
        glibc_dir = tmp_path / "glibc"

        with pytest.raises(RuntimeError, match="SHA256 mismatch.*libc6-dbg"):
            download_glibc(pkg, glibc_dir, include_dbg=True)

        # libc6 verified fine and stays; the tampered dbg deb is removed.
        assert (glibc_dir / ".cache" / pkg.filename).is_file()
        assert not (glibc_dir / ".cache" / pkg.dbg_filename).exists()
        mock_extract.assert_called_once()
        mock_dbg_extract.assert_not_called()


class TestVerifyAgainstDebSha256:
    """verify_against_deb checks the cached deb hash before content compare."""

    def _pkg(self):
        return _verify_pkg()

    @staticmethod
    def _install(glibc_dir):
        lib = glibc_dir / "2.31" / "amd64" / "lib"
        lib.mkdir(parents=True, exist_ok=True)
        (lib / "libc.so.6").write_bytes(b"contents")

    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._download_file")
    def test_cached_deb_mismatch_raises_before_content_compare(
            self, mock_dl, mock_extract, tmp_path):
        glibc_dir = tmp_path / "glibc"
        self._install(glibc_dir)
        cached = glibc_dir / ".cache" / self._pkg().filename
        cached.parent.mkdir(parents=True)
        cached.write_bytes(b"tampered")
        mock_extract.side_effect = AssertionError("must not extract a bad deb")
        mock_dl.side_effect = AssertionError("cached file must not be re-downloaded")

        with patch("pwnlibc.downloader._expected_sha256",
                   return_value=hashlib.sha256(b"legit").hexdigest()):
            with pytest.raises(RuntimeError, match="SHA256 mismatch"):
                verify_against_deb(self._pkg(), glibc_dir)

        assert not cached.exists()
        mock_extract.assert_not_called()

    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._expected_sha256")
    def test_unverifiable_deb_behaves_as_before(
            self, mock_expected, mock_dl, mock_extract, tmp_path):
        glibc_dir = tmp_path / "glibc"
        self._install(glibc_dir)
        mock_expected.return_value = None  # no index lists it
        mock_dl.side_effect = _fake_download(b"deb bytes")

        def fake_extract(deb_path, out_dir, arch):
            (out_dir / "libc.so.6").write_bytes(b"contents")
        mock_extract.side_effect = fake_extract

        results = verify_against_deb(self._pkg(), glibc_dir)
        mock_extract.assert_called_once()
        assert any(status == "MATCH" for _, status, _ in results)

    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._expected_sha256")
    def test_matching_deb_hash_proceeds_to_content_compare(
            self, mock_expected, mock_dl, mock_extract, tmp_path):
        glibc_dir = tmp_path / "glibc"
        self._install(glibc_dir)
        body = b"deb bytes"
        mock_expected.return_value = hashlib.sha256(body).hexdigest()
        mock_dl.side_effect = _fake_download(body)

        def fake_extract(deb_path, out_dir, arch):
            (out_dir / "libc.so.6").write_bytes(b"contents")
        mock_extract.side_effect = fake_extract

        results = verify_against_deb(self._pkg(), glibc_dir)
        assert any(status == "MATCH" for _, status, _ in results)
