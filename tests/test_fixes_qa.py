"""Adversarial QA tests for the fixes in commit 5ad6e7b
("Fix mirror selection, dpkg revision ordering, and debug resolution").

Self-contained: all build helpers are private copies in this file. Only the
public SAMPLE_MIRROR_HTML sample is imported from tests.conftest (as other
test files already do). All network access is mocked.
"""

from __future__ import annotations

import json
import re
import struct
import tarfile
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from pwnlibc.builder import build_glibc, check_build_deps
from pwnlibc.cli import (
    _deb_version_key,
    _ensure_writable,
    _mirrors_for_arch,
    _pkg_beats,
    _pick_best,
    _scrape_mirrors,
    cli,
)
from pwnlibc.config import ARCH_INFO
from pwnlibc.downloader import (
    DebPackage,
    _download_file,
    download_source,
    scrape_available as real_scrape_available,
)
from pwnlibc.elfutil import get_debuglink
from pwnlibc.glibc import GlibcInstall, find_library, get_debug_build_path
from pwnlibc.patcher import _find_debug_file
from tests.conftest import SAMPLE_MIRROR_HTML


@pytest.fixture
def runner():
    return CliRunner()


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _pkg(full_id, mirror="ubuntu", arch="amd64"):
    """DebPackage from a full id like '2.31-0ubuntu9.16_amd64'."""
    version = full_id.rsplit("_", 1)[0].split("-")[0]
    return DebPackage(
        version=version,
        full_id=full_id,
        arch=arch,
        filename=f"libc6_{full_id}.deb",
        dbg_filename=None,
        mirror=mirror,
    )


def _make_deb_install(glibc_dir, version="2.31", arch="amd64"):
    """On-disk deb-style install discoverable by discover_installed()."""
    lib = glibc_dir / version / arch / "lib"
    lib.mkdir(parents=True, exist_ok=True)
    (lib / "libc.so.6").write_bytes(b"\x7fELF" + b"\x00" * 64)
    (lib / ARCH_INFO[arch]["ld_soname"]).write_bytes(b"\x7fELF" + b"\x00" * 64)
    return glibc_dir


def _mk_install(lib_dir, version="2.31", arch="amd64", libc_name="libc-2.31.so"):
    """GlibcInstall pointing at lib_dir (created if needed)."""
    lib_dir.mkdir(parents=True, exist_ok=True)
    libc_path = lib_dir / libc_name
    if not libc_path.exists():
        libc_path.write_bytes(b"\x7fELF" + b"\x00" * 64)
    ld_path = lib_dir / f"ld-{version}.so"
    if not ld_path.exists():
        ld_path.write_bytes(b"\x7fELF" + b"\x00" * 64)
    return GlibcInstall(
        version=version,
        arch=arch,
        base_dir=lib_dir.parent,
        lib_dir=lib_dir,
        libc_path=libc_path,
        ld_path=ld_path,
        has_source=False,
        has_debug=True,
        new_naming=False,
    )


def _build_plain_elf(path):
    """Minimal 64-bit ELF with only a .shstrtab (no .gnu_debuglink)."""
    shstrtab = b"\x00.shstrtab\x00"
    shstr_name_off = 1
    ehdr_size, shent = 64, 64
    sh_offset = ehdr_size + len(shstrtab)
    if sh_offset % 8:
        shstrtab += b"\x00" * (8 - sh_offset % 8)
        sh_offset = ehdr_size + len(shstrtab)
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    ehdr = ident
    ehdr += struct.pack("<HHI", 2, 62, 1)
    ehdr += struct.pack("<QQQ", 0, 0, sh_offset)
    ehdr += struct.pack("<IHHHHHH", 0, ehdr_size, 0, 0, shent, 2, 1)
    null_sh = struct.pack("<IIQQQQIIQQ", *([0] * 10))
    shstr_sh = struct.pack(
        "<IIQQQQIIQQ", shstr_name_off, 3, 0, 0,
        ehdr_size, len(shstrtab), 0, 0, 1, 0,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(ehdr + shstrtab + null_sh + shstr_sh)
    return path


def _build_debuglink_elf(path, debuglink_name, raw_data=None):
    """Minimal 64-bit ELF whose .gnu_debuglink names debuglink_name.

    Private copy of the construction used in tests/conftest.py.
    """
    if raw_data is None:
        raw_data = debuglink_name.encode("ascii") + b"\x00"
        pad = 4 - len(raw_data) % 4 or 4
        raw_data += b"\x00" * pad

    shstrtab = b"\x00.gnu_debuglink\x00.shstrtab\x00"
    debuglink_name_off = 1
    shstrtab_name_off = 1 + len(b".gnu_debuglink\x00")

    ehdr_size = 64
    debuglink_offset = ehdr_size
    shstrtab_offset = debuglink_offset + len(raw_data)
    sh_offset = shstrtab_offset + len(shstrtab)
    if sh_offset % 8:
        shstrtab += b"\x00" * (8 - sh_offset % 8)
        sh_offset = shstrtab_offset + len(shstrtab)

    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    ehdr = ident
    ehdr += struct.pack("<HHI", 2, 62, 1)
    ehdr += struct.pack("<QQQ", 0, 0, sh_offset)
    ehdr += struct.pack("<IHHHHHH", 0, ehdr_size, 0, 0, 64, 3, 2)

    null_sh = struct.pack("<IIQQQQIIQQ", *([0] * 10))
    debuglink_sh = struct.pack(
        "<IIQQQQIIQQ", debuglink_name_off, 1, 0, 0,
        debuglink_offset, len(raw_data), 0, 0, 1, 0,
    )
    shstrtab_sh = struct.pack(
        "<IIQQQQIIQQ", shstrtab_name_off, 3, 0, 0,
        shstrtab_offset, len(shstrtab), 0, 0, 1, 0,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(ehdr + raw_data + shstrtab + null_sh + debuglink_sh + shstrtab_sh)
    return path


class _FakeResponse:
    """urlopen() response yielding fixed chunks, then b'' or an exception."""

    def __init__(self, chunks, final_exc=None, headers=None):
        self.headers = headers if headers is not None else {"Content-Length": "100"}
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


def _make_archive(archive_dir, version="2.31", top=None):
    """Tiny real .tar.gz with <top>/amd64/lib/libc.so.6 inside."""
    archive_dir.mkdir(parents=True, exist_ok=True)
    arc = archive_dir / f"{version}.tar.gz"
    top = top or version
    with tarfile.open(arc, "w:gz") as tf:
        data = b"\x7fELF-test"
        info = tarfile.TarInfo(name=f"{top}/amd64/lib/libc.so.6")
        info.size = len(data)
        tf.addfile(info, BytesIO(data))
    return arc


# ---------------------------------------------------------------------------
# 1. _deb_version_key: dpkg-style revision ordering
# ---------------------------------------------------------------------------

class TestDebVersionKey:
    ORDERS = [
        ("2.9-0ubuntu1", "2.10-0ubuntu1"),
        ("2.23-0ubuntu3", "2.23-0ubuntu11.3"),
        ("2.6.1-1ubuntu9", "2.6.1-1ubuntu10"),
        ("2.35-0ubuntu3.1~esm1", "2.35-0ubuntu3.1"),
        ("2.19-10ubuntu2", "2.19-10ubuntu2.1"),
        ("2.27-3ubuntu1.6", "2.27-3ubuntu1.10"),
        ("2.31-0ubuntu9.2", "2.31-0ubuntu9.16"),
        ("2.36-9", "2.36-9+deb12u9"),
        ("2.35-0ubuntu3~esm1", "2.35-0ubuntu3"),
    ]

    @pytest.mark.parametrize("lo,hi", ORDERS)
    def test_lo_less_than_hi(self, lo, hi):
        assert _deb_version_key(lo) < _deb_version_key(hi)

    @pytest.mark.parametrize("lo,hi", ORDERS)
    def test_strict_antisymmetry(self, lo, hi):
        assert not (_deb_version_key(hi) < _deb_version_key(lo))
        assert _deb_version_key(hi) > _deb_version_key(lo)

    def test_equal_strings_equal_keys(self):
        for ver in ("2.31-0ubuntu9.16", "2.35-0ubuntu3.1~esm1", "2.3.2.ds1-0ubuntu20.6"):
            assert _deb_version_key(ver) == _deb_version_key(ver)

    def test_tilde_sorts_below_final_release(self):
        # '~' < end-of-string: 3.1~esm1 < 3.1 < 3.1esm2-style letters
        assert _deb_version_key("2.35-0ubuntu3.1~esm1") < _deb_version_key("2.35-0ubuntu3.1")
        assert _deb_version_key("2.35-0ubuntu3.1") < _deb_version_key("2.35-0ubuntu3.1a")

    @pytest.mark.parametrize("lo,hi", [
        ("2.23-0ubuntu3", "2.23-0ubuntu11.3"),
        ("2.35-0ubuntu3.1~esm1", "2.35-0ubuntu3.1"),
    ])
    def test_pkg_beats_one_way_only(self, lo, hi):
        a = _pkg(f"{lo}_amd64")
        b = _pkg(f"{hi}_amd64")
        assert _pkg_beats(b, a) is True
        assert _pkg_beats(a, b) is False


class TestDebVersionKeyLettersVsPunctuation:
    """dpkg orders letters BEFORE non-letters ('.', '+'); plain ASCII does not.

    The old implementation mapped only '~' inside non-digit tokens, so ASCII
    order put '.'/'+' (0x2E/0x2B) before letters — e.g. ours said
    0ubuntu3a > 0ubuntu3.1 where dpkg says 0ubuntu3a < 0ubuntu3.1.
    """

    @pytest.mark.parametrize("lo,hi", [
        ("2.31-0ubuntu3a", "2.31-0ubuntu3.1"),     # QA-found divergence
        ("2.31-0ubuntu3a", "2.31-0ubuntu3+esm1"),  # letters vs '+'
        ("2.31-0ubuntu3~esm1", "2.31-0ubuntu3a"),  # '~' still below letters
        ("2.36-9a", "2.36-9+deb12u9"),
    ])
    def test_lo_less_than_hi(self, lo, hi):
        assert _deb_version_key(lo) < _deb_version_key(hi)
        assert not (_deb_version_key(hi) < _deb_version_key(lo))


# ---------------------------------------------------------------------------
# 2. _pick_best tie-breaks and _mirrors_for_arch
# ---------------------------------------------------------------------------

class TestPickBest:

    def test_mirrors_for_arch_lists(self):
        assert _mirrors_for_arch("amd64") == ["ubuntu", "old-ubuntu"]
        assert _mirrors_for_arch("i686") == ["ubuntu", "old-ubuntu"]
        assert _mirrors_for_arch("arm64") == ["ports", "ubuntu", "old-ubuntu"]
        assert _mirrors_for_arch("powerpc") == ["old-ubuntu"]
        assert _mirrors_for_arch("mipsel") == ["debian", "old-debian"]

    def test_tie_prefers_primary_mirror(self):
        for mirrors in (["old-ubuntu", "ubuntu"], ["ubuntu", "old-ubuntu"]):
            best = _pick_best([_pkg("2.31-0ubuntu9.16_amd64", mirror=m) for m in mirrors])
            assert len(best) == 1
            assert list(best.values())[0].mirror == "ubuntu"

    def test_tie_ports_primary_for_arm64(self):
        for mirrors in (["old-ubuntu", "ports"], ["ports", "old-ubuntu"], ["ubuntu", "ports"]):
            best = _pick_best([
                _pkg("2.35-0ubuntu3.8_arm64", mirror=m, arch="arm64") for m in mirrors
            ])
            assert list(best.values())[0].mirror == "ports"

    def test_tie_unknown_mirror_loses_to_primary(self):
        for mirrors in (["tsinghua", "ubuntu"], ["ubuntu", "tsinghua"]):
            best = _pick_best([_pkg("2.31-0ubuntu9.16_amd64", mirror=m) for m in mirrors])
            assert list(best.values())[0].mirror == "ubuntu"

    def test_tie_two_unknown_mirrors_is_stable(self):
        """Out-of-chain ties: same-family mirror (tsinghua for amd64) beats
        the other family (debian) regardless of order; two genuinely
        unknown mirrors keep the first encountered."""
        best = _pick_best([
            _pkg("2.31-0ubuntu9.16_amd64", mirror="debian"),
            _pkg("2.31-0ubuntu9.16_amd64", mirror="tsinghua"),
        ])
        assert list(best.values())[0].mirror == "tsinghua"

        best = _pick_best([
            _pkg("2.31-0ubuntu9.16_amd64", mirror="mirror-a"),
            _pkg("2.31-0ubuntu9.16_amd64", mirror="mirror-b"),
        ])
        assert list(best.values())[0].mirror == "mirror-a"


    def test_newer_revision_on_secondary_mirror_beats_older_on_primary(self):
        """dpkg ordering dominates the mirror tie-break."""
        for mirrors in (["ubuntu", "old-ubuntu"], ["old-ubuntu", "ubuntu"]):
            best = _pick_best([
                _pkg("2.23-0ubuntu3_amd64", mirror="ubuntu"),
                _pkg("2.23-0ubuntu11_amd64", mirror="old-ubuntu"),
            ])
            assert list(best.values())[0].full_id == "2.23-0ubuntu11_amd64"

    def test_empty_input(self):
        assert _pick_best([]) == {}

    def test_debian_revision_never_shadows_ubuntu_for_amd64(self):
        # The 2.28 bug: Debian's 2.28-10 outranked Ubuntu's 2.28-0ubuntu1
        # under dpkg ordering, making `available` report the wrong origin.
        best = _pick_best([
            _pkg("2.28-0ubuntu1_amd64", mirror="old-ubuntu"),
            _pkg("2.28-10_amd64", mirror="old-debian"),
        ])
        assert best[("2.28", "amd64")].mirror == "old-ubuntu"

    def test_ubuntu_never_shadows_debian_for_mipsel(self):
        best = _pick_best([
            _pkg("2.28-1_mipsel", mirror="debian", arch="mipsel"),
            _pkg("2.28-0ubuntu1_mipsel", mirror="old-ubuntu", arch="mipsel"),
        ])
        assert best[("2.28", "mipsel")].mirror == "debian"


class TestAutoChainOnly:
    """Auto mode catalog = exactly what download would fetch."""

    def test_debian_amd64_packages_dropped(self):
        from pwnlibc.cli import _auto_chain_only
        pkgs = [
            _pkg("2.28-0ubuntu1_amd64", mirror="old-ubuntu"),
            _pkg("2.28-10_amd64", mirror="old-debian"),
            _pkg("2.28-1_mipsel", mirror="debian", arch="mipsel"),
        ]
        kept = _auto_chain_only(pkgs)
        assert [p.mirror for p in kept] == ["old-ubuntu", "debian"]

    def test_out_of_chain_only_means_empty(self):
        from pwnlibc.cli import _auto_chain_only
        assert _auto_chain_only([_pkg("2.36-9_amd64", mirror="debian")]) == []

    def _mirror_html(self, **by_mirror):
        """Patch _fetch_index keyed by mirror URL (the scrape seam)."""
        from pwnlibc.config import MIRRORS
        url_map = {MIRRORS[m]: html for m, html in by_mirror.items()}
        return patch("pwnlibc.downloader._fetch_index",
                     side_effect=lambda url: url_map.get(url, ""))

    def test_available_auto_shows_no_debian_rows_for_x86(self, runner, tmp_path):
        # default arch=all scrapes debian for mipsel's sake; the amd64 2.28
        # row must stay with its ubuntu-family origin, not old-debian.
        u_html = '<a href="libc6_2.28-0ubuntu1_amd64.deb">libc6_2.28-0ubuntu1_amd64.deb</a>'
        d_html = '<a href="libc6_2.28-10_amd64.deb">libc6_2.28-10_amd64.deb</a>'
        with self._mirror_html(**{"ubuntu": u_html, "old-ubuntu": u_html, "debian": d_html,
                                  "old-debian": d_html, "ports": u_html}):
            res = runner.invoke(cli, ["--glibc-dir", str(tmp_path),
                                      "available", "--no-check-source"])
        assert res.exit_code == 0
        flat = " ".join(res.output.split())
        assert "2.28" in flat and "amd64" in flat
        # mirror names legitimately appear in the fetch header; table rows
        # start with the box char, so assert no debian-sourced ROW exists
        assert "│ old-debian" not in res.output and "│ debian" not in res.output

    def test_verify_auto_checks_against_same_origin_as_download(self, runner, tmp_path):
        # CRUD consistency: verify must fetch the reference .deb from the
        # same mirror family download used, not a higher-revisioned debian one.
        from tests.conftest import _build_minimal_elf
        g = tmp_path / "2.28" / "amd64" / "lib"
        g.mkdir(parents=True)
        _build_minimal_elf(g / "libc.so.6")
        _build_minimal_elf(g / "ld-linux-x86-64.so.2")
        u_html = '<a href="libc6_2.28-0ubuntu1_amd64.deb">libc6_2.28-0ubuntu1_amd64.deb</a>'
        d_html = '<a href="libc6_2.28-10_amd64.deb">libc6_2.28-10_amd64.deb</a>'
        with self._mirror_html(**{"ubuntu": "", "old-ubuntu": u_html, "debian": d_html,
                                  "old-debian": d_html}), \
             patch("pwnlibc.cli.verify_against_deb", return_value=[("libc.so.6", "MATCH", "x")]) as mock_v:
            res = runner.invoke(cli, ["--glibc-dir", str(tmp_path), "verify"])
        assert res.exit_code == 0
        assert mock_v.call_args.kwargs["mirror"] == "old-ubuntu"

    def test_download_not_found_hints_other_arches(self, runner, tmp_path):
        # 2.99 exists only for mipsel (debian) — the error must say so.
        # x86 scrapes ubuntu/old-ubuntu; the hint scans the rest.
        m_html = '<a href="libc6_2.99-1_mipsel.deb">libc6_2.99-1_mipsel.deb</a>'
        with self._mirror_html(debian=m_html):
            res = runner.invoke(cli, ["--glibc-dir", str(tmp_path),
                                      "download", "2.99", "--no-dbg", "--no-source"])
        assert res.exit_code == 1
        flat = " ".join(res.output.split())
        assert "exists for mipsel" in flat
        assert "--arch" in flat

    def test_download_not_found_hints_other_mirror(self, runner, tmp_path):
        # amd64 package exists only on debian (out of chain in auto mode).
        d_html = '<a href="libc6_2.99-1_amd64.deb">libc6_2.99-1_amd64.deb</a>'
        with self._mirror_html(debian=d_html):
            res = runner.invoke(cli, ["--glibc-dir", str(tmp_path),
                                      "download", "2.99", "--no-dbg", "--no-source"])
        assert res.exit_code == 1
        flat = " ".join(res.output.split())
        assert "found on debian" in flat
        assert "--mirror" in flat

    def test_download_success_prints_mirror(self, runner, tmp_path):
        html = '<a href="libc6_2.28-0ubuntu1_amd64.deb">libc6_2.28-0ubuntu1_amd64.deb</a>'
        with self._mirror_html(**{"ubuntu": "", "old-ubuntu": html}), \
             patch("pwnlibc.cli.download_glibc"):
            res = runner.invoke(cli, ["--glibc-dir", str(tmp_path),
                                      "download", "2.28", "--arch", "amd64",
                                      "--no-dbg", "--no-source"])
        assert res.exit_code == 0
        flat = " ".join(res.output.split())
        assert "2.28/amd64 installed (old-ubuntu)" in flat


# ---------------------------------------------------------------------------
# 3. Mirror propagation through the CLI (download / available / verify)
# ---------------------------------------------------------------------------

class TestMirrorPropagation:

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli.scrape_available")
    def test_download_auto_mode_uses_scraped_mirror(self, mock_scrape, mock_dl, runner, tmp_path):
        mock_scrape.return_value = [_pkg("2.19-0ubuntu6.15_amd64", mirror="old-ubuntu")]
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.19", "--arch", "amd64", "--no-source",
        ])
        assert result.exit_code == 0
        mock_dl.assert_called_once()
        assert mock_dl.call_args[0][0].full_id == "2.19-0ubuntu6.15_amd64"
        assert mock_dl.call_args.kwargs["mirror"] == "old-ubuntu"

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli.scrape_available")
    def test_download_explicit_mirror_overrides_scraped(self, mock_scrape, mock_dl, runner, tmp_path):
        mock_scrape.return_value = [_pkg("2.19-0ubuntu6.15_amd64", mirror="old-ubuntu")]
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.19", "--arch", "amd64",
            "--mirror", "ubuntu", "--no-source",
        ])
        assert result.exit_code == 0
        mock_dl.assert_called_once()
        assert mock_dl.call_args.kwargs["mirror"] == "ubuntu"

    @patch("pwnlibc.cli.download_glibc", side_effect=RuntimeError("404"))
    @patch("pwnlibc.cli.scrape_available")
    def test_download_all_arches_failing_exits_nonzero(self, mock_scrape, mock_dl, runner, tmp_path):
        mock_scrape.return_value = [_pkg("2.19-0ubuntu6.15_amd64", mirror="old-ubuntu")]
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.19", "--arch", "amd64", "--no-source",
        ])
        assert result.exit_code == 1
        assert "Failed" in result.output

    @patch("pwnlibc.cli.scrape_available")
    def test_available_table_renders_scraped_mirror(self, mock_scrape, runner, tmp_path):
        mock_scrape.return_value = [_pkg("2.19-0ubuntu6.15_amd64", mirror="old-ubuntu")]
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "available", "--arch", "amd64", "--no-check-source",
        ])
        assert result.exit_code == 0
        assert "Mirror" in result.output
        # Row (not the fetching line) shows version + arch + actual mirror
        assert re.search(r"2\.19.*amd64.*old-ubuntu", result.output)

    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.cli.scrape_available")
    def test_verify_auto_mode_uses_scraped_mirror(self, mock_scrape, mock_verify, runner, tmp_path):
        mock_scrape.return_value = [_pkg("2.31-0ubuntu9.16_amd64", mirror="old-ubuntu")]
        mock_verify.return_value = [("libc.so.6", "MATCH", "deadbeefdeadbeef")]
        glibc_dir = _make_deb_install(tmp_path / "glibc")

        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "verify"])
        assert result.exit_code == 0
        mock_verify.assert_called_once()
        assert mock_verify.call_args.kwargs["mirror"] == "old-ubuntu"

    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.cli.scrape_available")
    def test_verify_explicit_mirror_overrides_scraped(self, mock_scrape, mock_verify, runner, tmp_path):
        mock_scrape.return_value = [_pkg("2.31-0ubuntu9.16_amd64", mirror="old-ubuntu")]
        mock_verify.return_value = [("libc.so.6", "MATCH", "deadbeefdeadbeef")]
        glibc_dir = _make_deb_install(tmp_path / "glibc")

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "verify", "--mirror", "ubuntu",
        ])
        assert result.exit_code == 0
        assert mock_verify.call_args.kwargs["mirror"] == "ubuntu"


# ---------------------------------------------------------------------------
# 4. _download_file atomicity
# ---------------------------------------------------------------------------

class TestDownloadFileAtomic:

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_success_writes_dest_and_removes_part(self, mock_urlopen, tmp_path):
        mock_urlopen.return_value = _FakeResponse([b"ab", b"cd"])
        dest = tmp_path / "libc6_2.31-0ubuntu9.16_amd64.deb"
        seen = []
        _download_file("http://example.com/x.deb", dest,
                       progress_cb=lambda d, t: seen.append((d, t)))
        assert dest.read_bytes() == b"abcd"
        assert not dest.with_name(dest.name + ".part").exists()

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_progress_cb_receives_downloaded_and_total(self, mock_urlopen, tmp_path):
        mock_urlopen.return_value = _FakeResponse([b"ab", b"cd"])
        dest = tmp_path / "file.deb"
        seen = []
        _download_file("http://example.com/x.deb", dest,
                       progress_cb=lambda d, t: seen.append((d, t)))
        assert seen == [(2, 100), (4, 100)]

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_progress_total_zero_when_no_content_length(self, mock_urlopen, tmp_path):
        mock_urlopen.return_value = _FakeResponse([b"ab"], headers={})
        dest = tmp_path / "file.deb"
        seen = []
        _download_file("http://example.com/x.deb", dest,
                       progress_cb=lambda d, t: seen.append((d, t)))
        assert seen == [(2, 0)]

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_midstream_exception_leaves_no_part_and_no_dest(self, mock_urlopen, tmp_path):
        mock_urlopen.return_value = _FakeResponse([b"ab"], final_exc=RuntimeError("connection reset"))
        dest = tmp_path / "libc6_2.31-0ubuntu9.16_amd64.deb"
        with pytest.raises(RuntimeError, match="connection reset"):
            _download_file("http://example.com/x.deb", dest)
        assert not dest.exists()
        assert not dest.with_name(dest.name + ".part").exists()

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_keyboard_interrupt_cleans_up_part(self, mock_urlopen, tmp_path):
        mock_urlopen.return_value = _FakeResponse([b"ab"], final_exc=KeyboardInterrupt())
        dest = tmp_path / "libc6_2.31-0ubuntu9.16_amd64.deb"
        with pytest.raises(KeyboardInterrupt):
            _download_file("http://example.com/x.deb", dest)
        assert not dest.exists()
        assert not dest.with_name(dest.name + ".part").exists()

    @patch("pwnlibc.downloader.urllib.request.urlopen")
    def test_cached_dest_survives_failed_redownload(self, mock_urlopen, tmp_path):
        dest = tmp_path / "libc6_2.31-0ubuntu9.16_amd64.deb"
        dest.write_bytes(b"good")
        mock_urlopen.return_value = _FakeResponse([b"bad"], final_exc=RuntimeError("reset"))
        with pytest.raises(RuntimeError):
            _download_file("http://example.com/x.deb", dest)
        assert dest.read_bytes() == b"good"
        assert not dest.with_name(dest.name + ".part").exists()


# ---------------------------------------------------------------------------
# 5. download_source url passthrough
# ---------------------------------------------------------------------------

class TestDownloadSourceUrl:
    URL = "https://ftp.gnu.org/gnu/glibc/glibc-2.31.tar.xz"

    @patch("pwnlibc.downloader.subprocess.run")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.builder.check_source_available")
    def test_url_passthrough_never_checks_availability(self, mock_check, mock_dl, mock_run, tmp_path):
        download_source("2.31", tmp_path, url=self.URL)
        mock_check.assert_not_called()
        mock_dl.assert_called_once()
        assert mock_dl.call_args[0][0] == self.URL
        assert mock_run.call_args[0][0][:2] == ["tar", "xf"]
        assert (tmp_path / "2.31" / "source").is_dir()

    @patch("pwnlibc.builder.check_source_available", return_value=None)
    def test_no_url_does_internal_check_and_raises(self, mock_check, tmp_path):
        with pytest.raises(RuntimeError, match="not available"):
            download_source("2.31", tmp_path)
        mock_check.assert_called_once_with("2.31")

    @patch("pwnlibc.downloader.subprocess.run")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.builder.check_source_available")
    def test_no_url_uses_checked_url(self, mock_check, mock_dl, mock_run, tmp_path):
        mock_check.return_value = self.URL
        download_source("2.31", tmp_path)
        mock_check.assert_called_once_with("2.31")
        assert mock_dl.call_args[0][0] == self.URL


# ---------------------------------------------------------------------------
# 6. verify exit codes
# ---------------------------------------------------------------------------

class TestVerifyExitCodes:

    def _invoke(self, runner, tmp_path, extra_args=None):
        glibc_dir = _make_deb_install(tmp_path / "glibc")
        args = ["--glibc-dir", str(glibc_dir), "verify"] + (extra_args or [])
        return runner.invoke(cli, args)

    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.cli.scrape_available")
    def test_all_match_exits_zero(self, mock_scrape, mock_verify, runner, tmp_path):
        mock_scrape.return_value = [_pkg("2.31-0ubuntu9.16_amd64")]
        mock_verify.return_value = [
            ("libc.so.6", "MATCH", "aa"), ("ld-linux-x86-64.so.2", "MATCH", "bb"),
        ]
        result = self._invoke(runner, tmp_path)
        assert result.exit_code == 0
        assert "verified OK" in result.output

    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.cli.scrape_available")
    def test_mismatch_exits_one(self, mock_scrape, mock_verify, runner, tmp_path):
        mock_scrape.return_value = [_pkg("2.31-0ubuntu9.16_amd64")]
        mock_verify.return_value = [("libc.so.6", "MISMATCH", "expected=aa got=bb")]
        result = self._invoke(runner, tmp_path)
        assert result.exit_code == 1

    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.cli.scrape_available")
    def test_missing_exits_one(self, mock_scrape, mock_verify, runner, tmp_path):
        mock_scrape.return_value = [_pkg("2.31-0ubuntu9.16_amd64")]
        mock_verify.return_value = [("libc.so.6", "MISSING", "")]
        result = self._invoke(runner, tmp_path)
        assert result.exit_code == 1

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.cli.scrape_available")
    def test_fix_success_exits_zero(self, mock_scrape, mock_verify, mock_dl, runner, tmp_path):
        mock_scrape.return_value = [_pkg("2.31-0ubuntu9.16_amd64", mirror="old-ubuntu")]
        mock_verify.return_value = [("libc.so.6", "MISMATCH", "expected=aa got=bb")]
        result = self._invoke(runner, tmp_path, ["--fix"])
        assert result.exit_code == 0
        mock_dl.assert_called_once()
        assert mock_dl.call_args.kwargs["mirror"] == "old-ubuntu"

    @patch("pwnlibc.cli.download_glibc", side_effect=RuntimeError("download failed"))
    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.cli.scrape_available")
    def test_fix_failure_exits_one(self, mock_scrape, mock_verify, mock_dl, runner, tmp_path):
        mock_scrape.return_value = [_pkg("2.31-0ubuntu9.16_amd64")]
        mock_verify.return_value = [("libc.so.6", "MISMATCH", "expected=aa got=bb")]
        result = self._invoke(runner, tmp_path, ["--fix"])
        assert result.exit_code == 1

    @patch("pwnlibc.cli.download_glibc", side_effect=RuntimeError("download failed"))
    @patch("pwnlibc.cli.verify_against_deb", side_effect=RuntimeError("network down"))
    @patch("pwnlibc.cli.scrape_available")
    def test_fix_with_verify_error_exits_one(self, mock_scrape, mock_verify, mock_dl,
                                             runner, tmp_path):
        """verify --fix must not exit 0 when verification itself errored.

        The errored install gets a fix retry (fresh download); when that retry
        also fails — the scenario here, the network is down — fix_failed > 0
        and the command exits 1.
        """
        mock_scrape.return_value = [_pkg("2.31-0ubuntu9.16_amd64")]
        result = self._invoke(runner, tmp_path, ["--fix"])
        assert "problems" in result.output  # the run did report a problem...
        assert result.exit_code == 1        # ...so the exit code must agree
        mock_dl.assert_called_once()        # ...and the errored install was retried

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli.verify_against_deb", side_effect=RuntimeError("network down"))
    @patch("pwnlibc.cli.scrape_available")
    def test_fix_with_verify_error_retry_success_exits_zero(self, mock_scrape, mock_verify,
                                                            mock_dl, runner, tmp_path):
        """When the retry download succeeds, the verification error is fixed."""
        mock_scrape.return_value = [_pkg("2.31-0ubuntu9.16_amd64")]
        result = self._invoke(runner, tmp_path, ["--fix"])
        assert result.exit_code == 0
        mock_dl.assert_called_once()

    @patch("pwnlibc.cli.verify_against_deb", side_effect=RuntimeError("network down"))
    @patch("pwnlibc.cli.scrape_available")
    def test_verify_error_without_fix_exits_one(self, mock_scrape, mock_verify,
                                                runner, tmp_path):
        mock_scrape.return_value = [_pkg("2.31-0ubuntu9.16_amd64")]
        result = self._invoke(runner, tmp_path)
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# 7. remove source rules
# ---------------------------------------------------------------------------

class TestRemoveSourceRules:

    def test_arch_filter_keeps_shared_source_then_prunes_on_last_arch(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _make_deb_install(glibc_dir, "2.31", "amd64")
        _make_deb_install(glibc_dir, "2.31", "i686")
        (glibc_dir / "2.31" / "source").mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--arch", "amd64",
        ])
        assert result.exit_code == 0
        assert not (glibc_dir / "2.31" / "amd64").exists()
        assert (glibc_dir / "2.31" / "i686").is_dir()
        assert (glibc_dir / "2.31" / "source").is_dir()

        # Removing the last arch takes the orphaned source with it
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--arch", "i686",
        ])
        assert result.exit_code == 0
        assert not (glibc_dir / "2.31" / "source").exists()
        assert not (glibc_dir / "2.31").exists()

    def test_variant_all_arch_all_removes_source(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _make_deb_install(glibc_dir, "2.31", "amd64")
        _make_deb_install(glibc_dir, "2.31", "i686")
        (glibc_dir / "2.31" / "source").mkdir()

        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "remove", "2.31"])
        assert result.exit_code == 0
        assert not (glibc_dir / "2.31").exists()

    def test_variant_source_removes_only_source(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _make_deb_install(glibc_dir, "2.31", "amd64")
        (glibc_dir / "2.31" / "source").mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--variant", "source",
        ])
        assert result.exit_code == 0
        assert not (glibc_dir / "2.31" / "source").exists()
        assert (glibc_dir / "2.31" / "amd64").is_dir()

    def test_variant_all_specific_arch_last_lib_auto_removes_source(self, runner, tmp_path):
        """--variant all --arch amd64 where only amd64 exists: source is
        auto-removed because no deb/built variant remains."""
        glibc_dir = tmp_path / "glibc"
        _make_deb_install(glibc_dir, "2.31", "amd64")
        (glibc_dir / "2.31" / "source").mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--arch", "amd64",
        ])
        assert result.exit_code == 0
        assert not (glibc_dir / "2.31" / "source").exists()
        assert not (glibc_dir / "2.31").exists()

    def test_arch_filter_missing_arch_keeps_everything(self, runner, tmp_path):
        """Removing an arch that is not installed must not touch the others."""
        glibc_dir = tmp_path / "glibc"
        _make_deb_install(glibc_dir, "2.31", "i686")
        (glibc_dir / "2.31" / "source").mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--arch", "amd64",
        ])
        assert result.exit_code == 0
        assert (glibc_dir / "2.31" / "i686").is_dir()
        assert (glibc_dir / "2.31" / "source").is_dir()
        assert "Nothing to remove" in result.output


class TestRemoveCachePruning:
    """remove --arch must prune only that arch's cached .debs."""

    @staticmethod
    def _make_cache(glibc_dir, version="2.31"):
        cache = glibc_dir / ".cache"
        cache.mkdir(parents=True, exist_ok=True)
        for deb_arch in ("amd64", "i386"):
            (cache / f"libc6_{version}-0ubuntu9.16_{deb_arch}.deb").write_bytes(b"deb")
            (cache / f"libc6-dbg_{version}-0ubuntu9.16_{deb_arch}.deb").write_bytes(b"dbg")

    def test_remove_single_arch_keeps_other_arch_cache(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _make_deb_install(glibc_dir, "2.31", "amd64")
        _make_deb_install(glibc_dir, "2.31", "i686")
        self._make_cache(glibc_dir)

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--arch", "amd64",
        ])
        assert result.exit_code == 0
        cache = glibc_dir / ".cache"
        assert not (cache / "libc6_2.31-0ubuntu9.16_amd64.deb").exists()
        assert not (cache / "libc6-dbg_2.31-0ubuntu9.16_amd64.deb").exists()
        assert (cache / "libc6_2.31-0ubuntu9.16_i386.deb").exists()
        assert (cache / "libc6-dbg_2.31-0ubuntu9.16_i386.deb").exists()

    def test_remove_all_arches_prunes_all_cache(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _make_deb_install(glibc_dir, "2.31", "amd64")
        _make_deb_install(glibc_dir, "2.31", "i686")
        self._make_cache(glibc_dir)

        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "remove", "2.31"])
        assert result.exit_code == 0
        cache = glibc_dir / ".cache"
        assert not (cache / "libc6_2.31-0ubuntu9.16_amd64.deb").exists()
        assert not (cache / "libc6_2.31-0ubuntu9.16_i386.deb").exists()


# ---------------------------------------------------------------------------
# 8. get_debuglink
# ---------------------------------------------------------------------------

class TestGetDebuglink:

    @pytest.mark.parametrize("name", ["abc123def456.debug", "libc.so.6.debug", "x"])
    def test_returns_debuglink_name(self, tmp_path, name):
        f = _build_debuglink_elf(tmp_path / "with_link", name)
        assert get_debuglink(f) == name

    def test_no_debuglink_section_returns_none(self, tmp_path):
        f = _build_plain_elf(tmp_path / "no_link")
        assert get_debuglink(f) is None

    def test_non_elf_returns_none(self, tmp_path):
        f = tmp_path / "blob"
        f.write_bytes(b"definitely not an elf file")
        assert get_debuglink(f) is None

    def test_debuglink_without_nul_terminator_returns_none(self, tmp_path):
        """Malformed section data must not crash; it degrades to None."""
        f = _build_debuglink_elf(tmp_path / "bad_link", "unused", raw_data=b"no-nul-here")
        assert get_debuglink(f) is None


# ---------------------------------------------------------------------------
# 9. patcher._find_debug_file
# ---------------------------------------------------------------------------

class TestFindDebugFile:

    def test_debuglink_name_in_debug_dir_wins(self, tmp_path):
        lib_dir = tmp_path / "lib"
        debug_dir = tmp_path / ".debug"
        debug_dir.mkdir()
        lib = _build_debuglink_elf(lib_dir / "libc-2.31.so", "abc123.debug")
        (debug_dir / "abc123.debug").write_bytes(b"hash-debug")
        (debug_dir / "libc-2.31.debug").write_bytes(b"prefixed-debug")

        found = _find_debug_file(debug_dir, lib)
        assert found is not None
        assert found.name == "abc123.debug"

    def test_debuglink_missing_falls_back_to_exact_name(self, tmp_path):
        lib_dir = tmp_path / "lib"
        debug_dir = tmp_path / ".debug"
        debug_dir.mkdir()
        lib = _build_debuglink_elf(lib_dir / "libc-2.31.so", "notthere.debug")
        (debug_dir / "libc-2.31.so").write_bytes(b"exact")
        (debug_dir / "libc-2.31.debug").write_bytes(b"prefixed")

        found = _find_debug_file(debug_dir, lib)
        assert found is not None
        assert found.name == "libc-2.31.so"

    def test_no_debuglink_exact_name(self, tmp_path):
        lib_dir = tmp_path / "lib"
        debug_dir = tmp_path / ".debug"
        debug_dir.mkdir()
        lib = _build_plain_elf(lib_dir / "libc-2.31.so")
        (debug_dir / "libc-2.31.so").write_bytes(b"exact")

        assert _find_debug_file(debug_dir, lib) == debug_dir / "libc-2.31.so"

    def test_prefix_fallback_picks_libc_prefixed_file(self, tmp_path):
        lib_dir = tmp_path / "lib"
        debug_dir = tmp_path / ".debug"
        debug_dir.mkdir()
        lib = _build_plain_elf(lib_dir / "libc-2.31.so")
        for name in ("libcrypt-2.31.debug", "libc-2.31.debug", "libcidn-2.31.debug"):
            (debug_dir / name).write_bytes(b"d")

        found = _find_debug_file(debug_dir, lib)
        assert found is not None
        assert found.name == "libc-2.31.debug"

    def test_libc_prefix_never_matches_libcrypt_or_libcidn(self, tmp_path):
        lib_dir = tmp_path / "lib"
        debug_dir = tmp_path / ".debug"
        debug_dir.mkdir()
        lib = _build_plain_elf(lib_dir / "libc-2.31.so")
        (debug_dir / "libcrypt-2.31.debug").write_bytes(b"d")
        (debug_dir / "libcidn-2.31.debug").write_bytes(b"d")

        assert _find_debug_file(debug_dir, lib) is None

    def test_libm_prefix_matches_libm_but_not_libmvec(self, tmp_path):
        lib_dir = tmp_path / "lib"
        debug_dir = tmp_path / ".debug"
        debug_dir.mkdir()
        lib = _build_plain_elf(lib_dir / "libm-2.31.so")
        (debug_dir / "libm-2.31.debug").write_bytes(b"d")
        (debug_dir / "libmvec-2.31.debug").write_bytes(b"d")
        (debug_dir / "libmemusage-2.31.debug").write_bytes(b"d")

        found = _find_debug_file(debug_dir, lib)
        assert found is not None
        assert found.name == "libm-2.31.debug"

    def test_libm_prefix_never_matches_libmvec_only(self, tmp_path):
        lib_dir = tmp_path / "lib"
        debug_dir = tmp_path / ".debug"
        debug_dir.mkdir()
        lib = _build_plain_elf(lib_dir / "libm-2.31.so")
        (debug_dir / "libmvec-2.31.debug").write_bytes(b"d")
        (debug_dir / "libmemusage-2.31.debug").write_bytes(b"d")

        assert _find_debug_file(debug_dir, lib) is None

    def test_empty_debug_dir_returns_none(self, tmp_path):
        lib_dir = tmp_path / "lib"
        debug_dir = tmp_path / ".debug"
        debug_dir.mkdir()
        lib = _build_plain_elf(lib_dir / "libc-2.31.so")

        assert _find_debug_file(debug_dir, lib) is None


# ---------------------------------------------------------------------------
# 10. find_library
# ---------------------------------------------------------------------------

class TestFindLibrary:

    def test_direct_soname_hit(self, tmp_path):
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "libpthread-2.31.so").write_bytes(b"x")
        (lib_dir / "libpthread.so.0").symlink_to("libpthread-2.31.so")
        inst = _mk_install(lib_dir)

        found = find_library(inst, "libpthread.so.0")
        assert found is not None
        assert found.name == "libpthread-2.31.so"  # resolved

    def test_versioned_fallback_picks_shortest_name(self, tmp_path):
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "libm-2.31.so").write_bytes(b"x")
        (lib_dir / "libmvec-2.31.so").write_bytes(b"x")
        inst = _mk_install(lib_dir)

        found = find_library(inst, "libm.so.6")
        assert found is not None
        assert found.name == "libm-2.31.so"

    def test_libm_soname_never_matches_libmvec_only(self, tmp_path):
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "libmvec-2.31.so").write_bytes(b"x")
        (lib_dir / "libmemusage-2.31.so").write_bytes(b"x")
        inst = _mk_install(lib_dir)

        assert find_library(inst, "libm.so.6") is None

    def test_no_match_returns_none(self, tmp_path):
        inst = _mk_install(tmp_path / "lib")
        assert find_library(inst, "libnothere.so.9") is None

    def test_deterministic_across_creation_orders(self, tmp_path):
        """Same names created in different orders must resolve identically."""
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        for name in ("libm-2.31.so", "libmvec-2.31.so", "libm-9.99.so"):
            (dir_a / name).write_bytes(b"x")
        dir_b.mkdir()
        for name in reversed(["libm-2.31.so", "libmvec-2.31.so", "libm-9.99.so"]):
            (dir_b / name).write_bytes(b"x")

        assert find_library(_mk_install(dir_a), "libm.so.6").name == \
               find_library(_mk_install(dir_b), "libm.so.6").name == "libm-2.31.so"

    def test_deterministic_under_permuted_iterdir(self, tmp_path, monkeypatch):
        """Result must not depend on Path.iterdir() ordering."""
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        for name in ("libm-2.31.so", "libm-9.99.so", "libmvec-2.31.so"):
            (lib_dir / name).write_bytes(b"x")

        original_iterdir = Path.iterdir

        def reversed_iterdir(self):
            return list(reversed(list(original_iterdir(self))))

        monkeypatch.setattr(Path, "iterdir", reversed_iterdir)
        inst = _mk_install(lib_dir)
        assert find_library(inst, "libm.so.6").name == "libm-2.31.so"


# ---------------------------------------------------------------------------
# 11. get_debug_build_path
# ---------------------------------------------------------------------------

class TestGetDebugBuildPath:

    def _install(self, tmp_path, version="2.31", libc_content=None):
        inst = _mk_install(tmp_path / "lib", version=version)
        if libc_content is not None:
            inst.libc_path.write_bytes(libc_content)
        return inst

    def test_hash_debug_file_via_debuglink(self, tmp_path, monkeypatch):
        hash_name = "abc123def456.debug"
        inst = self._install(tmp_path)
        debug_dir = inst.lib_dir / ".debug"
        debug_dir.mkdir()
        (debug_dir / hash_name).write_bytes(
            b"junk" + b"/build/glibc-abc/glibc-2.31/malloc/malloc.c" + b"junk"
        )
        monkeypatch.setattr("pwnlibc.glibc.get_debuglink", lambda p: hash_name)

        assert get_debug_build_path(inst) == "/build/glibc-abc/glibc-2.31"

    def test_debuglink_candidate_takes_priority(self, tmp_path, monkeypatch):
        """First candidate (debuglink-named) wins over later candidates."""
        hash_name = "first.debug"
        inst = self._install(tmp_path)
        debug_dir = inst.lib_dir / ".debug"
        debug_dir.mkdir()
        (debug_dir / hash_name).write_bytes(b"/build/glibc-debug/glibc-2.31/x")
        (debug_dir / inst.libc_path.name).write_bytes(b"/build/glibc-other/glibc-2.31/x")
        monkeypatch.setattr("pwnlibc.glibc.get_debuglink", lambda p: hash_name)

        assert get_debug_build_path(inst) == "/build/glibc-debug/glibc-2.31"

    def test_zero_length_debug_file_falls_through_to_libc(self, tmp_path, monkeypatch):
        hash_name = "empty.debug"
        inst = self._install(
            tmp_path,
            libc_content=b"\x7fELF" + b"\x00" * 32 + b"/build/glibc-builder/glibc-2.31/stdio/printf.c",
        )
        debug_dir = inst.lib_dir / ".debug"
        debug_dir.mkdir()
        (debug_dir / hash_name).write_bytes(b"")  # zero-length: mmap refuses
        monkeypatch.setattr("pwnlibc.glibc.get_debuglink", lambda p: hash_name)

        assert get_debug_build_path(inst) == "/build/glibc-builder/glibc-2.31"

    def test_exact_name_debug_file_without_debuglink(self, tmp_path):
        """No debuglink: .debug/<libc name> is consulted."""
        inst = self._install(tmp_path, libc_content=b"\x7fELF" + b"\x00" * 64)
        debug_dir = inst.lib_dir / ".debug"
        debug_dir.mkdir()
        (debug_dir / inst.libc_path.name).write_bytes(b"/build/glibc-Zz9/glibc-2.31/y")

        assert get_debug_build_path(inst) == "/build/glibc-Zz9/glibc-2.31"

    def test_no_match_anywhere_returns_none(self, tmp_path, monkeypatch):
        inst = self._install(tmp_path)  # plain ELF, no path inside
        debug_dir = inst.lib_dir / ".debug"
        debug_dir.mkdir()
        (debug_dir / "abc.debug").write_bytes(b"no build path here")
        monkeypatch.setattr("pwnlibc.glibc.get_debuglink", lambda p: "abc.debug")

        assert get_debug_build_path(inst) is None

    def test_mmap_path_usable_for_multi_mb_debug_file(self, tmp_path, monkeypatch):
        """A debug file larger than one mmap page still yields the group.

        Regression guard for reading the match group while the mmap is open:
        closing first raises TypeError (swallowed to None by the except).
        """
        hash_name = "big.debug"
        inst = self._install(tmp_path)
        debug_dir = inst.lib_dir / ".debug"
        debug_dir.mkdir()
        payload = b"A" * (4 * 1024 * 1024) + b"/build/glibc-big/glibc-2.31/libc-start.c"
        (debug_dir / hash_name).write_bytes(payload)
        monkeypatch.setattr("pwnlibc.glibc.get_debuglink", lambda p: hash_name)

        assert get_debug_build_path(inst) == "/build/glibc-big/glibc-2.31"


# ---------------------------------------------------------------------------
# 12. builder: multilib probe, configure args, download delegation
# ---------------------------------------------------------------------------

class TestBuilder:

    @patch("pwnlibc.builder.subprocess.run")
    @patch("shutil.which")
    def test_i686_bare_libgcc_name_reports_multilib_missing(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/fake"
        mock_run.return_value = SimpleNamespace(returncode=0, stdout="libgcc.a\n", stderr="")
        missing = check_build_deps("i686")
        assert any("gcc-multilib" in m for m in missing)

    @patch("pwnlibc.builder.subprocess.run")
    @patch("shutil.which")
    def test_i686_full_libgcc_path_not_reported(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/fake"
        mock_run.return_value = SimpleNamespace(
            returncode=0, stdout="/usr/lib/gcc/x86_64-linux-gnu/13/32/libgcc.a\n", stderr="")
        assert check_build_deps("i686") == []

    @patch("pwnlibc.builder.subprocess.run")
    @patch("shutil.which")
    def test_i686_probe_nonzero_rc_reports_multilib_missing(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/fake"
        mock_run.return_value = SimpleNamespace(returncode=2, stdout="", stderr="gcc: error")
        missing = check_build_deps("i686")
        assert any("gcc-multilib" in m for m in missing)

    @patch("pwnlibc.builder.subprocess.run")
    @patch("shutil.which")
    def test_probe_not_run_when_gcc_missing(self, mock_which, mock_run):
        def which(name):
            return None if name == "gcc" else "/usr/bin/fake"
        mock_which.side_effect = which
        missing = check_build_deps("i686")
        assert "gcc" in missing
        mock_run.assert_not_called()

    # -- configure args ----------------------------------------------------

    URL = "https://ftp.gnu.org/gnu/glibc/glibc-{version}.tar.xz"

    @staticmethod
    def _run_build(version, arch, glibc_dir):
        """Run build_glibc fully mocked; return the recorded configure cmd/env."""
        recorded = {}

        def run_side_effect(cmd, **kwargs):
            cmd = [str(c) for c in cmd]
            if cmd[0] == "tar":
                try:
                    target = Path(cmd[cmd.index("-C") + 1])
                except ValueError:
                    target = Path(kwargs.get("cwd", "."))
                src_dir = target / f"glibc-{version}"
                src_dir.mkdir(parents=True, exist_ok=True)
                (src_dir / "configure").write_text("#!/bin/sh\nexit 0\n")
            elif cmd[0].endswith("configure"):
                recorded["configure"] = cmd
                recorded["env"] = kwargs.get("env")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("pwnlibc.builder.check_source_available",
                   return_value=TestBuilder.URL.format(version=version)), \
             patch("pwnlibc.builder._download_file"), \
             patch("pwnlibc.builder.subprocess.run", side_effect=run_side_effect):
            build_glibc(version, arch, glibc_dir)
        return recorded

    def test_arm64_configure_has_host_but_no_build(self, tmp_path):
        recorded = self._run_build("2.35", "arm64", tmp_path)
        cmd = recorded["configure"]
        assert "--host=aarch64-linux-gnu" in cmd
        assert not any(arg.startswith("--build=") for arg in cmd)

    def test_i686_configure_keeps_host_and_build(self, tmp_path):
        recorded = self._run_build("2.27", "i686", tmp_path)
        cmd = recorded["configure"]
        assert "--host=i686-linux-gnu" in cmd
        assert "--build=i686-linux-gnu" in cmd
        assert recorded["env"]["CC"] == "gcc -m32"

    def test_amd64_configure_has_neither_host_nor_build(self, tmp_path):
        recorded = self._run_build("2.31", "amd64", tmp_path)
        cmd = recorded["configure"]
        assert not any(arg.startswith("--host=") for arg in cmd)
        assert not any(arg.startswith("--build=") for arg in cmd)

    # -- download delegation -------------------------------------------------

    def test_build_delegates_download_to_download_file(self, tmp_path):
        url = self.URL.format(version="2.31")

        def run_side_effect(cmd, **kwargs):
            cmd = [str(c) for c in cmd]
            if cmd[0] == "tar":
                src_dir = Path(cmd[cmd.index("-C") + 1]) / "glibc-2.31"
                src_dir.mkdir(parents=True, exist_ok=True)
                (src_dir / "configure").write_text("#!/bin/sh\n")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("pwnlibc.builder.check_source_available", return_value=url), \
             patch("pwnlibc.builder._download_file") as mock_dl, \
             patch("pwnlibc.builder.subprocess.run", side_effect=run_side_effect):
            build_glibc("2.31", "amd64", tmp_path)

        mock_dl.assert_called_once()
        dl_url, dl_dest = mock_dl.call_args[0][:2]
        assert dl_url == url
        assert dl_dest.name == "glibc-2.31.tar.xz"


# ---------------------------------------------------------------------------
# 13. _scrape_mirrors
# ---------------------------------------------------------------------------

class TestScrapeMirrors:

    @patch("pwnlibc.cli.scrape_available", side_effect=RuntimeError("all down"))
    def test_all_mirrors_fail_returns_empty(self, mock_scrape):
        assert _scrape_mirrors({"ubuntu", "old-ubuntu"}) == []
        assert mock_scrape.call_count == 2

    def test_empty_mirror_set_returns_empty(self):
        assert _scrape_mirrors(set()) == []

    @patch("pwnlibc.downloader._fetch_index")
    @patch("pwnlibc.cli.scrape_available")
    def test_partial_failure_returns_good_ones(self, mock_scrape, mock_fetch):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML

        def side_effect(mirror):
            if mirror == "old-ubuntu":
                raise RuntimeError("mirror down")
            return real_scrape_available(mirror)

        mock_scrape.side_effect = side_effect
        pkgs = _scrape_mirrors({"ubuntu", "old-ubuntu"})
        assert pkgs, "results from the healthy mirror must survive"
        assert all(p.mirror == "ubuntu" for p in pkgs)
        assert any(p.version == "2.31" for p in pkgs)


# ---------------------------------------------------------------------------
# 14. setup writability / extraction
# ---------------------------------------------------------------------------

class TestEnsureWritable:
    """Write commands auto-create a missing glibc dir instead of erroring."""

    def test_missing_dir_created(self, tmp_path, capsys):
        target = tmp_path / "fresh" / "nested" / "glibcdir"
        _ensure_writable(target)
        assert target.is_dir()
        assert "Created glibc directory" in capsys.readouterr().out

    def test_existing_dir_passes(self, tmp_path, capsys):
        _ensure_writable(tmp_path)
        assert "Created" not in capsys.readouterr().out

    def test_uncreatable_dir_exits(self, tmp_path, monkeypatch, capsys):
        from pathlib import Path as _P
        import click
        monkeypatch.setattr(_P, "mkdir", lambda self, *a, **k: (_ for _ in ()).throw(OSError("EACCES")))
        with pytest.raises(SystemExit):
            _ensure_writable(tmp_path / "nope")
        assert "Cannot create" in capsys.readouterr().out


class TestSetup:

    def test_missing_target_dir_is_created_and_used(self, runner, tmp_path):
        archive_dir = tmp_path / "archives"
        _make_archive(archive_dir, version="2.31")
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        target = tmp_path / "fresh" / "nested"  # does not exist yet

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "setup", str(archive_dir),
            "--target-dir", str(target),
        ])
        assert result.exit_code == 0
        assert (target / "2.31" / "amd64" / "lib" / "libc.so.6").exists()

    def test_setup_with_real_tarball_extracts(self, runner, tmp_path):
        archive_dir = tmp_path / "archives"
        _make_archive(archive_dir, version="2.35")
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "setup", str(archive_dir),
        ])
        assert result.exit_code == 0
        assert "deb variant" in result.output
        assert (glibc_dir / "2.35" / "amd64" / "lib" / "libc.so.6").exists()

    def test_setup_single_nonmatching_topdir_fallback(self, runner, tmp_path):
        archive_dir = tmp_path / "archives"
        _make_archive(archive_dir, version="2.31", top="glibc-2.31")
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "setup", str(archive_dir),
        ])
        assert result.exit_code == 0
        assert (glibc_dir / "2.31" / "amd64" / "lib" / "libc.so.6").exists()

    def test_extractall_filter_typeerror_falls_back(self, runner, tmp_path):
        """Python without the filter= parameter must fall back to plain
        extractall rather than crashing."""
        archive_dir = tmp_path / "archives"
        _make_archive(archive_dir, version="2.31")
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        fake_tf = MagicMock()
        fake_tf.__enter__.return_value = fake_tf
        fake_tf.__exit__.return_value = False
        fake_tf.extractall.side_effect = [
            TypeError("extractall() got an unexpected keyword argument 'filter'"),
            None,
        ]
        with patch("pwnlibc.cli.tarfile.open", return_value=fake_tf):
            result = runner.invoke(cli, [
                "--glibc-dir", str(glibc_dir), "setup", str(archive_dir),
            ])

        assert result.exit_code == 0
        assert fake_tf.extractall.call_count == 2
        assert fake_tf.extractall.call_args_list[0].kwargs.get("filter") == "data"
        assert "filter" not in fake_tf.extractall.call_args_list[1].kwargs


# ---------------------------------------------------------------------------
# 15. restore consumes the copy-mode patch manifest
# ---------------------------------------------------------------------------

class TestRestoreManifest:

    @staticmethod
    def _make_manifest(binary, files):
        manifest = binary.parent / (binary.name + ".patched.manifest")
        manifest.write_text(json.dumps({"files": files}))
        return manifest

    @staticmethod
    def _make_binary(tmp_path):
        d = tmp_path / "proj"
        d.mkdir()
        binary = d / "vuln"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 32)
        return binary

    def test_manifest_removes_listed_files_empty_debug_and_itself(self, runner, tmp_path):
        binary = self._make_binary(tmp_path)
        (binary.parent / "libc-2.31.so").write_bytes(b"lib")
        (binary.parent / "ld-2.31.so").write_bytes(b"ld")
        debug = binary.parent / ".debug"
        debug.mkdir()
        (debug / "abc123.debug").write_bytes(b"dbg")
        manifest = self._make_manifest(
            binary, ["libc-2.31.so", "ld-2.31.so", ".debug/abc123.debug"])

        result = runner.invoke(cli, ["restore", str(binary)])
        assert result.exit_code == 0
        assert not (binary.parent / "libc-2.31.so").exists()
        assert not (binary.parent / "ld-2.31.so").exists()
        assert not debug.exists()        # emptied -> removed
        assert not manifest.exists()     # consumed
        assert binary.exists()
        assert "Removed 3 copied files" in result.output

    def test_files_not_in_manifest_are_left_alone(self, runner, tmp_path):
        binary = self._make_binary(tmp_path)
        (binary.parent / "libc-2.31.so").write_bytes(b"lib")
        (binary.parent / "chal_helper.so").write_bytes(b"manual")
        debug = binary.parent / ".debug"
        debug.mkdir()
        (debug / "abc123.debug").write_bytes(b"dbg")
        (debug / "user.debug").write_bytes(b"manual")
        self._make_manifest(binary, ["libc-2.31.so", ".debug/abc123.debug"])

        result = runner.invoke(cli, ["restore", str(binary)])
        assert result.exit_code == 0
        assert not (binary.parent / "libc-2.31.so").exists()
        assert (binary.parent / "chal_helper.so").exists()
        assert (debug / "user.debug").exists()   # .debug not empty -> kept
        assert debug.is_dir()

    def test_traversal_entries_are_refused(self, runner, tmp_path):
        binary = self._make_binary(tmp_path)
        canary = tmp_path / "canary.txt"
        canary.write_text("must survive")
        (binary.parent / "libc-2.31.so").write_bytes(b"lib")
        manifest = self._make_manifest(
            binary, ["../../etc/passwd", "../canary.txt", "libc-2.31.so"])

        result = runner.invoke(cli, ["restore", str(binary)])
        assert result.exit_code == 0
        assert canary.exists()                    # outside file untouched
        assert not (binary.parent / "libc-2.31.so").exists()  # sane entry honored
        assert not manifest.exists()

    def test_patched_and_manifest_both_handled(self, runner, tmp_path):
        binary = self._make_binary(tmp_path)
        patched = binary.parent / (binary.name + ".patched")
        patched.write_bytes(b"\x7fELF-patched")
        (binary.parent / "ld-2.31.so").write_bytes(b"ld")
        manifest = self._make_manifest(binary, ["ld-2.31.so"])

        result = runner.invoke(cli, ["restore", str(binary)])
        assert result.exit_code == 0
        assert not patched.exists()
        assert not (binary.parent / "ld-2.31.so").exists()
        assert not manifest.exists()
        assert f"Removed {patched.name}" in result.output

    def test_manifest_without_patched_still_consumed(self, runner, tmp_path):
        """User deleted the .patched copy manually: manifest still cleans up."""
        binary = self._make_binary(tmp_path)
        (binary.parent / "libc-2.31.so").write_bytes(b"lib")
        manifest = self._make_manifest(binary, ["libc-2.31.so"])

        result = runner.invoke(cli, ["restore", str(binary)])
        assert result.exit_code == 0
        assert not (binary.parent / "libc-2.31.so").exists()
        assert not manifest.exists()

    def test_no_manifest_legacy_behavior_unchanged(self, runner, tmp_path):
        """Without a manifest restore does not touch anything but .patched."""
        binary = self._make_binary(tmp_path)
        patched = binary.parent / (binary.name + ".patched")
        patched.write_bytes(b"\x7fELF-patched")
        (binary.parent / "libc-2.31.so").write_bytes(b"copied long ago")

        result = runner.invoke(cli, ["restore", str(binary)])
        assert result.exit_code == 0
        assert not patched.exists()
        assert (binary.parent / "libc-2.31.so").exists()  # still untouchable

    def test_empty_files_list_just_consumes_manifest(self, runner, tmp_path):
        binary = self._make_binary(tmp_path)
        manifest = self._make_manifest(binary, [])

        result = runner.invoke(cli, ["restore", str(binary)])
        assert result.exit_code == 0
        assert not manifest.exists()
        assert "copied files" not in result.output

    def test_manifest_cannot_delete_non_lib_files(self, runner, tmp_path):
        """A tampered manifest must not name arbitrary files (flag.txt,
        Makefile, ...) in the binary's directory for deletion — directly or
        via lib/../ or .debug/../ traversal that lands on them: only names a
        copy-mode patch can create (lib*, ld-*, .debug/*) are honored."""
        binary = self._make_binary(tmp_path)
        (binary.parent / "libc-2.31.so").write_bytes(b"lib")
        (binary.parent / "flag.txt").write_text("CTF flag — must survive")
        (binary.parent / "notes.md").write_text("user notes — must survive")
        (binary.parent / "notes.txt").write_text("more notes — must survive")
        manifest = self._make_manifest(
            binary,
            ["flag.txt", "notes.md",
             "lib/../notes.txt",     # traversal wearing a lib* prefix
             ".debug/../flag.txt",   # traversal wearing a .debug/ prefix
             "libc-2.31.so"])

        result = runner.invoke(cli, ["restore", str(binary)])
        assert result.exit_code == 0
        assert (binary.parent / "flag.txt").exists()
        assert (binary.parent / "notes.md").exists()
        assert (binary.parent / "notes.txt").exists()
        assert not (binary.parent / "libc-2.31.so").exists()  # sane entry honored
        assert not manifest.exists()

    def test_manifest_symlink_escape_refused(self, runner, tmp_path):
        """A lib*-named symlink must not act as a deletion handle for the
        file it points at (resolution must stay a lib*/ld-* basename or a
        .debug/ child of the binary's directory)."""
        binary = self._make_binary(tmp_path)
        (binary.parent / "precious.txt").write_text("must survive")
        (binary.parent / "libx.so").symlink_to("precious.txt")
        manifest = self._make_manifest(binary, ["libx.so"])

        result = runner.invoke(cli, ["restore", str(binary)])
        assert result.exit_code == 0
        assert (binary.parent / "precious.txt").exists()
        assert not manifest.exists()


# ---------------------------------------------------------------------------
# 16. offline-by-default is enforced, not aspirational
# ---------------------------------------------------------------------------

def test_offline_default_blocks_real_sockets():
    """The conftest offline guard must fail any real connect in an unmarked
    test — against a LIVE local listener too, so an unmocked fetch cannot
    quietly reach archive.ubuntu.com / ftp.gnu.org on a networked machine."""
    import socket

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    client = socket.socket()
    try:
        with pytest.raises(OSError):
            client.connect(("127.0.0.1", srv.getsockname()[1]))
    finally:
        client.close()
        srv.close()
