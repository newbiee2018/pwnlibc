"""Tests for pwnlibc.store — the install database (single source of truth).

CRUD contract: download/build/setup write records, remove/source-remove
delete them, list/verify read them. The database must survive corruption
and never break a command.
"""

import json

import pytest

from pwnlibc.store import DB_FILENAME, InstallRecord, InstallStore


def _rec(version="2.28", arch="amd64", variant="deb", **kw):
    return InstallRecord(version=version, arch=arch, variant=variant, **kw)


class TestStoreCrud:
    def test_upsert_get_roundtrip(self, tmp_path):
        store = InstallStore(tmp_path)
        store.upsert(_rec(mirror="old-ubuntu", filename="libc6_2.28-0ubuntu1_amd64.deb",
                          full_id="2.28-0ubuntu1_amd64", has_dbg=True))
        store.save()

        r = InstallStore(tmp_path).get("2.28", "amd64", "deb")
        assert r is not None
        assert r.mirror == "old-ubuntu"
        assert r.full_id == "2.28-0ubuntu1_amd64"
        assert r.has_dbg is True
        assert r.installed_at  # stamped automatically

    def test_upsert_replaces_same_key(self, tmp_path):
        store = InstallStore(tmp_path)
        store.upsert(_rec(mirror="ubuntu"))
        store.upsert(_rec(mirror="old-ubuntu"))
        store.save()
        assert len(InstallStore(tmp_path).all()) == 1
        assert InstallStore(tmp_path).get("2.28", "amd64", "deb").mirror == "old-ubuntu"

    def test_remove_filters(self, tmp_path):
        store = InstallStore(tmp_path)
        store.upsert(_rec(arch="amd64"))
        store.upsert(_rec(arch="i686"))
        store.upsert(_rec(arch="amd64", variant="built"))
        assert store.remove("2.28", arch="amd64", variant="deb") == 1
        store.save()

        fresh = InstallStore(tmp_path)
        assert fresh.get("2.28", "i686", "deb") is not None
        assert fresh.get("2.28", "amd64", "built") is not None
        assert fresh.get("2.28", "amd64", "deb") is None
        assert fresh.remove("2.28") == 2  # everything for the version

    def test_remove_nonexistent_is_zero(self, tmp_path):
        assert InstallStore(tmp_path).remove("9.9") == 0

    def test_sources(self, tmp_path):
        store = InstallStore(tmp_path)
        store.add_source("2.31")
        store.add_source("2.31")  # idempotent
        store.save()
        fresh = InstallStore(tmp_path)
        assert fresh.has_source("2.31")
        assert fresh.sources() == {"2.31"}
        assert fresh.remove_source("2.31") is True
        assert fresh.remove_source("2.31") is False

    def test_save_is_atomic_no_tmp_left(self, tmp_path):
        store = InstallStore(tmp_path)
        store.upsert(_rec())
        store.save()
        assert not (tmp_path / (DB_FILENAME + ".tmp")).exists()
        assert (tmp_path / DB_FILENAME).exists()

    def test_missing_file_is_empty(self, tmp_path):
        store = InstallStore(tmp_path)
        assert store.all() == []
        assert store.get("2.28", "amd64", "deb") is None


class TestStoreRobustness:
    def test_corrupt_json_backed_up_and_ignored(self, tmp_path):
        (tmp_path / DB_FILENAME).write_text("{ not json !!!")
        store = InstallStore(tmp_path)
        assert store.all() == []
        store.upsert(_rec())
        store.save()
        assert (tmp_path / (DB_FILENAME + ".bak")).exists()
        assert InstallStore(tmp_path).get("2.28", "amd64", "deb") is not None

    def test_unknown_fields_tolerated(self, tmp_path):
        (tmp_path / DB_FILENAME).write_text(json.dumps({
            "version": 1,
            "installs": [{"version": "2.31", "arch": "amd64", "variant": "deb",
                          "mirror": "ubuntu", "future_field": "x"}],
            "sources": [],
        }))
        r = InstallStore(tmp_path).get("2.31", "amd64", "deb")
        assert r is not None and r.mirror == "ubuntu"

    def test_save_to_unwritable_dir_is_silent(self, tmp_path):
        store = InstallStore(tmp_path / "nonexistent-root" / "sub")
        store.upsert(_rec())
        store.save()  # must not raise
        # Note: mkdir(parents=True) actually succeeds here; the guarantee is
        # that a genuinely failing save never raises.

    def test_bad_record_entries_skipped(self, tmp_path):
        (tmp_path / DB_FILENAME).write_text(json.dumps({
            "installs": [{"version": "2.31"}, {"garbage": True}],
            "sources": [],
        }))
        store = InstallStore(tmp_path)
        assert store.all() == []


class TestStoreWiring:
    """CRUD paths maintain the database."""

    def test_download_glibc_writes_record(self, tmp_path):
        from unittest.mock import patch
        from pwnlibc.downloader import DebPackage, download_glibc

        pkg = DebPackage(version="2.28", full_id="2.28-0ubuntu1_amd64", arch="amd64",
                         filename="libc6_2.28-0ubuntu1_amd64.deb",
                         dbg_filename="libc6-dbg_2.28-0ubuntu1_amd64.deb",
                         mirror="old-ubuntu")
        with patch("pwnlibc.downloader._download_file"), \
             patch("pwnlibc.downloader._extract_deb"), \
             patch("pwnlibc.downloader._extract_dbg_deb"), \
             patch("pwnlibc.downloader._expected_sha256", return_value=None):
            download_glibc(pkg, tmp_path, mirror="old-ubuntu")

        r = InstallStore(tmp_path).get("2.28", "amd64", "deb")
        assert r is not None
        assert r.mirror == "old-ubuntu"
        assert r.filename == "libc6_2.28-0ubuntu1_amd64.deb"
        assert r.has_dbg is True

    def test_download_glibc_no_dbg_records_it(self, tmp_path):
        from unittest.mock import patch
        from pwnlibc.downloader import DebPackage, download_glibc

        pkg = DebPackage(version="2.28", full_id="2.28-0ubuntu1_amd64", arch="amd64",
                         filename="libc6_2.28-0ubuntu1_amd64.deb",
                         dbg_filename="libc6-dbg_2.28-0ubuntu1_amd64.deb")
        with patch("pwnlibc.downloader._download_file"), \
             patch("pwnlibc.downloader._extract_deb"), \
             patch("pwnlibc.downloader._expected_sha256", return_value=None):
            download_glibc(pkg, tmp_path, include_dbg=False, mirror="old-ubuntu")

        assert InstallStore(tmp_path).get("2.28", "amd64", "deb").has_dbg is False

    def test_discover_adopts_unrecorded_installs(self, tmp_path):
        from tests.conftest import _build_minimal_elf
        from pwnlibc.glibc import discover_installed

        lib = tmp_path / "2.27" / "amd64" / "lib"
        lib.mkdir(parents=True)
        _build_minimal_elf(lib / "libc.so.6")
        _build_minimal_elf(lib / "ld-linux-x86-64.so.2")

        installs = discover_installed(tmp_path)
        assert len(installs) == 1
        assert installs[0].origin is None  # adopted, unknown origin

        r = InstallStore(tmp_path).get("2.27", "amd64", "deb")
        assert r is not None and r.mirror is None

        # Second discovery now enriches from the adopted record
        installs2 = discover_installed(tmp_path)
        assert installs2[0].origin is None and installs2[0].installed_at

    def test_discover_enriches_from_record(self, tmp_path):
        from tests.conftest import _build_minimal_elf
        from pwnlibc.glibc import discover_installed

        lib = tmp_path / "2.28" / "amd64" / "lib"
        lib.mkdir(parents=True)
        _build_minimal_elf(lib / "libc.so.6")
        _build_minimal_elf(lib / "ld-linux-x86-64.so.2")

        store = InstallStore(tmp_path)
        store.upsert(_rec(mirror="old-ubuntu"))
        store.save()

        installs = discover_installed(tmp_path)
        assert installs[0].origin == "old-ubuntu"

    def test_remove_command_deletes_records(self, tmp_path):
        from click.testing import CliRunner
        from tests.conftest import _build_minimal_elf
        from pwnlibc.cli import cli

        lib = tmp_path / "2.28" / "amd64" / "lib"
        lib.mkdir(parents=True)
        _build_minimal_elf(lib / "libc.so.6")
        _build_minimal_elf(lib / "ld-linux-x86-64.so.2")

        store = InstallStore(tmp_path)
        store.upsert(_rec(mirror="old-ubuntu"))
        store.upsert(_rec(arch="i686", mirror="old-ubuntu"))
        store.save()

        runner = CliRunner()
        res = runner.invoke(cli, ["--glibc-dir", str(tmp_path),
                                  "remove", "2.28", "--arch", "amd64"])
        assert res.exit_code == 0

        fresh = InstallStore(tmp_path)
        assert fresh.get("2.28", "amd64", "deb") is None
        assert fresh.get("2.28", "i686", "deb") is not None

    def test_verify_uses_recorded_origin_without_scraping(self, tmp_path):
        from unittest.mock import patch
        from click.testing import CliRunner
        from tests.conftest import _build_minimal_elf
        from pwnlibc.cli import cli

        lib = tmp_path / "2.28" / "amd64" / "lib"
        lib.mkdir(parents=True)
        _build_minimal_elf(lib / "libc.so.6")
        _build_minimal_elf(lib / "ld-linux-x86-64.so.2")

        store = InstallStore(tmp_path)
        store.upsert(_rec(mirror="old-ubuntu", filename="libc6_2.28-0ubuntu1_amd64.deb",
                          full_id="2.28-0ubuntu1_amd64"))
        store.save()

        with patch("pwnlibc.cli._scrape_mirrors") as mock_scrape, \
             patch("pwnlibc.cli.verify_against_deb",
                   return_value=[("libc.so.6", "MATCH", "x")]) as mock_v:
            res = CliRunner().invoke(cli, ["--glibc-dir", str(tmp_path), "verify"])
        assert res.exit_code == 0
        mock_scrape.assert_not_called()  # recorded provenance suffices
        assert mock_v.call_args.kwargs["mirror"] == "old-ubuntu"
        assert mock_v.call_args.args[0].filename == "libc6_2.28-0ubuntu1_amd64.deb"

    def test_list_shows_origin_column(self, tmp_path):
        from click.testing import CliRunner
        from tests.conftest import _build_minimal_elf
        from pwnlibc.cli import cli

        lib = tmp_path / "2.28" / "amd64" / "lib"
        lib.mkdir(parents=True)
        _build_minimal_elf(lib / "libc.so.6")
        _build_minimal_elf(lib / "ld-linux-x86-64.so.2")

        store = InstallStore(tmp_path)
        store.upsert(_rec(mirror="old-ubuntu"))
        store.save()

        res = CliRunner().invoke(cli, ["--glibc-dir", str(tmp_path), "list"])
        assert res.exit_code == 0
        assert "Origin" in res.output
        assert "old-ubuntu" in res.output
