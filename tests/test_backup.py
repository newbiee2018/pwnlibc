"""Tests for pwnlibc.backup — backup creation and restoration."""

import pytest

from pwnlibc.backup import create_backup, restore_backup


class TestCreateBackup:
    def test_basic(self, tmp_path):
        binary = tmp_path / "hello"
        binary.write_bytes(b"original")

        bak = create_backup(binary)
        assert bak.name == "hello.bak"
        assert bak.read_bytes() == b"original"

    def test_numbered_when_exists(self, tmp_path):
        binary = tmp_path / "hello"
        binary.write_bytes(b"v1")

        bak1 = create_backup(binary)
        assert bak1.name == "hello.bak"

        binary.write_bytes(b"v2")
        bak2 = create_backup(binary)
        assert bak2.name == "hello.bak.1"
        assert bak2.read_bytes() == b"v2"

    def test_multiple_numbered(self, tmp_path):
        binary = tmp_path / "hello"
        binary.write_bytes(b"v1")

        create_backup(binary)
        binary.write_bytes(b"v2")
        create_backup(binary)
        binary.write_bytes(b"v3")
        bak3 = create_backup(binary)
        assert bak3.name == "hello.bak.2"

    def test_preserves_original(self, tmp_path):
        binary = tmp_path / "hello"
        binary.write_bytes(b"keep me")
        create_backup(binary)
        assert binary.read_bytes() == b"keep me"


class TestRestoreBackup:
    def test_restore_basic(self, tmp_path):
        binary = tmp_path / "hello"
        binary.write_bytes(b"original")
        create_backup(binary)

        binary.write_bytes(b"modified")
        removed = restore_backup(binary)

        assert removed is not None
        assert binary.read_bytes() == b"original"
        assert not removed.exists()

    def test_restore_plain_bak_first(self, tmp_path):
        """When both .bak and .bak.1 exist, restore picks .bak first."""
        binary = tmp_path / "hello"
        binary.write_bytes(b"v1")
        create_backup(binary)  # -> .bak (contains v1)
        binary.write_bytes(b"v2")
        create_backup(binary)  # -> .bak.1 (contains v2)

        binary.write_bytes(b"v3")
        removed = restore_backup(binary)
        assert binary.read_bytes() == b"v1"
        assert removed.name == "hello.bak"

    def test_restore_falls_back_to_numbered(self, tmp_path):
        """When .bak is gone but .bak.1 exists, restore picks .bak.1."""
        binary = tmp_path / "hello"
        binary.write_bytes(b"v1")
        create_backup(binary)  # -> .bak
        binary.write_bytes(b"v2")
        create_backup(binary)  # -> .bak.1

        # Remove the plain .bak
        (tmp_path / "hello.bak").unlink()

        binary.write_bytes(b"v3")
        removed = restore_backup(binary)
        assert binary.read_bytes() == b"v2"
        assert removed.name == "hello.bak.1"

    def test_no_backup_returns_none(self, tmp_path):
        binary = tmp_path / "hello"
        binary.write_bytes(b"data")
        assert restore_backup(binary) is None

    def test_restore_removes_backup_file(self, tmp_path):
        binary = tmp_path / "hello"
        binary.write_bytes(b"original")
        bak = create_backup(binary)
        assert bak.exists()

        restore_backup(binary)
        assert not bak.exists()
