import os, getpass
from pathlib import Path
from pwnlibc.ownership import chown_tree, invoking_uid_gid

def test_invoking_uid_gid_none_without_sudo(monkeypatch):
    monkeypatch.delenv("SUDO_USER", raising=False)
    assert invoking_uid_gid() is None

def test_invoking_uid_gid_none_when_not_root(monkeypatch):
    monkeypatch.setenv("SUDO_USER", getpass.getuser())
    monkeypatch.setattr("pwnlibc.ownership.os.geteuid", lambda: 1000)
    assert invoking_uid_gid() is None

def test_invoking_uid_gid_under_sudo(monkeypatch):
    monkeypatch.setenv("SUDO_USER", getpass.getuser())
    monkeypatch.setattr("pwnlibc.ownership.os.geteuid", lambda: 0)
    assert invoking_uid_gid() == (os.getuid(), os.getgid())

def test_chown_tree_noop_unprivileged(tmp_path, monkeypatch):
    monkeypatch.setattr("pwnlibc.ownership.os.geteuid", lambda: 1000)
    assert chown_tree(tmp_path) == 0

def test_chown_tree_chowns_files_dirs_symlinks(tmp_path, monkeypatch):
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "libc.so.6").write_bytes(b"x")
    (tmp_path / "lib" / "link").symlink_to("libc.so.6")
    monkeypatch.setenv("SUDO_USER", getpass.getuser())
    monkeypatch.setattr("pwnlibc.ownership.os.geteuid", lambda: 0)
    changed = chown_tree(tmp_path)
    assert changed == 4  # tmp_path, lib, libc.so.6, link
    assert (tmp_path / "lib" / "libc.so.6").stat().st_uid == os.getuid()
