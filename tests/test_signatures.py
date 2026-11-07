"""Tests for pwnlibc.signatures — opt-in Release/InRelease verification.

Fully offline: _fetch_bytes, shutil.which and subprocess.run are patched,
and the InRelease fixture is built from real hashlib.sha256 values of the
fixture index bytes (no magic constants).
"""

import hashlib
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pwnlibc.signatures import (
    default_keyring,
    parse_release_sha256,
    verify_index_signature,
)

# The cached Packages index is stored exactly as fetched (compressed), but
# only its raw bytes are hashed here — plain text keeps the fixture honest.
INDEX_XZ = (
    b"Package: libc6\n"
    b"Filename: pool/main/g/glibc/libc6_2.31-0ubuntu9.18_amd64.deb\n"
    b"SHA256: " + hashlib.sha256(b"good-deb").hexdigest().encode() + b"\n"
)
INDEX_GZ = b"gz twin of the same stanzas"


def _inrelease_text(index_xz: bytes = INDEX_XZ,
                    index_gz: bytes = INDEX_GZ) -> str:
    """A realistic cleartext-signed InRelease with a live SHA256 block."""
    entries = [
        ("main/binary-amd64/Packages.xz", index_xz),
        ("main/binary-amd64/Packages.gz", index_gz),
        ("main/binary-i386/Packages.xz", b"i386 index bytes"),
    ]
    sha_lines = "\n".join(
        f" {hashlib.sha256(data).hexdigest()} {len(data)} {path}"
        for path, data in entries
    )
    return f"""-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Origin: Ubuntu
Label: Ubuntu
Suite: focal-updates
Codename: focal
Architectures: amd64 i386
Components: main restricted universe multiverse
Description: Ubuntu Focal Updates

MD5Sum:
 0123456789abcdef0123456789abcdef 1234 main/binary-amd64/Packages.xz

SHA256:
{sha_lines}

-----BEGIN PGP SIGNATURE-----
iQEcBAABCgAGBQJfakefakefake
-----END PGP SIGNATURE-----
"""


def _seed_index(cache_dir: Path, suite: str = "focal-updates",
                deb_arch: str = "amd64", name: str = "Packages.xz",
                data: bytes = INDEX_XZ) -> Path:
    index_file = cache_dir / "indices" / "ubuntu" / suite / deb_arch / name
    index_file.parent.mkdir(parents=True, exist_ok=True)
    index_file.write_bytes(data)
    return index_file


# ---------------------------------------------------------------------------
# parse_release_sha256
# ---------------------------------------------------------------------------

class TestParseReleaseSha256:
    def test_exact_path(self):
        text = _inrelease_text()
        want = hashlib.sha256(INDEX_XZ).hexdigest()
        assert parse_release_sha256(text, "main/binary-amd64/Packages.xz") == want

    def test_dot_slash_prefixed_entry_matched_by_bare_path(self):
        text = _inrelease_text().replace(
            " main/binary-amd64/Packages.xz", " ./main/binary-amd64/Packages.xz",
            1,
        )
        want = hashlib.sha256(INDEX_XZ).hexdigest()
        assert parse_release_sha256(text, "main/binary-amd64/Packages.xz") == want

    def test_absent_path_returns_none(self):
        assert parse_release_sha256(_inrelease_text(), "main/binary-ppc64el/Packages.xz") is None

    def test_no_sha256_block_returns_none(self):
        assert parse_release_sha256("Origin: Ubuntu\n", "main/binary-amd64/Packages.xz") is None


# ---------------------------------------------------------------------------
# default_keyring
# ---------------------------------------------------------------------------

class TestDefaultKeyring:
    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("PWNLIBC_KEYRING", "/custom/kr.gpg")
        assert default_keyring("ubuntu") == Path("/custom/kr.gpg")

    def test_unknown_family_returns_none(self, monkeypatch):
        monkeypatch.delenv("PWNLIBC_KEYRING", raising=False)
        assert default_keyring("no-such-mirror") is None


# ---------------------------------------------------------------------------
# verify_index_signature
# ---------------------------------------------------------------------------

class TestVerifyIndexSignature:
    def _no_gpgv(self):
        return patch("pwnlibc.signatures.shutil.which", return_value=None)

    def test_ok_without_gpgv(self, tmp_path):
        """gpgv absent: index hash still checked, signature degrades to a note."""
        _seed_index(tmp_path)
        with patch("pwnlibc.signatures._fetch_bytes",
                   return_value=_inrelease_text().encode()), self._no_gpgv():
            check = verify_index_signature("ubuntu", "focal-updates", "amd64", tmp_path)
        assert check.index_file is not None
        assert check.index_file.name == "Packages.xz"
        assert check.index_sha_ok is True
        assert check.signature_ok is None
        assert any("gnupg" in n for n in check.notes)

    def test_detects_tampered_index(self, tmp_path):
        """Cached index bytes altered after the Release was signed -> False."""
        _seed_index(tmp_path, data=INDEX_XZ + b"tampered\n")
        with patch("pwnlibc.signatures._fetch_bytes",
                   return_value=_inrelease_text().encode()), self._no_gpgv():
            check = verify_index_signature("ubuntu", "focal-updates", "amd64", tmp_path)
        assert check.index_file is not None
        assert check.index_sha_ok is False

    def test_no_cached_index(self, tmp_path):
        """Nothing cached: nothing to check, both verdicts None, note set."""
        with patch("pwnlibc.signatures._fetch_bytes") as mock_fetch, self._no_gpgv():
            check = verify_index_signature("ubuntu", "focal-updates", "amd64", tmp_path)
        assert check.index_file is None
        assert check.index_sha_ok is None
        assert check.signature_ok is None
        assert check.notes
        mock_fetch.assert_not_called()  # nothing to hash against

    def test_release_fetch_failure_degrades_to_note(self, tmp_path):
        """Both InRelease and Release unreachable: notes, never an exception."""
        _seed_index(tmp_path)
        with patch("pwnlibc.signatures._fetch_bytes",
                   side_effect=urllib.error.URLError("down")), self._no_gpgv():
            check = verify_index_signature("ubuntu", "focal-updates", "amd64", tmp_path)
        assert check.index_sha_ok is None
        assert check.signature_ok is None
        assert any("could not fetch" in n for n in check.notes)

    def test_release_fallback_when_inrelease_404(self, tmp_path):
        """InRelease missing -> detached Release + Release.gpg are used."""
        _seed_index(tmp_path)
        release = _inrelease_text().replace("-----BEGIN PGP SIGNED MESSAGE-----\n", "")

        def fetch(url):
            if url.endswith("/InRelease"):
                raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
            if url.endswith("/Release"):
                return release.encode()
            if url.endswith("/Release.gpg"):
                return b"-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n"
            raise AssertionError(f"unexpected url {url}")

        keyring = tmp_path / "kr.gpg"
        keyring.write_bytes(b"keyring")
        with patch("pwnlibc.signatures._fetch_bytes", side_effect=fetch), \
             patch("pwnlibc.signatures.shutil.which", return_value="/usr/bin/gpgv"), \
             patch("pwnlibc.signatures.subprocess.run",
                   MagicMock(return_value=MagicMock(returncode=0))) as mock_run:
            check = verify_index_signature("ubuntu", "focal-updates", "amd64",
                                           tmp_path, keyring)
        assert check.index_sha_ok is True
        assert check.signature_ok is True
        # detached verification: Release.gpg comes before Release
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "gpgv"
        assert cmd[-2].endswith("Release.gpg")
        assert cmd[-1].endswith("Release")

    def test_missing_entry_in_release_is_skip_not_fail(self, tmp_path):
        """Release without an entry for the cached index: None + note."""
        _seed_index(tmp_path)
        # retarget BOTH the MD5Sum and SHA256 entries (the md5 line would
        # otherwise absorb a single replace)
        text = _inrelease_text().replace(
            "main/binary-amd64/Packages.xz", "main/binary-other/Packages.xz")
        with patch("pwnlibc.signatures._fetch_bytes",
                   return_value=text.encode()), self._no_gpgv():
            check = verify_index_signature("ubuntu", "focal-updates", "amd64", tmp_path)
        assert check.index_sha_ok is None
        assert any("no SHA256 entry" in n for n in check.notes)

    def test_gpgv_verdicts(self, tmp_path):
        """returncode 0 -> True; non-zero -> False."""
        _seed_index(tmp_path)
        keyring = tmp_path / "kr.gpg"
        keyring.write_bytes(b"keyring")
        for code, expected in ((0, True), (1, False)):
            with patch("pwnlibc.signatures._fetch_bytes",
                       return_value=_inrelease_text().encode()), \
                 patch("pwnlibc.signatures.shutil.which",
                       return_value="/usr/bin/gpgv"), \
                 patch("pwnlibc.signatures.subprocess.run",
                       MagicMock(return_value=MagicMock(returncode=code))):
                check = verify_index_signature("ubuntu", "focal-updates", "amd64",
                                               tmp_path, keyring)
            assert check.signature_ok is expected, f"returncode={code}"

    def test_missing_keyring_degrades_to_note(self, tmp_path):
        """gpgv present but no usable keyring: signature_ok None + hint."""
        _seed_index(tmp_path)
        with patch("pwnlibc.signatures._fetch_bytes",
                   return_value=_inrelease_text().encode()), \
             patch("pwnlibc.signatures.shutil.which",
                   return_value="/usr/bin/gpgv"), \
             patch("pwnlibc.signatures.default_keyring", return_value=None), \
             patch("pwnlibc.signatures.subprocess.run") as mock_run:
            check = verify_index_signature("ubuntu", "focal-updates", "amd64", tmp_path)
        assert check.signature_ok is None
        assert any("keyring" in n for n in check.notes)
        mock_run.assert_not_called()
