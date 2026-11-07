"""Opt-in verification of cached dists indices against signed Release files.

`downloader` already checks every downloaded .deb against the SHA256 in a
dists Packages index. This module adds the layer above it: after a run,
confirm that the cached Packages index itself matches the digest listed in
the suite's GPG-signed InRelease (or Release + Release.gpg) file, verified
with gpgv against the distro archive keyring.

Everything here is best-effort: network failures, a missing gpgv, or a
missing keyring degrade to notes on the returned IndexCheck and never
raise. Only an outright mismatch (index_sha_ok False / signature_ok False)
is a verdict the caller turns into a failure exit.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import MIRROR_FAMILY
from .downloader import _fetch_bytes, _mirror_dists_base, sha256_file

_UBUNTU_KEYRING = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
_DEBIAN_KEYRING = Path("/usr/share/keyrings/debian-archive-keyring.gpg")


@dataclass
class IndexCheck:
    """Result of checking one suite's cached index.

    None means "not checked" (no cached index, no Release entry, gpgv or
    keyring missing, fetch failed); True/False are actual verdicts. notes
    carries the human-readable reason for every skip.
    """

    suite: str
    index_file: Path | None
    index_sha_ok: bool | None
    signature_ok: bool | None
    notes: list[str]


def default_keyring(mirror: str) -> Path | None:
    """Trusted archive keyring for the mirror's distro family, or None.

    $PWNLIBC_KEYRING overrides everything (returned verbatim — a bad path
    surfaces later as a skipped check with the path in the note); otherwise
    the distro's archive keyring, but only when actually installed.
    """
    env = os.environ.get("PWNLIBC_KEYRING", "").strip()
    if env:
        return Path(os.path.expanduser(env))
    family = MIRROR_FAMILY.get(mirror)
    if family == "ubuntu":
        candidate = _UBUNTU_KEYRING
    elif family == "debian":
        candidate = _DEBIAN_KEYRING
    else:
        return None
    return candidate if candidate.is_file() else None


def parse_release_sha256(release_text: str, rel_path: str) -> str | None:
    """Hex digest from the SHA256: block for rel_path, or None.

    Entries are the indented "<digest> <size> <path>" lines that follow the
    SHA256: field; a leading "./" on the entry path is stripped before the
    comparison. Any non-indented line ends the block (the next field, or
    the PGP signature armor of an InRelease file).
    """
    want = rel_path[2:] if rel_path.startswith("./") else rel_path
    in_block = False
    for line in release_text.splitlines():
        if not line.strip():
            continue
        indented = line[0] in (" ", "\t")
        if not indented:
            in_block = line.split(":", 1)[0].strip() == "SHA256"
            continue
        if not in_block:
            continue
        parts = line.split()
        if len(parts) >= 3:
            path = parts[2]
            entry = path[2:] if path.startswith("./") else path
            if entry == want:
                return parts[0].lower()
    return None


def verify_index_signature(mirror: str, suite: str, deb_arch: str,
                           cache_dir: Path,
                           keyring: Path | None = None) -> IndexCheck:
    """Check one suite's cached Packages index against the signed Release.

    The first existing cached index (Packages.xz, then Packages.gz) is
    hashed and compared with the SHA256 the suite's InRelease (or detached
    Release + Release.gpg) lists for it; the Release file itself is then
    verified with gpgv against the keyring. Never raises.
    """
    notes: list[str] = []

    index_dir = Path(cache_dir) / "indices" / mirror / suite / deb_arch
    index_file: Path | None = None
    for name in ("Packages.xz", "Packages.gz"):
        candidate = index_dir / name
        if candidate.is_file():
            index_file = candidate
            break
    if index_file is None:
        notes.append(
            f"no cached Packages index for {suite}/{deb_arch} — "
            f"nothing to check (download again to cache it)"
        )
        return IndexCheck(suite, None, None, None, notes)

    base = _mirror_dists_base(mirror)
    release_bytes: bytes | None = None
    sig_bytes: bytes | None = None
    detached = False
    try:
        release_bytes = _fetch_bytes(f"{base}/dists/{suite}/InRelease")
    except Exception:
        try:
            release_bytes = _fetch_bytes(f"{base}/dists/{suite}/Release")
            sig_bytes = _fetch_bytes(f"{base}/dists/{suite}/Release.gpg")
            detached = True
        except Exception as exc:
            notes.append(f"could not fetch InRelease/Release for {suite}: {exc}")
            return IndexCheck(suite, index_file, None, None, notes)

    release_text = release_bytes.decode("utf-8", errors="replace")
    rel_path = f"main/binary-{deb_arch}/{index_file.name}"
    expected = parse_release_sha256(release_text, rel_path)
    if expected is None:
        notes.append(f"Release has no SHA256 entry for {rel_path}")
        index_sha_ok: bool | None = None
    else:
        index_sha_ok = sha256_file(index_file) == expected

    signature_ok: bool | None = None
    resolved_keyring = keyring if keyring is not None else default_keyring(mirror)
    if shutil.which("gpgv") is None:
        notes.append(
            "gpgv not found — sudo apt install gnupg "
            "(Release signature not checked)"
        )
    elif resolved_keyring is None or not Path(resolved_keyring).is_file():
        notes.append(
            f"no trusted keyring for {mirror} — install the distro "
            f"archive-keyring package or pass --keyring PATH"
        )
    else:
        signature_ok = _gpgv_check(resolved_keyring, release_bytes, sig_bytes,
                                   detached, notes)

    return IndexCheck(suite, index_file, index_sha_ok, signature_ok, notes)


def _gpgv_check(keyring: Path, release_bytes: bytes, sig_bytes: bytes | None,
                detached: bool, notes: list[str]) -> bool | None:
    """Run gpgv on the fetched Release data written to a tempdir.

    Cleartext InRelease: `gpgv --keyring <kr> <file>`; detached:
    `gpgv --keyring <kr> Release.gpg Release`. Returns None (with a note)
    when gpgv cannot run at all.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        try:
            if detached:
                release = tmp / "Release"
                sig = tmp / "Release.gpg"
                release.write_bytes(release_bytes)
                sig.write_bytes(sig_bytes)
                cmd = ["gpgv", "--keyring", str(keyring), str(sig), str(release)]
            else:
                signed = tmp / "InRelease"
                signed.write_bytes(release_bytes)
                cmd = ["gpgv", "--keyring", str(keyring), str(signed)]
            proc = subprocess.run(cmd, capture_output=True)
        except OSError as exc:
            notes.append(f"gpgv could not run: {exc}")
            return None
    if proc.returncode != 0:
        detail = ""
        if isinstance(proc.stderr, bytes):
            detail = proc.stderr.decode("utf-8", errors="replace").strip()
        if detail:
            notes.append(
                f"gpgv rejected the Release signature: {detail.splitlines()[-1]}")
        else:
            notes.append("gpgv rejected the Release signature")
    return proc.returncode == 0
