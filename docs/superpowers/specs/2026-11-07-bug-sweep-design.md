# pwnlibc Bug Sweep — Design (brainstorm conclusions, 2026-11-07)

**Intent:** mature the existing tool. No new user-facing capability except an
opt-in signature check. The project's purpose stays: let CTF pwners swap a
binary's libc for a debug-symboled, *version-like* glibc to study heap
mechanics — byte-identity with the remote libc is a non-goal.

**Scope settled in brainstorm:**

1. **Ownership repair (sudo model).** Keep `sudo pwnlibc ...` working; after
   privileged writes, chown everything created under the glibc dir back to the
   `SUDO_USER`. `remove` catches `PermissionError` (legacy root-owned files)
   and prints the existing chown hint instead of a traceback.
2. **Suite-map refresh + decay warning.** Versions absent from `_UBUNTU_SUITES`/`_DEBIAN_SUITES`
   currently skip SHA256 verification silently. Refresh the tables with
   live-verified current releases — `"2.42": "questing"` (Ubuntu 25.10),
   `"2.43": "resolute"` (Ubuntu 26.04), confirmed 2026-11-07 via Launchpad —
   and re-verify the Debian side for anything newer than trixie during
   execution. Then warn once per unmapped version on stderr; keep downloading.
   Dynamic suite derivation stays a later feature.
3. **Full-lib-dir verify.** `verify` compares every file of the reference deb's
   lib dir (recursively, symlink targets compared as links, `.debug/` ignored)
   instead of 4 hand-picked files, so "All N files verified OK" means what it
   says.
4. **Opt-in signature check.** `--verify-signatures` (+ `--keyring`) on
   `download`, `download-all`, `verify`: after the run, check each used
   Packages index against the GPG-signed `InRelease`/`Release` (gpgv). Off by
   default. Missing gpgv/keyring degrades to a warning; a failed check exits 1.
5. **Builder fixes.** Reuse `<version>/source/` when it holds a real source
   tree (has `configure`) instead of re-downloading from ftp.gnu.org; make the
   30-min `make` timeout configurable (`--timeout`, 0 = unlimited).
6. **`download-all --source`** opt-in flag (default off); `download` keeps
   source on by default. Shared helper, no silent default changes.
7. **`--version` flag** on the CLI group from `pwnlibc.__version__`.
8. **Retry transient failures in `check_source_available`** HEAD checks via
   the downloader's `_retry_transient`.
9. **`download latest`.** The literal argument `latest` resolves to the newest
   glibc available per target arch from the arch's own mirror chain
   (family-safe: existing chain filtering and `_pick_best` rules), announced
   with a resolution line, then downloads like an explicit version. Mixes with
   explicit versions; an arch with no packages errors per-arch without
   aborting the rest.
10. **Bug-hunt review pass.** After the fixes, a structured review sweeps for
    further bugs (failure paths, cross-command invariants, robustness,
    Python-3.8 floor, the brainstorm long-tail). Findings are triaged by rule:
    FIX-NOW (≤ ~20 lines + offline regression test, own commit), FOLLOW-UP
    (appended to this spec), WONTFIX (reasoned). Deliverable:
    `docs/superpowers/reviews/2026-11-07-bug-sweep-review.md`.

**Non-goals (later phases):** `identify` command (read version banner from a
provided libc), symbol-offset fingerprinting (rejected permanently), dynamic
suite derivation, signatures on by default, cache/disk-management commands,
`build latest` / `available latest` variants (only `download` gets the token
for now).

**Approach note:** each item rides the existing architecture — no new state,
filesystem stays the single source of truth, one new module per genuinely new
concern (`ownership.py`, `signatures.py`).
