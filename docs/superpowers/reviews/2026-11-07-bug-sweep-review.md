# Bug-hunt review pass — 2026-11-07 bug sweep, Task 10

Sweep of the codebase as it stands after Task 9, hunting what the plan missed.
Five audit passes were run (failure paths per command, cross-command
invariants, robustness grep, Python-3.8 floor, brainstorm long-tail), plus
re-triage of every Minor/deferred finding parked in the progress ledger by the
per-task reviews (Tasks 1-9), including the two seeded audit items.

Triage rule (binding): **FIX-NOW** iff the fix is ≤ ~20 lines and
offline-testable (TDD, one commit per finding); **FOLLOW-UP** for larger or
speculative work (appended to the spec's follow-up list); **WONTFIX** for
intended behavior, with a one-line reason.

Empirical anchor for the offline findings: running the default suite with all
network blocked (`https_proxy=http://127.0.0.1:9`) made exactly one test fail
and inflated the run from 99 s to 357 s — proving real network I/O inside the
"offline by default" suite (one test whose assertion *depends* on the network,
ten more that quietly fetch). After the fixes below, the full default suite
runs green in ~1.4 s with sockets and DNS disabled process-wide.

## Findings

Status legend: FIX-NOW = fixed here with a regression test; FOLLOW-UP =
appended to the spec; WONTFIX = intended behavior (reason inline).

| # | Severity | Area | Finding | Status |
|---|----------|------|---------|--------|
| 1 | Major | tests | SEED: `test_download_default_includes_source` does real network I/O (unmocked `check_source_available` HEAD) — the only default-suite test that *fails* offline; flaked once during Task 5. | FIX-NOW (7c87119) |
| 2 | Major | tests | The offline-by-default policy was unenforced: 10 more default-suite tests quietly hit archive.ubuntu.com / ftp.gnu.org via unmocked `_fetch_bytes` index fetches and `check_source_available` HEADs (54 s of retry stalls each on a dead network). | FIX-NOW (aaa81c4): autouse socket/DNS guard in conftest, exempting `network`-marked tests; suite now provably offline. |
| 3 | Major | cli/build | SEED: `build` (and `patch`'s build-from-source prompt) gates on a real `check_source_available` HEAD before calling `build_glibc`, so fully-offline builds with a local source tree are blocked at the CLI layer even though Task 5 made `build_glibc` reuse local source. | FIX-NOW (8c2823e): skip the remote check when `_local_source_dir` finds a usable tree. |
| 4 | Major | cli/download-all | `download-all` exits 0 even when *every* download failed (`if not sig_ok` only), unlike `download` — provisioning scripts cannot detect total failure. | FIX-NOW (9bd2489): exit 1 when nothing succeeded; partial failure still exits 0. |
| 5 | Minor | cli/source | `source remove` has no PermissionError handling: root-owned source (from a past `sudo build`) crashes with a raw traceback, while `remove` prints the chown hint. | FIX-NOW (9a50cef). |
| 6 | Minor | cli/download | `_maybe_download_source` violates its documented "warn (never raise)" contract: the availability check and the source-dir scan sit outside its try, so an exception crashes `download` and mislabels a *successful* deb install as "failed" in `download-all`. | FIX-NOW (5b58692). |
| 7 | Minor | cli/download | Duplicate version tokens (`download 2.31 2.31`, `download latest latest`) download and announce twice; dedupe only applied to explicit versions when `latest` was present. | FIX-NOW (5513372): order-preserving dedupe of tokens up front. |
| 8 | Minor | cli/restore | A tampered `<binary>.patched.manifest` could name *any* file in the binary's directory (flag.txt, notes.md) and `restore` would delete it — the traversal guard only protected "elsewhere". Challenge dirs are untrusted input for this tool. | FIX-NOW (0209a76): deletions restricted to names a copy-mode patch can create (`lib*`, `ld-*`, `.debug/*`). |
| 9 | Minor | cli/signatures | A signature-only `--verify-signatures` FAIL printed the "cached index was re-fetched and still disagrees" hint — false for a gpgv rejection, where no index was re-fetched. | FIX-NOW (da2b415): distinct hint per failure kind. |
| 10 | Minor | tests | `test_unknown_version_warns_once_on_stderr` is non-hermetic: `_unknown_suite_versions` is module-global state never reset, so a prior test announcing 2.99 suppresses the warning (fails under session repeats). | FIX-NOW (45d63ad): monkeypatch-reset in the test. |
| 11 | Minor | downloader | Network death between the libc6 and libc6-dbg downloads leaves a partial install (libc extracted, no `.debug`); re-download heals, `list` shows it as no-debug. | FOLLOW-UP (extract-to-temp + swap, like builder's staged install). |
| 12 | Minor | cli/patch | In the build-from-source prompt path, a missing `patchelf` is discovered only *after* a full source build completes (BUILD_DEPS doesn't include it; it's a patch dep). The built variant survives, but the order confuses. | FOLLOW-UP (early patchelf check in `_prompt_no_debug`). |
| 13 | Minor | cli/setup | Per-archive `OSError` (disk full, permissions changing mid-run) crashes the whole `setup` command with a traceback; only "unexpected layout" is handled per-archive. | FOLLOW-UP (per-archive guard + continue). |
| 14 | Minor | docs/setup | `setup` silently skips colliding installed variants; neither the command docstring nor the README documents the skip semantics. | FOLLOW-UP (doc pass). |
| 15 | Minor | downloader/signatures | Refresh edge: a fresh `.gz` matching the signed Release while the cached `.xz` is stale leaves the stale `.xz` preferred — convergent but wasteful (re-fetch on every run). | FOLLOW-UP (Task 4 deferred). |
| 16 | Minor | signatures | InRelease-404 + Release-ok + Release.gpg-404 skips the hash compare entirely even though the (unsigned) Release lists digest entries. | FOLLOW-UP (Task 4 deferred). |
| 17 | Minor | downloader | ESM pockets (e.g. focal-esm) are absent from `_candidate_suites`; ESM-only revisions download without SHA256 verification, announced only as a settled miss. Dynamic suite derivation is a spec non-goal. | FOLLOW-UP. |
| 18 | Minor | cli | `_where_is_version` re-scrapes every untried mirror a second time to explain a missing version — full double scrape on the miss path. | FOLLOW-UP (latency; could reuse the first scrape). |
| 19 | Minor | cli/patch | `_do_patch`'s source hint does up to 9 HEAD probes (3 formats × 3 retries with backoff) just to print a dim hint line — up to ~13.5 s stall on a dead network. | FOLLOW-UP (probe policy: skip, cache, or async). |
| 20 | Minor | builder | `check_source_available` surfaces "unreachable" and "absent" identically as None (pre-existing contract). | FOLLOW-UP (needs an API change; Task 9 deferred). |
| 21 | Minor | cli | `download`'s unwritable-`.cache` failure prints a bare per-file "Failed" without the chown hint the `remove` path gives. | WONTFIX — cosmetic message; the deb download error is accurate and the chown repair is documented elsewhere. |
| 22 | Minor | cli/restore | A corrupt manifest is consumed silently (no output when no `.patched` exists). | WONTFIX — by design ("nothing we can safely delete"); the manifest is removed either way. |
| 23 | Minor | cli/available | `available` exits 0 when every mirror fails ("No packages found."). | WONTFIX — informational command; per-mirror failures are printed. |
| 24 | Minor | downloader | `.deb`-internal absolute symlink targets are preserved verbatim on extraction. | WONTFIX — mirrors the package's own layout; content is SHA256-verified against the signed index. |
| 25 | Minor | downloader | Downloads without Content-Length set `total=0` in the progress callback. | WONTFIX — verified handled: rich renders total=0 as indeterminate; no crash. |
| 26 | Minor | cli | `download --with-dbg` with no dbg package on the mirror installs silently without debug symbols. | WONTFIX — the mirror simply doesn't ship one; `available`'s "Debug .deb" column shows it. |
| 27 | Minor | cli | `latest`-expansion loop variable `arch` shadows the click `arch` param (harmless: param unused after the block). | WONTFIX — zero behavior impact; a rename has no RED-able regression test. |
| 28 | Minor | tests | Task 1 parked: chown-count message counts already-owned entries; "Repaired ownership" branch untested. | WONTFIX — brief-mandated semantics (count attempts, not changes); the untested branch is cosmetic output. |
| 29 | Trivial | tests | Task 1 parked: unused `Path` import in tests/test_ownership.py. | WONTFIX — lint-level noise; no behavioral surface. |
| 30 | Minor | downloader | Task 2 parked: unknown-mirror warning says "the suite map may be stale" when the *mirror* is the problem. | WONTFIX — plan-mandated wording. |
| 31 | Minor | verify | Task 3 parked: ref regular file vs installed directory raises IsADirectoryError (parity with the deleted 4-file code; caught by cli as an error row). | WONTFIX — upstream handling is the CLI error row, which is the intent. |
| 32 | Trivial | verify | Task 3 parked: `Path(root)` re-instantiated per entry in `_compare_tree`. | WONTFIX — micro-perf; no measurable effect. |
| 33 | Minor | verify | Task 3 parked: resolve-based existence accepts installed symlinks resolving outside the install tree. | WONTFIX — a valid symlink is valid wherever it points; only *broken* links are flagged. |
| 34 | Minor | cli/signatures | Task 4 parked: combined-notes wording when a total re-fetch failure occurs. | WONTFIX — cosmetic; notes already carry per-URL failure reasons. |
| 35 | Minor | signatures | Task 4 parked: `default_keyring` docstring vs the returned-path note mismatch. | WONTFIX — help text summarizes; the None-when-missing behavior is intentional and tested. |
| 36 | Minor | tests | Task 4 parked (stale): "no off-by-default test for download-all --verify-signatures" — `test_download_all_source_off_by_default` and `TestDownloadAllVerifySignatures::test_off_by_default`... the source off-by-default test exists; signature off-by-default is covered for download/verify; download-all signature-off was covered by exit-path tests. | WONTFIX — addressed by later tasks' tests (ledger list predates Task 6). |
| 37 | Trivial | tests | Task 4 parked: gpgv argv position unasserted. | WONTFIX — test-depth choice, not a defect. |
| 38 | Trivial | cli | Task 4 parked: `--keyring` without `--verify-signatures` no-ops. | WONTFIX — documented as the parameter of `--verify-signatures`. |
| 39 | Minor | tests | Task 5 parked: `test_make_timeout_passthrough` pins configure uncapped but not install calls. | WONTFIX — test-depth choice; install inherits the same run path. |
| 40 | Minor | tests | Task 5 parked: `test_incomplete_local_source_falls_back_to_download` was never RED. | WONTFIX — meta-note about the original TDD cycle, not a defect in the code. |
| 41 | Minor | tests | Task 6 parked: download-all source tests omit `--arch amd64` vs the brief sketch. | WONTFIX — functionally broader (covers the amd64+i686 default). |
| 42 | Minor | tests | Task 6 parked: source-before-signature-check sub-ordering unpinned by tests. | WONTFIX — test-gap only; ordering is pinned for chown and exercised by Task 4 tests. |
| 43 | Minor | tests | Task 8 parked: --version test could pin the full "pwnlibc, version 0.1.0" string and reuse the module runner fixture. | WONTFIX — test niceties. |
| 44 | Minor | builder | Task 9 parked: worst-case ~13.5 s per version on a down network inside `available`/`source available` workers. | WONTFIX — bounded retry-with-backoff is the shipped Task 9 feature; workers parallelize. |
| 45 | Trivial | builder | Task 9 parked: `400 <= code < 500` treated as permanent absence. | WONTFIX — sensible superset of plain 404 (Task 9 review judgment). |
| 46 | Minor | docs | Brainstorm: click shell completion is available (`_PWNLIBC_COMPLETE`) but undocumented. | WONTFIX — upstream click feature; README scope. |

Python-3.8 floor audit: `grep -rnE "Path\.readlink|\.removeprefix|\.removesuffix|match .+:"
pwnlibc/` produced only two explanatory comments and one false positive
("mis**match for** {label}"); no floor violations found. Every module carries
`from __future__ import annotations`; os.walk/os.readlink are used over their
3.12/3.9 Path equivalents.

## Tally

- 46 findings: **10 FIX-NOW** (fixed, each with a named regression test and
  its own commit), **10 FOLLOW-UP** (appended to the spec), **26 WONTFIX**
  (each with a one-line reason).

## Regression tests per fix

| Fix commit | Regression test(s) |
|---|---|
| 7c87119 | `tests/test_crud_lifecycle.py::TestDownloadWithSource::test_download_default_includes_source` (now passes with network blocked) |
| aaa81c4 | `tests/test_fixes_qa.py::test_offline_default_blocks_real_sockets` (RED without the guard: connect to a live local listener succeeds) |
| 8c2823e | `tests/test_cli.py::TestBuildOfflineLocalSource::test_build_uses_local_source_without_remote_check`, `::test_patch_prompt_build_uses_local_source_offline` |
| 9bd2489 | `tests/test_cli.py::TestDownloadAllExitSemantics::test_all_downloads_failed_exits_1`, `::test_partial_failure_still_exits_0` |
| 9a50cef | `tests/test_crud_lifecycle.py::TestSourceRemoveFailures::test_source_remove_permission_error_clean_exit` |
| 5b58692 | `tests/test_cli.py::TestMaybeDownloadSourceNeverRaises::test_source_check_error_never_crashes_download` |
| 5513372 | `tests/test_multiarch_download.py::TestDownloadDuplicateTokens::test_duplicate_explicit_versions_downloaded_once`, `::test_duplicate_latest_tokens_resolve_and_announce_once` |
| 0209a76 | `tests/test_fixes_qa.py::TestRestoreManifest::test_manifest_cannot_delete_non_lib_files` |
| da2b415 | `tests/test_cli.py::TestSignatureFailHintWording::test_signature_only_fail_gets_signature_hint`, `::test_index_mismatch_fail_keeps_refetch_hint` |
| 45d63ad | `tests/test_downloader.py::test_unknown_version_warns_once_on_stderr` (hermetic under prior pollution; failure mode demonstrated in-process) |
