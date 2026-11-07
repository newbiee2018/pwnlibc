from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import click
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TransferSpeedColumn,
)
from rich.table import Table

from .config import ALL_ARCHES, ARCH_INFO, DEFAULT_GLIBC_DIR, MIRRORS, MIRROR_FAMILY, X86_ARCHES, parse_version
from .downloader import (
    DebPackage,
    _candidate_suites,
    download_glibc,
    download_source,
    scrape_available,
    verify_against_deb,
)
from .elfutil import detect_arch
from .glibc import discover_installed, get_debug_build_path, resolve_lib_paths
from .ownership import chown_tree
from .patcher import patch_copy, patch_inplace
from .signatures import verify_index_signature

console = Console()

ALL_MIRRORS = list(MIRRORS.keys()) + ["auto"]


class _HelpCommand(click.Command):
    def parse_args(self, ctx, args):
        if args and args[0] == "help":
            click.echo(self.get_help(ctx))
            ctx.exit(0)
        return super().parse_args(ctx, args)


class _HelpGroup(click.Group):
    command_class = _HelpCommand

    def parse_args(self, ctx, args):
        if args and args[0] == "help" and len(args) == 1:
            click.echo(self.get_help(ctx))
            ctx.exit(0)
        return super().parse_args(ctx, args)


def _ensure_writable(glibc_dir: Path) -> None:
    if not glibc_dir.exists():
        try:
            glibc_dir.mkdir(parents=True)
            console.print(f"[dim]Created glibc directory {glibc_dir}[/dim]")
        except OSError:
            console.print(f"[red]Cannot create glibc directory {glibc_dir}.[/red]")
            console.print(f"[dim]Run: sudo mkdir -p {glibc_dir} && sudo chown $(id -u):$(id -g) {glibc_dir}[/dim]")
            sys.exit(1)
    if not os.access(glibc_dir, os.W_OK):
        console.print(f"[red]No write permission on {glibc_dir}.[/red]")
        console.print(f"[dim]Run: sudo chown $(id -u):$(id -g) {glibc_dir}[/dim]")
        sys.exit(1)


def _chown_after_write(glibc_dir: Path) -> None:
    """After a possibly-privileged (sudo) write, hand the tree back to
    SUDO_USER. No-op for unprivileged runs."""
    changed = chown_tree(glibc_dir)
    if changed > 0:
        console.print(f"[dim]Repaired ownership on {changed} entries (sudo)[/dim]")


def _run_signature_checks(pkgs: list[DebPackage], glibc_dir: Path,
                          keyring: Path | None) -> bool:
    """Opt-in post-run layer: check each cached Packages index this run
    used against the GPG-signed InRelease/Release of its suite.

    (mirror, suite, deb_arch) triples are deduped via _candidate_suites per
    package; one line is printed per suite. Returns True when everything
    checked out or only degraded to warnings (skips); False when at least
    one index hash or Release signature check outright failed.
    """
    cache_dir = glibc_dir / ".cache"
    triples: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for pkg in pkgs:
        deb_arch = ARCH_INFO.get(pkg.arch, {}).get("deb_arch")
        if deb_arch is None:
            continue
        for suite in _candidate_suites(pkg):
            triple = (pkg.mirror, suite, deb_arch)
            if triple not in seen:
                seen.add(triple)
                triples.append(triple)

    if not triples:
        return True

    console.print(f"[bold]Verifying Packages indices against signed Release files"
                  f"[/bold] [dim]({len(triples)} suite indices)[/dim]")
    ok = True
    for mirror, suite, deb_arch in triples:
        check = verify_index_signature(mirror, suite, deb_arch, cache_dir, keyring)
        label = f"{mirror} {suite} {deb_arch}"
        if check.index_sha_ok is False or check.signature_ok is False:
            ok = False
            what = []
            if check.index_sha_ok is False:
                what.append("cached index does not match the signed Release")
            if check.signature_ok is False:
                what.append("gpgv rejected the Release signature")
            console.print(
                f"  [red]FAIL[/red] {label} [dim]({'; '.join(check.notes + what)})[/dim]"
            )
            console.print(
                "  [dim]a stale cached index can cause a mismatch; "
                "re-running the command refreshes it[/dim]"
            )
        elif check.notes:
            console.print(
                f"  [yellow]skipped[/yellow] {label} [dim]({'; '.join(check.notes)})[/dim]"
            )
        else:
            console.print(f"  [green]ok[/green] {label}")
    return ok


def _mirrors_for_arch(arch: str) -> list[str]:
    primary = ARCH_INFO.get(arch, {}).get("mirror", "ubuntu")
    mirrors = [primary]
    if primary == "ubuntu":
        mirrors.append("old-ubuntu")
    elif primary == "ports":
        mirrors.append("ubuntu")
        mirrors.append("old-ubuntu")
    elif primary == "debian":
        mirrors.append("old-debian")
    return mirrors


def _scrape_mirrors(mirrors: set[str]) -> list[DebPackage]:
    pkgs: list[DebPackage] = []
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(mirrors)))) as executor:
        futures = {executor.submit(scrape_available, m): m for m in sorted(mirrors)}
        for future in as_completed(futures):
            m = futures[future]
            try:
                pkgs.extend(future.result())
            except Exception as e:
                console.print(f"[yellow]Failed to fetch {m}: {e}[/yellow]")
    return pkgs


def _deb_version_key(ver: str) -> tuple:
    """dpkg-style ordering for Ubuntu glibc revisions like 2.31-0ubuntu9.16.

    Digit runs compare numerically. Inside non-digit runs, characters are
    mapped per dpkg's ordering classes: '~' sorts before everything (so ESM
    revisions like 3.1~esm1 sort below the final 3.1); letters sort above
    '~' and below all other characters — real dpkg orders letters before
    non-letters, so 0ubuntu3a < 0ubuntu3.1 even though ASCII would put '.'
    before 'a'. Everything else ('.', '+', ...) sorts above letters. The
    end-of-string sentinel sorts above '~' but below letters (the prefix
    rule makes "" < "a" within the letter class). Covers the character set
    that actually appears in Ubuntu pool revisions (digits, letters, '.',
    '+', '-', '~').
    """
    def char_key(tok: str) -> str:
        out = []
        for ch in tok:
            if ch == "~":
                out.append("\x01")
            elif ch.isalpha():
                out.append("\x02" + ch)
            else:
                out.append("\x03" + ch)
        return "".join(out)

    key = []
    for tok in re.split(r"(\d+)", ver):
        if tok.isdigit():
            key.append((1, int(tok), "\x00"))
        elif tok:
            key.append((0, 0, char_key(tok)))
    key.append((0, 0, "\x02"))  # end-of-string sentinel
    return tuple(key)


def _pkg_beats(a: DebPackage, b: DebPackage) -> bool:
    """Whether a replaces b as the best pick.

    Packages from the arch's own distribution family always beat the other
    family: Debian and Ubuntu revision numbers are different package
    streams and must never be compared (Debian's 2.28-10 would otherwise
    shadow Ubuntu's 2.28-0ubuntu1). Within the family: newer dpkg-style
    revision, then the earlier (primary) mirror on an exact tie.
    """
    fam_a = _pkg_family(a)
    fam_b = _pkg_family(b)
    if fam_a != fam_b:
        return fam_a < fam_b

    key_a = _deb_version_key(a.full_id.rsplit("_", 1)[0])
    key_b = _deb_version_key(b.full_id.rsplit("_", 1)[0])
    if key_a != key_b:
        return key_a > key_b

    mirrors = _mirrors_for_arch(a.arch)

    def rank(m: str) -> int:
        return mirrors.index(m) if m in mirrors else len(mirrors)

    return rank(a.mirror) < rank(b.mirror)


def _pkg_family(pkg: DebPackage) -> int:
    """0 when the package's mirror family matches the arch's primary family
    (amd64←ubuntu, mipsel←debian, ...), 1 otherwise."""
    primary = MIRROR_FAMILY.get(ARCH_INFO.get(pkg.arch, {}).get("mirror", "ubuntu"), "ubuntu")
    return 0 if MIRROR_FAMILY.get(pkg.mirror) == primary else 1


def _auto_chain_only(packages: list[DebPackage]) -> list[DebPackage]:
    """Auto mode: keep only packages from each arch's own mirror chain, so
    the catalog (available) shows exactly what download would fetch. A
    Debian amd64 package scraped for mipsel's sake must not appear (or be
    picked) for amd64; it's reachable explicitly via --mirror debian."""
    return [p for p in packages if p.mirror in _mirrors_for_arch(p.arch)]


def _where_is_version(version: str, tried: set[str], wanted_arches: list[str]):
    """Scan the mirrors a command didn't already scrape, to explain where a
    missing version lives (other arches, or out-of-chain mirrors)."""
    rest = sorted(set(MIRRORS) - tried)
    if not rest:
        return [], []
    pkgs = [p for p in _scrape_mirrors(set(rest)) if p.version == version]
    arches = sorted({p.arch for p in pkgs if p.arch not in wanted_arches})
    mirrors = sorted({p.mirror for p in pkgs})
    return arches, mirrors


def _pick_best(packages: list[DebPackage]) -> dict[tuple[str, str], DebPackage]:
    best: dict[tuple[str, str], DebPackage] = {}
    for pkg in packages:
        key = (pkg.version, pkg.arch)
        existing = best.get(key)
        if existing is None or _pkg_beats(pkg, existing):
            best[key] = pkg
    return best


def _variant_label(inst) -> str:
    label = inst.variant
    if inst.has_debug:
        label += "(dbg)"
    return label


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group(cls=_HelpGroup, invoke_without_command=True)
@click.option(
    "--glibc-dir",
    type=click.Path(path_type=Path),
    default=DEFAULT_GLIBC_DIR,
    envvar="PWNLIBC_DIR",
    help="Glibc installation directory.",
)
@click.pass_context
def cli(ctx, glibc_dir):
    """pwnlibc - CTF glibc manager and ELF patcher."""
    ctx.ensure_object(dict)
    ctx.obj["glibc_dir"] = glibc_dir
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@cli.command("list")
@click.option("--arch", type=click.Choice(ALL_ARCHES + ["all"]), default="all")
@click.pass_context
def list_cmd(ctx, arch):
    """List installed glibc versions."""
    glibc_dir = ctx.obj["glibc_dir"]
    installs = discover_installed(glibc_dir)

    if arch != "all":
        installs = [i for i in installs if i.arch == arch]

    if not installs:
        console.print("[dim]No glibc versions found.[/dim]")
        console.print(f"[dim]Looking in: {glibc_dir}[/dim]")
        console.print("[dim]Use 'pwnlibc available' to see downloadable versions.[/dim]")
        return

    table = Table(title="Installed glibc versions")
    table.add_column("#", style="dim")
    table.add_column("Version", style="bold")
    table.add_column("Arch")
    table.add_column("Variant")
    table.add_column("Source", justify="center")

    groups: dict[tuple[str, str], list] = {}
    for inst in installs:
        groups.setdefault((inst.version, inst.arch), []).append(inst)

    idx = 1
    for (ver, a) in sorted(groups.keys(), key=lambda k: (parse_version(k[0]), k[1])):
        arch_installs = groups[(ver, a)]
        variants = " ".join(_variant_label(i) for i in arch_installs)
        has_src = any(i.has_source for i in arch_installs)
        src_str = "[green]yes[/green]" if has_src else "[dim]-[/dim]"
        table.add_row(str(idx), ver, a, variants, src_str)
        idx += 1

    console.print(table)


# ---------------------------------------------------------------------------
# available
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--arch", type=click.Choice(ALL_ARCHES + ["all"]), default="all")
@click.option(
    "--mirror",
    type=click.Choice(ALL_MIRRORS),
    default="auto",
)
@click.option("--check-source/--no-check-source", default=True,
              help="Check ftp.gnu.org for source availability.")
@click.pass_context
def available(ctx, arch, mirror, check_source):
    """List glibc versions available for download."""
    glibc_dir = ctx.obj["glibc_dir"]

    arches = ALL_ARCHES if arch == "all" else [arch]
    mirrors_to_try: set[str] = set()
    if mirror == "auto":
        for a in arches:
            for m in _mirrors_for_arch(a):
                mirrors_to_try.add(m)
    else:
        mirrors_to_try.add(mirror)

    console.print(f"[bold]Fetching package lists...[/bold] [dim]({', '.join(sorted(mirrors_to_try))})[/dim]")
    packages = _scrape_mirrors(mirrors_to_try)
    if not packages:
        console.print("[red]No packages found.[/red]")
        return
    if mirror == "auto":
        packages = _auto_chain_only(packages)

    installs = discover_installed(glibc_dir)
    installed_map: dict[tuple[str, str], str] = {}
    for i in installs:
        key = (i.version, i.arch)
        label = _variant_label(i)
        if key in installed_map:
            installed_map[key] += " " + label
        else:
            installed_map[key] = label

    best = _pick_best([p for p in packages if p.arch in arches])

    by_version: dict[str, dict[str, DebPackage]] = {}
    for (ver, a), pkg in best.items():
        by_version.setdefault(ver, {})[a] = pkg

    source_avail: dict[str, bool] = {}
    if check_source:
        from .builder import check_source_available

        unique_versions = sorted(set(by_version.keys()), key=lambda v: parse_version(v))
        console.print(f"[dim]Checking source availability ({len(unique_versions)} versions)...[/dim]")
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_source_available, ver): ver for ver in unique_versions}
            for future in as_completed(futures):
                ver = futures[future]
                source_avail[ver] = future.result() is not None

    table = Table(title="Available glibc packages")
    table.add_column("#", style="dim")
    table.add_column("Version", style="bold")
    table.add_column("Arch")
    table.add_column("Mirror", style="dim")
    table.add_column("Debug .deb", justify="center")
    if check_source:
        table.add_column("Source", justify="center")
    table.add_column("Installed")

    entries: list[tuple[str, str, DebPackage]] = []
    idx = 1
    for ver in sorted(by_version.keys(), key=lambda v: parse_version(v)):
        for a in sorted(by_version[ver].keys()):
            pkg = by_version[ver][a]
            pkg_mirror = pkg.mirror

            key = (ver, a)
            if key in installed_map:
                inst_str = f"[green]{installed_map[key]}[/green]"
            else:
                inst_str = "[dim]-[/dim]"

            dbg_str = "[green]yes[/green]" if pkg.dbg_filename else "[dim]-[/dim]"

            row = [str(idx), ver, a, pkg_mirror, dbg_str]
            if check_source:
                src = source_avail.get(ver)
                row.append("[green]yes[/green]" if src else "[dim]-[/dim]")
            row.append(inst_str)

            table.add_row(*row)
            entries.append((ver, a, pkg))
            idx += 1

    console.print(table)
    console.print(f"\n[dim]{len(entries)} entries. "
                  f"'pwnlibc download VERSION --arch ARCH' to download.[/dim]")


# ---------------------------------------------------------------------------
# patch
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("binary", type=click.Path(exists=True, path_type=Path))
@click.option("-v", "--version", "glibc_version", required=True, help="Glibc version.")
@click.option("-a", "--arch", type=click.Choice(ALL_ARCHES), default=None)
@click.option(
    "-m", "--mode",
    type=click.Choice(["copy", "inplace"]),
    default="inplace",
    help="inplace: absolute paths into the glibc dir (default). copy: libs to binary dir.",
)
@click.option("--variant", type=click.Choice(["deb", "built", "auto"]), default="auto",
              help="auto: prefer deb with debug symbols, prompt if unavailable. "
                   "deb/built: use that variant directly.")
@click.option("--no-rpath", is_flag=True, help="Don't set RPATH.")
@click.pass_context
def patch(ctx, binary, glibc_version, arch, mode, variant, no_rpath):
    """Patch an ELF binary to use a specific glibc version.

    Creates <binary>.patched — the original is never modified.

    In auto mode (default), prefers deb with debug symbols for source-level
    debugging. If only a deb without debug is available, prompts to build
    from source, use the deb without debug, or cancel.
    """
    binary = binary.resolve()
    glibc_dir = ctx.obj["glibc_dir"]

    try:
        detected = detect_arch(binary)
    except ValueError:
        detected = None

    if arch is None:
        if detected is None:
            console.print("[red]Cannot detect binary architecture. Use -a/--arch.[/red]")
            sys.exit(1)
        arch = detected
        console.print(f"Detected architecture: [bold]{arch}[/bold]")
    elif detected and arch != detected:
        console.print(
            f"[red]Architecture mismatch: binary is {detected} but --arch {arch} was specified.[/red]"
        )
        sys.exit(1)

    glibc = _resolve_variant(glibc_version, arch, glibc_dir, variant)
    if glibc is None:
        sys.exit(1)

    _do_patch(binary, glibc, glibc_dir, glibc_version, arch, mode, no_rpath)


def _resolve_variant(glibc_version, arch, glibc_dir, variant):
    """Resolve which glibc variant to use. Returns GlibcInstall or None."""
    if variant != "auto":
        try:
            glibc = resolve_lib_paths(glibc_version, arch, glibc_dir, variant)
        except FileNotFoundError:
            console.print(f"[red]Glibc {glibc_version} ({arch}, {variant}) not found.[/red]")
            console.print(f"[dim]Run: pwnlibc download {glibc_version} --arch {arch}[/dim]")
            return None
        if not glibc.has_debug:
            console.print(f"[yellow]Warning: no debug symbols ({variant} variant).[/yellow]")
        return glibc

    # --- auto mode: prefer deb(dbg) > built(dbg) > prompt ---
    deb = None
    built = None
    try:
        deb = resolve_lib_paths(glibc_version, arch, glibc_dir, "deb")
    except FileNotFoundError:
        pass
    try:
        built = resolve_lib_paths(glibc_version, arch, glibc_dir, "built")
    except FileNotFoundError:
        pass

    # 1) deb with debug — best case
    if deb and deb.has_debug:
        return deb

    # 2) built with debug
    if built and built.has_debug:
        console.print(f"Using [bold]built[/bold] variant (deb has no debug symbols)")
        return built

    # 3) deb exists but no debug, no built with debug — prompt user
    if deb:
        return _prompt_no_debug(glibc_version, arch, glibc_dir, deb)

    # 4) nothing installed at all
    console.print(f"[red]Glibc {glibc_version} ({arch}) not found.[/red]")
    console.print(f"[dim]Run: pwnlibc download {glibc_version} --arch {arch}[/dim]")
    return None


def _prompt_no_debug(glibc_version, arch, glibc_dir, deb_install):
    """Deb exists but has no debug symbols. Prompt user for action."""
    console.print(
        f"[yellow]Glibc {glibc_version} ({arch}) deb installed but "
        f"has no debug symbols.[/yellow]"
    )
    console.print()
    console.print("  [bold]1)[/bold] Build from source with debug symbols "
                  "[dim](recommended, enables source-level debugging)[/dim]")
    console.print("  [bold]2)[/bold] Use deb without debug symbols "
                  "[dim](no source debugging or symbol info)[/dim]")
    console.print("  [bold]3)[/bold] Cancel")
    console.print()

    choice = click.prompt("Choose", type=click.IntRange(1, 3), default=1)

    if choice == 3:
        console.print("[dim]Cancelled.[/dim]")
        return None

    if choice == 2:
        console.print("[yellow]Patching without debug symbols. "
                      "Source-level debugging will not be available.[/yellow]")
        return deb_install

    # choice == 1: build from source
    console.print(f"\n[bold]Building glibc {glibc_version} from source...[/bold]")
    from .builder import build_glibc, check_build_deps, check_source_available, get_install_cmd
    from rich.progress import SpinnerColumn, TextColumn

    missing_deps = check_build_deps(arch)
    if missing_deps:
        console.print("[red]Missing build dependencies:[/red]")
        for dep in missing_deps:
            console.print(f"  [red]- {dep}[/red]")
        console.print(f"\n[bold]Install with:[/bold] {get_install_cmd(arch)}")
        console.print("[yellow]Falling back to deb without debug symbols.[/yellow]")
        return deb_install

    if not check_source_available(glibc_version):
        console.print(f"[red]Source not available on ftp.gnu.org for {glibc_version}.[/red]")
        console.print("[yellow]Falling back to deb without debug symbols.[/yellow]")
        return deb_install

    build_err = None
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.fields[label]}"),
        console=console,
    ) as progress:
        task_id = progress.add_task("", label=f"building {glibc_version}/{arch}")

        def cb(stage, downloaded, total, tid=task_id):
            progress.update(tid, description=f"  {stage}")

        try:
            build_glibc(glibc_version, arch, glibc_dir, progress_cb=cb)
        except Exception as e:
            build_err = e

    if build_err:
        console.print(f"[red]Build failed: {build_err}[/red]")
        console.print("[yellow]Falling back to deb without debug symbols.[/yellow]")
        return deb_install

    console.print(f"[green]Build complete.[/green]")
    try:
        return resolve_lib_paths(glibc_version, arch, glibc_dir, "built")
    except FileNotFoundError:
        console.print("[red]Built variant not found after build.[/red]")
        console.print("[yellow]Falling back to deb without debug symbols.[/yellow]")
        return deb_install


def _pick_source_subdir(source_dir: Path) -> Path | None:
    """Deterministically pick the extracted source subdirectory:
    first sorted dir named glibc-*, else first sorted subdir, else None."""
    subdirs = sorted(d for d in source_dir.iterdir() if d.is_dir())
    for d in subdirs:
        if d.name.startswith("glibc-"):
            return d
    return subdirs[0] if subdirs else None


def _do_patch(binary, glibc, glibc_dir, glibc_version, arch, mode, no_rpath):
    """Perform the actual patchelf operation and print results."""
    if glibc.variant != "deb":
        console.print(f"Using [bold]{glibc.variant}[/bold] variant")

    try:
        if mode == "copy":
            patched, copied = patch_copy(binary, glibc, set_rpath=not no_rpath)
            console.print(f"Copied {len(copied)} libs to {binary.parent}")
        else:
            patched = patch_inplace(binary, glibc, set_rpath=not no_rpath)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    console.print(
        f"[green]Created [bold]{patched.name}[/bold] -> "
        f"glibc {glibc_version} ({arch}, {mode}, {_variant_label(glibc)})[/green]"
    )

    if not glibc.has_debug:
        return

    source_dir = glibc_dir / glibc_version / "source"
    if glibc.has_source:
        build_path = get_debug_build_path(glibc)
        source_subdir = _pick_source_subdir(source_dir) if source_dir.is_dir() else None
        if build_path and source_subdir:
            console.print(
                f"\n[dim]GDB source mapping:[/dim]\n"
                f"  [bold]set substitute-path {build_path} {source_subdir}[/bold]"
            )
    else:
        from .builder import check_source_available
        if check_source_available(glibc_version):
            console.print(f"[dim]Source available. Run: pwnlibc source download {glibc_version}[/dim]")
        else:
            console.print(f"[dim]No source available for {glibc_version} on ftp.gnu.org[/dim]")


# ---------------------------------------------------------------------------
# restore
# ---------------------------------------------------------------------------

def _consume_patch_manifest(binary: Path) -> bool:
    """Remove files copied by `patch --mode copy`, as listed in its manifest.

    Returns True when a manifest was found (and consumed). Each entry is a
    relative path; only files resolving directly into binary.parent (or one
    level down, into binary.parent/.debug) are deleted — a tampered or
    traversing manifest cannot remove anything elsewhere.
    """
    parent = binary.parent
    # keep in sync with patcher.PATCHED_MANIFEST_SUFFIX
    manifest = parent / (binary.name + ".patched.manifest")
    if not manifest.is_file():
        return False

    entries: list[str] = []
    try:
        data = json.loads(manifest.read_text())
        if isinstance(data, dict) and isinstance(data.get("files"), list):
            entries = [e for e in data["files"] if isinstance(e, str)]
    except (OSError, ValueError):
        pass  # unreadable/corrupt manifest: nothing we can safely delete

    debug_dir = parent / ".debug"
    removed: list[str] = []
    for rel in entries:
        resolved = (parent / rel).resolve()
        if resolved in (binary, manifest):
            continue
        if resolved.parent not in (parent, debug_dir):
            continue  # refuses traversal / tampered entries
        if resolved.is_file() or resolved.is_symlink():
            resolved.unlink()
            removed.append(resolved.name)

    if debug_dir.is_dir() and not any(debug_dir.iterdir()):
        debug_dir.rmdir()

    manifest.unlink()
    if removed:
        summary = ", ".join(removed[:5])
        if len(removed) > 5:
            summary += f", +{len(removed) - 5} more"
        console.print(f"[dim]Removed {len(removed)} copied files ({summary})[/dim]")
    return True


@cli.command()
@click.argument("binary", type=click.Path(exists=True, path_type=Path))
def restore(binary):
    """Remove the .patched file created by pwnlibc patch, or restore a legacy .bak backup.

    Copy-mode patching records the files it copied in a
    <binary>.patched.manifest; when present, restore removes those copied
    libs and .debug files (an emptied .debug directory goes too). Copied
    files from older versions without a manifest — and manual/challenge
    files — are still left untouched.
    """
    binary = binary.resolve()

    from .patcher import PATCHED_SUFFIX
    patched = binary.parent / (binary.name + PATCHED_SUFFIX)

    handled = False
    if patched.exists():
        patched.unlink()
        console.print(f"[green]Removed {patched.name}[/green]")
        handled = True

    # Consumed even when .patched is gone (user may have deleted it manually).
    if _consume_patch_manifest(binary):
        handled = True

    if not handled:
        from .backup import restore_backup
        removed = restore_backup(binary)
        if removed:
            console.print(f"[green]Restored {binary.name} from {removed.name}[/green]")
        else:
            console.print(f"[red]No .patched file or backup found for {binary.name}[/red]")
            sys.exit(1)


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------

def _rmtree_verbose(path: Path, label: str) -> None:
    shutil.rmtree(path)
    console.print(f"  [green]Removed {label}[/green]")


@cli.command()
@click.argument("versions", nargs=-1, required=True)
@click.option("--arch", type=click.Choice(ALL_ARCHES + ["all"]), default="all",
              help="Remove only this architecture.")
@click.option("--variant", type=click.Choice(["deb", "built", "source", "all"]), default="all",
              help="Remove only this variant.")
@click.option("--keep-cache", is_flag=True, help="Keep cached .deb files.")
@click.pass_context
def remove(ctx, versions, arch, variant, keep_cache):
    """Remove installed glibc versions.

    Source is auto-removed when no deb/built variant remains for that version.

    Examples:

      pwnlibc remove 2.31

      pwnlibc remove 2.27 --arch amd64

      pwnlibc remove 2.31 --variant source

      pwnlibc remove 2.27 --variant built --arch amd64
    """
    glibc_dir = ctx.obj["glibc_dir"]
    _ensure_writable(glibc_dir)

    for version in versions:
        try:
            ver_dir = glibc_dir / version
            if not ver_dir.is_dir():
                console.print(f"[red]{version}: not installed[/red]")
                continue

            console.print(f"[bold]{version}:[/bold]")
            removed_any = False

            arches = ALL_ARCHES if arch == "all" else [arch]

            for a in arches:
                if variant in ("deb", "all"):
                    deb_dir = ver_dir / a
                    if deb_dir.is_dir():
                        _rmtree_verbose(deb_dir, f"{a} (deb)")
                        removed_any = True

                if variant in ("built", "all"):
                    built_dir = ver_dir / f"{a}-built"
                    if built_dir.is_dir():
                        _rmtree_verbose(built_dir, f"{a}-built")
                        removed_any = True

            # With --variant all + a specific --arch, other arches may still need the
            # shared source/ dir — so source only goes via the auto-removal rule below.
            remove_source_now = variant == "source" or (variant == "all" and arch == "all")
            if remove_source_now:
                source_dir = ver_dir / "source"
                if source_dir.is_dir():
                    _rmtree_verbose(source_dir, "source")
                    removed_any = True

            # Auto-remove source when no deb/built remains
            if not remove_source_now and ver_dir.is_dir():
                has_lib = any(
                    d.is_dir() and d.name != "source" and not d.name.startswith(".")
                    for d in ver_dir.iterdir()
                )
                if not has_lib:
                    source_dir = ver_dir / "source"
                    if source_dir.is_dir():
                        _rmtree_verbose(source_dir, "source (no variants left)")
                        removed_any = True

            if not keep_cache and variant in ("deb", "all"):
                cache_dir = glibc_dir / ".cache"
                if cache_dir.is_dir():
                    # With --arch, other arches may still be installed and must
                    # keep their cached .debs — prune only that arch's files.
                    if arch == "all":
                        cache_pattern = f"libc6*_{version}-*"
                    else:
                        cache_pattern = f"libc6*_{version}-*_{ARCH_INFO[arch]['deb_arch']}.deb"
                    for deb_file in cache_dir.glob(cache_pattern):
                        deb_file.unlink()
                        console.print(f"  [dim]Removed cache: {deb_file.name}[/dim]")

            if ver_dir.is_dir() and not any(ver_dir.iterdir()):
                ver_dir.rmdir()
                console.print(f"  [dim]Removed empty {version}/ directory[/dim]")

            if not removed_any:
                console.print(f"  [yellow]Nothing to remove for given filters[/yellow]")
        except PermissionError:
            console.print(f"[red]Permission denied under {glibc_dir}.[/red]")
            console.print(f"[dim]Run: sudo chown $(id -u):$(id -g) {glibc_dir}[/dim]")
            sys.exit(1)


# ---------------------------------------------------------------------------
# source
# ---------------------------------------------------------------------------

@cli.group(cls=_HelpGroup, invoke_without_command=True)
@click.pass_context
def source(ctx):
    """Manage glibc source code for GDB debugging.

    Without a subcommand, shows downloaded source for installed versions.
    Use 'source check' to verify local source, 'source available' to
    check ftp.gnu.org.
    """
    if ctx.invoked_subcommand is not None:
        return

    glibc_dir = ctx.obj["glibc_dir"]
    installs = discover_installed(glibc_dir)

    versions: dict[str, bool] = {}
    for inst in installs:
        if inst.version not in versions:
            versions[inst.version] = inst.has_source

    for d in sorted(glibc_dir.iterdir()) if glibc_dir.is_dir() else []:
        if not d.is_dir() or d.name.startswith("."):
            continue
        try:
            parse_version(d.name)
        except (ValueError, IndexError):
            continue
        if d.name not in versions:
            has_src = (d / "source").is_dir()
            versions[d.name] = has_src

    if not versions:
        console.print("[dim]No glibc versions found.[/dim]")
        return

    table = Table(title="Glibc source status")
    table.add_column("Version", style="bold")
    table.add_column("Source", justify="center")
    table.add_column("Path")

    glibc_dir_path = glibc_dir
    for ver in sorted(versions.keys(), key=lambda v: parse_version(v)):
        has_src = versions[ver]
        if has_src:
            src_dir = glibc_dir_path / ver / "source"
            table.add_row(ver, "[green]yes[/green]", f"[dim]{src_dir}[/dim]")
        else:
            table.add_row(ver, "[dim]-[/dim]", "")

    console.print(table)
    console.print("[dim]Use 'pwnlibc source check' to verify, 'pwnlibc source available' to check ftp.gnu.org[/dim]")


@source.command("download")
@click.argument("versions", nargs=-1, required=True)
@click.pass_context
def source_download(ctx, versions):
    """Download glibc source from ftp.gnu.org.

    Examples:

      pwnlibc source download 2.31

      pwnlibc source download 2.27 2.35
    """
    glibc_dir = ctx.obj["glibc_dir"]
    _ensure_writable(glibc_dir)

    from .builder import check_source_available

    any_success = False
    for version in versions:
        source_dir = glibc_dir / version / "source"
        if source_dir.is_dir() and any(source_dir.iterdir()):
            console.print(f"[dim]{version}: source already exists[/dim]")
            continue

        console.print(f"Checking {version}...", end=" ")
        url = check_source_available(version)
        if not url:
            console.print("[yellow]not available on ftp.gnu.org[/yellow]")
            continue
        console.print("downloading...")

        try:
            download_source(version, glibc_dir, url=url)
            any_success = True
            console.print(f"  [green]{version} source installed at {source_dir}[/green]")
        except Exception as e:
            console.print(f"  [red]{version} failed: {e}[/red]")

    if any_success:
        _chown_after_write(glibc_dir)


@source.command("remove")
@click.argument("versions", nargs=-1, required=True)
@click.pass_context
def source_remove(ctx, versions):
    """Remove downloaded source for specific versions.

    Examples:

      pwnlibc source remove 2.31

      pwnlibc source remove 2.27 2.35
    """
    glibc_dir = ctx.obj["glibc_dir"]
    _ensure_writable(glibc_dir)

    for version in versions:
        source_dir = glibc_dir / version / "source"
        if not source_dir.is_dir():
            console.print(f"[yellow]{version}: no source installed[/yellow]")
            continue
        shutil.rmtree(source_dir)
        console.print(f"[green]Removed source for {version}[/green]")

        ver_dir = glibc_dir / version
        if ver_dir.is_dir() and not any(ver_dir.iterdir()):
            ver_dir.rmdir()
            console.print(f"  [dim]Removed empty {version}/ directory[/dim]")


@source.command("check")
@click.pass_context
def source_check(ctx):
    """Verify local source directories exist and have content."""
    glibc_dir = ctx.obj["glibc_dir"]
    installs = discover_installed(glibc_dir)

    versions = sorted({i.version for i in installs}, key=lambda v: parse_version(v))
    if not versions:
        console.print("[dim]No installed versions.[/dim]")
        return

    ok = 0
    missing = 0
    for ver in versions:
        source_dir = glibc_dir / ver / "source"
        if source_dir.is_dir() and any(source_dir.iterdir()):
            ok += 1
            console.print(f"  {ver}: [green]OK[/green] [dim]({source_dir})[/dim]")
        else:
            missing += 1
            console.print(f"  {ver}: [yellow]missing[/yellow]")

    console.print(f"\n[green]{ok} OK[/green], [yellow]{missing} missing[/yellow]")
    if missing:
        console.print("[dim]Use 'pwnlibc source download VERSION' or 'pwnlibc source available' to check online[/dim]")


@source.command("available")
@click.argument("versions", nargs=-1)
@click.pass_context
def source_available(ctx, versions):
    """Check which versions have source on ftp.gnu.org.

    Without arguments, scrapes all mirrors to discover every available
    version and checks source for each. With arguments, checks only
    the specified versions.

    Examples:

      pwnlibc source available

      pwnlibc source available 2.19 2.31 2.40
    """
    glibc_dir = ctx.obj["glibc_dir"]

    from .builder import check_source_available
    from .config import GNU_SOURCE_BASE, gnu_source_version

    if not versions:
        mirrors_to_try: set[str] = set()
        for a in ALL_ARCHES:
            for m in _mirrors_for_arch(a):
                mirrors_to_try.add(m)

        console.print(f"[dim]Fetching package lists... ({', '.join(sorted(mirrors_to_try))})[/dim]")
        all_packages = _scrape_mirrors(mirrors_to_try)
        installs = discover_installed(glibc_dir)
        all_versions = set(p.version for p in all_packages) | set(i.version for i in installs)
        versions = sorted(all_versions, key=lambda v: parse_version(v))
        if not versions:
            console.print("[dim]No versions found.[/dim]")
            return

    console.print(f"[dim]Source: {GNU_SOURCE_BASE}glibc-<VERSION>.tar.{{xz,gz,bz2}}[/dim]")
    console.print(f"[dim]Checking {len(versions)} versions...[/dim]\n")

    # Check non-local versions in parallel
    to_check = []
    local_map: dict[str, Path] = {}
    for ver in versions:
        source_dir = glibc_dir / ver / "source"
        if source_dir.is_dir() and any(source_dir.iterdir()):
            local_map[ver] = source_dir
        else:
            to_check.append(ver)

    remote_map: dict[str, str | None] = {}
    if to_check:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_source_available, ver): ver for ver in to_check}
            for future in as_completed(futures):
                ver = futures[future]
                remote_map[ver] = future.result()

    avail_count = 0
    unavail_count = 0
    for ver in versions:
        src_ver = gnu_source_version(ver)
        if ver in local_map:
            avail_count += 1
            console.print(f"  {ver}: [green]installed[/green] [dim]({local_map[ver]})[/dim]")
        elif ver in remote_map and remote_map[ver]:
            avail_count += 1
            console.print(f"  {ver}: [cyan]available[/cyan] [dim]({remote_map[ver]})[/dim]")
        else:
            unavail_count += 1
            console.print(f"  {ver}: [yellow]not available[/yellow] [dim]({GNU_SOURCE_BASE}glibc-{src_ver}.tar.*)[/dim]")

    console.print(f"\n{avail_count} available, {unavail_count} not available")


# ---------------------------------------------------------------------------
# download
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("versions", nargs=-1, required=True)
@click.option("--arch", type=click.Choice(ALL_ARCHES + ["all"]), default="all")
@click.option(
    "--mirror",
    type=click.Choice(ALL_MIRRORS),
    default="auto",
    help="auto: pick mirror per arch.",
)
@click.option("--with-dbg/--no-dbg", default=True, help="Include debug symbols.")
@click.option("--source/--no-source", default=True, help="Download GNU source for GDB debugging.")
@click.option("--verify-signatures", is_flag=True,
              help="After the run, check each Packages index used against the GPG-signed InRelease/Release (gpgv).")
@click.option("--keyring", type=click.Path(path_type=Path), default=None,
              help="Trusted keyring for --verify-signatures (default: distro archive keyring).")
@click.pass_context
def download(ctx, versions, arch, mirror, with_dbg, source,
             verify_signatures, keyring):
    """Download one or more glibc versions.

    Examples:

      pwnlibc download 2.31

      pwnlibc download 2.27 2.31 2.35

      pwnlibc download 2.31 --arch arm64
    """
    glibc_dir = ctx.obj["glibc_dir"]
    _ensure_writable(glibc_dir)
    archs_to_download = X86_ARCHES if arch == "all" else [arch]
    from .builder import check_source_available

    mirrors_to_try: set[str] = set()
    if mirror == "auto":
        for a in archs_to_download:
            for m in _mirrors_for_arch(a):
                mirrors_to_try.add(m)
    else:
        mirrors_to_try.add(mirror)

    console.print(f"[bold]Fetching package lists...[/bold] [dim]({', '.join(sorted(mirrors_to_try))})[/dim]")
    all_packages = _scrape_mirrors(mirrors_to_try)
    chain_packages = _auto_chain_only(all_packages) if mirror == "auto" else all_packages

    any_success = False
    used_pkgs: list[DebPackage] = []
    for version in versions:
        matching = [
            p for p in chain_packages
            if p.version == version and p.arch in archs_to_download
        ]

        if not matching:
            tried = ", ".join(sorted(mirrors_to_try))
            msg = f"{version} ({', '.join(archs_to_download)}): not found on mirrors ({tried})"
            hint_arches, hint_mirrors = _where_is_version(version, mirrors_to_try, archs_to_download)
            if hint_arches:
                msg += f" — exists for {', '.join(hint_arches)}, retry with --arch"
            elif hint_mirrors:
                msg += f" — found on {', '.join(hint_mirrors)}, retry with --mirror"
            console.print(f"[red]{msg}[/red]")
            continue

        best = _pick_best(matching)

        with Progress(
            TextColumn("[bold]{task.fields[label]}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            console=console,
        ) as progress:
            for (_, pkg_arch), pkg in sorted(best.items()):
                task_id = progress.add_task("", label=f"libc6 {version} ({pkg_arch})", total=None)

                def cb(downloaded, total, tid=task_id):
                    progress.update(tid, total=total, completed=downloaded)

                dl_mirror = pkg.mirror if mirror == "auto" else mirror
                try:
                    download_glibc(
                        pkg, glibc_dir, mirror=dl_mirror,
                        include_dbg=with_dbg, progress_cb=cb,
                    )
                    progress.update(task_id, completed=progress.tasks[task_id].total or 0)
                except Exception as e:
                    console.print(f"[red]Failed {pkg.filename}: {e}[/red]")
                    continue

                any_success = True
                used_pkgs.append(pkg)
                console.print(f"  [green]{version}/{pkg_arch} installed[/green] [dim]({dl_mirror})[/dim]")

        if source:
            src_dir = glibc_dir / version / "source"
            if not src_dir.is_dir() or not any(src_dir.iterdir()):
                console.print(f"[dim]Downloading source for {version}...[/dim]")
                url = check_source_available(version)
                if url is None:
                    console.print(f"[yellow]Source: not available on ftp.gnu.org for {version}[/yellow]")
                else:
                    try:
                        download_source(version, glibc_dir, url=url)
                    except Exception as e:
                        console.print(f"[yellow]Source: {e}[/yellow]")

    # Signature checks run BEFORE the ownership repair: verify content
    # first, repair ownership last.
    sig_ok = True
    if verify_signatures and used_pkgs:
        sig_ok = _run_signature_checks(used_pkgs, glibc_dir, keyring)

    if any_success:
        _chown_after_write(glibc_dir)

    if not any_success or not sig_ok:
        sys.exit(1)


# ---------------------------------------------------------------------------
# download-all
# ---------------------------------------------------------------------------

@cli.command("download-all")
@click.option("--arch", type=click.Choice(ALL_ARCHES + ["all"]), default="all",
              help="all = amd64+i686. Specify one to download all versions for that arch.")
@click.option(
    "--mirror",
    type=click.Choice(ALL_MIRRORS),
    default="auto",
)
@click.option("--with-dbg/--no-dbg", default=True)
@click.option("--check", is_flag=True, help="Dry run.")
@click.option("--verify-signatures", is_flag=True,
              help="After the run, check each Packages index used against the GPG-signed InRelease/Release (gpgv).")
@click.option("--keyring", type=click.Path(path_type=Path), default=None,
              help="Trusted keyring for --verify-signatures (default: distro archive keyring).")
@click.pass_context
def download_all(ctx, arch, mirror, with_dbg, check, verify_signatures, keyring):
    """Download all available glibc versions for the given arch(es).

    Skips versions already installed. With --arch all, downloads amd64 + i686
    (x86). Specify --arch arm64 etc. to download all versions for that arch.
    Use --check to see what would be downloaded without downloading.
    """
    glibc_dir = ctx.obj["glibc_dir"]
    if not check:
        _ensure_writable(glibc_dir)
    arches = X86_ARCHES if arch == "all" else [arch]

    mirrors_to_try: set[str] = set()
    if mirror == "auto":
        for a in arches:
            for m in _mirrors_for_arch(a):
                mirrors_to_try.add(m)
    else:
        mirrors_to_try.add(mirror)

    console.print(f"[bold]Fetching all package lists...[/bold] [dim]({', '.join(sorted(mirrors_to_try))})[/dim]")
    all_packages = _scrape_mirrors(mirrors_to_try)
    if mirror == "auto":
        all_packages = _auto_chain_only(all_packages)

    filtered = [p for p in all_packages if p.arch in arches]
    best = _pick_best(filtered)

    installs = discover_installed(glibc_dir)
    installed_map: dict[tuple[str, str], bool] = {}
    for i in installs:
        if i.variant == "deb":
            installed_map[(i.version, i.arch)] = i.has_debug

    to_download: dict[tuple[str, str], DebPackage] = {}
    to_add_dbg: dict[tuple[str, str], DebPackage] = {}
    for k, v in best.items():
        if k not in installed_map:
            to_download[k] = v
        elif with_dbg and not installed_map[k]:
            to_add_dbg[k] = v

    if not to_download and not to_add_dbg:
        console.print("[green]All versions already installed.[/green]")
        return

    if to_download:
        console.print(f"[bold]{len(to_download)} new versions to download:[/bold]")
        for (ver, a) in sorted(to_download.keys(), key=lambda k: (parse_version(k[0]), k[1])):
            console.print(f"  {ver} / {a}")

    if to_add_dbg:
        console.print(f"[bold]{len(to_add_dbg)} versions missing debug symbols:[/bold]")
        for (ver, a) in sorted(to_add_dbg.keys(), key=lambda k: (parse_version(k[0]), k[1])):
            console.print(f"  {ver} / {a}")

    if check:
        return

    any_success = False
    used_pkgs: list[DebPackage] = []
    for (ver, a), pkg in sorted({**to_download, **to_add_dbg}.items(),
                                  key=lambda x: (parse_version(x[0][0]), x[0][1])):
        dl_mirror = pkg.mirror if mirror == "auto" else mirror
        is_dbg_only = (ver, a) in to_add_dbg
        try:
            download_glibc(pkg, glibc_dir, mirror=dl_mirror, include_dbg=with_dbg)
            any_success = True
            used_pkgs.append(pkg)
            label = "debug added" if is_dbg_only else "installed"
            console.print(f"  [green]{ver}/{a} {label}[/green] [dim]({dl_mirror})[/dim]")
        except Exception as e:
            console.print(f"  [red]{ver}/{a} failed: {e}[/red]")

    # Signature checks run BEFORE the ownership repair: verify content
    # first, repair ownership last.
    sig_ok = True
    if verify_signatures and used_pkgs:
        sig_ok = _run_signature_checks(used_pkgs, glibc_dir, keyring)

    if any_success:
        _chown_after_write(glibc_dir)

    if not sig_ok:
        sys.exit(1)


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("versions", nargs=-1, required=True)
@click.option("--arch", type=click.Choice(ALL_ARCHES), required=True,
              help="Target architecture.")
@click.pass_context
def build(ctx, versions, arch):
    """Build glibc from source with debug symbols (-g3).

    Produces a separate 'built' variant alongside deb installs.

    Examples:

      pwnlibc build 2.31 --arch amd64

      pwnlibc build 2.27 2.31 --arch arm64
    """
    from .builder import build_glibc, check_build_deps, check_source_available, get_install_cmd

    glibc_dir = ctx.obj["glibc_dir"]
    _ensure_writable(glibc_dir)

    missing_deps = check_build_deps(arch)
    if missing_deps:
        console.print("[red]Missing build dependencies:[/red]")
        for dep in missing_deps:
            console.print(f"  [red]- {dep}[/red]")
        console.print(f"\n[bold]Install with:[/bold] {get_install_cmd(arch)}")
        sys.exit(1)

    console.print(f"[bold]Build target: {arch}[/bold]")
    info = ARCH_INFO[arch]
    console.print(f"[dim]Cross-compiler: {info['cross_gcc']}  triplet: {info['cross_triplet']}[/dim]")

    any_success = False
    for version in versions:
        console.print(f"\n[bold]Checking source availability for {version}...[/bold]")
        if not check_source_available(version):
            console.print(f"[red]{version}: source not found at ftp.gnu.org. Skipping.[/red]")
            continue

        out_dir = glibc_dir / version / f"{arch}-built"
        if out_dir.is_dir():
            console.print(f"[yellow]{version}/{arch}-built already exists. Rebuilding...[/yellow]")

        result_dir = None
        build_err = None
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.fields[label]}"),
            console=console,
        ) as progress:
            task_id = progress.add_task("", label=f"building {version}/{arch}")

            def cb(stage, downloaded, total, tid=task_id):
                progress.update(tid, description=f"  {stage}")

            try:
                result_dir = build_glibc(version, arch, glibc_dir, progress_cb=cb)
            except Exception as e:
                build_err = e

        if build_err:
            console.print(f"  [red]{version}/{arch} build failed: {build_err}[/red]")
        else:
            any_success = True
            console.print(f"  [green]{version}/{arch}-built installed at {result_dir}[/green]")

    if any_success:
        _chown_after_write(glibc_dir)


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--fix", is_flag=True, help="Re-download and replace mismatched files.")
@click.option("--verbose", "-v", is_flag=True, help="Show MATCH entries too.")
@click.option("--mirror", type=click.Choice(ALL_MIRRORS), default="auto")
@click.option("--verify-signatures", is_flag=True,
              help="After the run, check each Packages index used against the GPG-signed InRelease/Release (gpgv).")
@click.option("--keyring", type=click.Path(path_type=Path), default=None,
              help="Trusted keyring for --verify-signatures (default: distro archive keyring).")
@click.pass_context
def verify(ctx, fix, verbose, mirror, verify_signatures, keyring):
    """Verify installed glibc against official Ubuntu packages.

    Exits with status 1 when problems (MISSING/MISMATCH/errors) are found,
    or with --fix when at least one fix attempt fails (installs whose
    verification errored are retried too). Exits 0 otherwise.
    """
    glibc_dir = ctx.obj["glibc_dir"]
    if fix:
        _ensure_writable(glibc_dir)

    installs = [i for i in discover_installed(glibc_dir) if i.variant == "deb"]
    if not installs:
        console.print("[dim]No deb-installed versions to verify.[/dim]")
        return

    mirrors_to_try: set[str] = set()
    if mirror == "auto":
        for inst in installs:
            for m in _mirrors_for_arch(inst.arch):
                mirrors_to_try.add(m)
    else:
        mirrors_to_try.add(mirror)

    console.print("[bold]Fetching package lists...[/bold]")
    all_packages = _scrape_mirrors(mirrors_to_try)
    if mirror == "auto":
        all_packages = _auto_chain_only(all_packages)
    pkg_map = _pick_best(all_packages)

    table = Table(title="Verification results")
    table.add_column("Version")
    table.add_column("Arch")
    table.add_column("File")
    table.add_column("Status")
    table.add_column("Details")

    versions_to_fix = []
    used_pkgs: list[DebPackage] = []
    match_count = 0
    problem_count = 0
    fix_failed = 0
    has_rows = False

    for inst in installs:
        key = (inst.version, inst.arch)
        pkg = pkg_map.get(key)
        if pkg is None:
            table.add_row(inst.version, inst.arch, "*", "[dim]no ref pkg[/dim]", "")
            has_rows = True
            continue

        used_pkgs.append(pkg)
        console.print(f"[dim]Verifying {inst.version}/{inst.arch}...[/dim]")
        dl_mirror = pkg.mirror if mirror == "auto" else mirror
        try:
            results = verify_against_deb(pkg, glibc_dir, mirror=dl_mirror)
        except Exception as e:
            table.add_row(inst.version, inst.arch, "*", "[red]error[/red]", str(e))
            has_rows = True
            problem_count += 1
            # Verification itself failed — with --fix, retry the install via a
            # fresh download like any other problem (its cached .deb may be the
            # culprit). A failed retry then counts towards fix_failed.
            versions_to_fix.append((inst, pkg))
            continue

        needs_fix = False
        for fname, status, detail in results:
            if status == "MATCH":
                match_count += 1
                if verbose:
                    table.add_row(inst.version, inst.arch, fname, "[green]MATCH[/green]", detail)
                    has_rows = True
            else:
                problem_count += 1
                has_rows = True
                if status == "MISSING":
                    style = "[red]MISSING[/red]"
                elif status == "MISMATCH":
                    style = "[yellow]MISMATCH[/yellow]"
                else:
                    style = f"[red]{status}[/red]"
                needs_fix = True
                table.add_row(inst.version, inst.arch, fname, style, detail)

        if needs_fix:
            versions_to_fix.append((inst, pkg))

    if has_rows:
        console.print(table)

    if problem_count == 0:
        console.print(f"[green]All {match_count} files verified OK.[/green]")
    else:
        console.print(f"\n[green]{match_count} OK[/green], [red]{problem_count} problems[/red]")

    if fix and versions_to_fix:
        console.print(f"\n[bold]Fixing {len(versions_to_fix)} installs...[/bold]")
        for inst, pkg in versions_to_fix:
            dl_mirror = pkg.mirror if mirror == "auto" else mirror
            try:
                download_glibc(pkg, glibc_dir, mirror=dl_mirror)
                console.print(f"  [green]{inst.version}/{inst.arch} replaced[/green]")
            except Exception as e:
                console.print(f"  [red]{inst.version}/{inst.arch} fix failed: {e}[/red]")
                fix_failed += 1

    # Non-zero exit so scripts/CI can detect problems; with --fix only a
    # failed fix attempt is an error (the problems themselves were addressed).
    # A failed --verify-signatures check is ORed in on top.
    sig_ok = True
    if verify_signatures and used_pkgs:
        sig_ok = _run_signature_checks(used_pkgs, glibc_dir, keyring)

    if (not fix and problem_count > 0) or (fix and fix_failed > 0) or not sig_ok:
        sys.exit(1)


# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------

def _is_source_built(path: Path) -> bool:
    """Detect if an extracted glibc dir is source-built (not from a .deb)."""
    for sub in path.iterdir():
        if not sub.is_dir() or sub.name in ("source", ".debug"):
            continue
        lib_dir = sub / "lib"
        if not lib_dir.is_dir():
            continue
        if any(lib_dir.glob("*.a")) or (sub / "libexec").is_dir():
            return True
    return False


@cli.command()
@click.argument("archive_dir", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--target-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Where to extract (default: glibc-dir).",
)
@click.option("--variant", type=click.Choice(["auto", "deb", "built"]), default="auto",
              help="auto: detect from archive contents. Source-built archives (.a files, libexec/) → built variant.")
@click.pass_context
def setup(ctx, archive_dir, target_dir, variant):
    """Extract .tar.gz archives to glibc dir.

    Archives containing .a static libraries or libexec/ directories are
    detected as source-built and placed under <arch>-built/ (not <arch>/).
    Override with --variant deb or --variant built.

    ARCHIVE_DIR is the directory containing .tar.gz glibc archives.

    Examples:

      pwnlibc setup ./debug_glibc

      pwnlibc setup /path/to/archives --target-dir /opt/glibc
    """
    glibc_dir = ctx.obj["glibc_dir"]
    if target_dir is None:
        target_dir = glibc_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    _ensure_writable(target_dir)

    archives = sorted(archive_dir.glob("*.tar.gz"))
    if not archives:
        console.print(f"[red]No .tar.gz files found in {archive_dir}[/red]")
        sys.exit(1)

    console.print(f"Extracting {len(archives)} archives to {target_dir}")

    import tempfile

    any_success = False
    for arc in archives:
        version = arc.stem.replace(".tar", "")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with tarfile.open(arc, "r:gz") as tf:
                try:
                    tf.extractall(path=tmp_path, filter="data")
                except TypeError:
                    # Python without the (backported) filter= parameter
                    tf.extractall(path=tmp_path)

            extracted = tmp_path / version
            if not extracted.is_dir():
                candidates = [d for d in tmp_path.iterdir() if d.is_dir()]
                if len(candidates) == 1:
                    extracted = candidates[0]
                else:
                    console.print(f"  [red]{arc.name}: unexpected archive layout[/red]")
                    continue

            detected_variant = variant
            if variant == "auto":
                detected_variant = "built" if _is_source_built(extracted) else "deb"

            dest = target_dir / version
            dest.mkdir(parents=True, exist_ok=True)

            for sub in sorted(extracted.iterdir()):
                if not sub.is_dir():
                    continue

                if sub.name == "source":
                    final = dest / "source"
                    if final.is_dir():
                        console.print(f"  [dim]{version}/source already exists, skipping[/dim]")
                        continue
                    shutil.copytree(sub, final)
                    continue

                arch_name = sub.name
                if detected_variant == "built":
                    final_name = f"{arch_name}-built"
                else:
                    final_name = arch_name

                final = dest / final_name
                if final.is_dir():
                    console.print(f"  [dim]{version}/{final_name} already exists, skipping[/dim]")
                    continue

                shutil.copytree(sub, final)

            console.print(
                f"  [green]{version} done[/green] "
                f"[dim]({detected_variant} variant)[/dim]"
            )
            any_success = True

    if any_success:
        _chown_after_write(target_dir)

    console.print("[green]Setup complete.[/green]")


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("binary", type=click.Path(exists=True, path_type=Path))
def info(binary):
    """Show ELF info for a binary (arch, needed libs, interpreter)."""
    binary = binary.resolve()
    try:
        arch = detect_arch(binary)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    from .elfutil import get_needed_libs

    needed = get_needed_libs(binary)

    interp = None
    try:
        result = subprocess.run(
            ["patchelf", "--print-interpreter", str(binary)],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            interp = result.stdout.strip()
    except FileNotFoundError:
        pass

    rpath = None
    try:
        result = subprocess.run(
            ["patchelf", "--print-rpath", str(binary)],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            rpath = result.stdout.strip()
    except FileNotFoundError:
        pass

    console.print(f"[bold]Binary:[/bold] {binary}")
    console.print(f"[bold]Architecture:[/bold] {arch}")
    if interp:
        console.print(f"[bold]Interpreter:[/bold] {interp}")
    if rpath:
        console.print(f"[bold]RPATH:[/bold] {rpath}")
    console.print(f"[bold]NEEDED libraries:[/bold]")
    for lib in needed:
        console.print(f"  {lib}")
