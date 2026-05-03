from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
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

from .config import ALL_ARCHES, ARCH_INFO, BUILD_DEPS, DEFAULT_GLIBC_DIR, X86_ARCHES, parse_version, uses_new_naming
from .downloader import (
    DebPackage,
    download_glibc,
    download_source,
    scrape_available,
    verify_against_deb,
)
from .elfutil import detect_arch
from .glibc import discover_installed, resolve_lib_paths
from .patcher import patch_copy, patch_inplace

console = Console()

ALL_MIRRORS = ["ubuntu", "old-ubuntu", "tsinghua", "ports", "debian", "old-debian", "auto"]


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


def _check_writable(glibc_dir: Path) -> None:
    if not glibc_dir.exists():
        console.print(f"[red]Glibc directory {glibc_dir} does not exist.[/red]")
        console.print(f"[dim]Run: sudo mkdir -p {glibc_dir} && sudo chown $(id -u):$(id -g) {glibc_dir}[/dim]")
        console.print(f"[dim]Or run: bash install.sh[/dim]")
        sys.exit(1)
    if not os.access(glibc_dir, os.W_OK):
        console.print(f"[red]No write permission on {glibc_dir}.[/red]")
        console.print(f"[dim]Run: sudo chown $(id -u):$(id -g) {glibc_dir}[/dim]")
        sys.exit(1)


def _mirror_for_arch(arch: str) -> str:
    return ARCH_INFO.get(arch, {}).get("mirror", "ubuntu")


def _scrape_mirrors(mirrors: set[str]) -> list[DebPackage]:
    pkgs: list[DebPackage] = []
    for m in sorted(mirrors):
        try:
            pkgs.extend(scrape_available(m))
        except Exception as e:
            console.print(f"[yellow]Failed to fetch {m}: {e}[/yellow]")
    return pkgs


def _pick_best(packages: list[DebPackage]) -> dict[tuple[str, str], DebPackage]:
    best: dict[tuple[str, str], DebPackage] = {}
    for pkg in packages:
        key = (pkg.version, pkg.arch)
        existing = best.get(key)
        if existing is None or pkg.full_id > existing.full_id:
            best[key] = pkg
    return best


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

    versions: dict[str, dict[str, list]] = {}
    for inst in installs:
        if arch != "all" and inst.arch != arch:
            continue
        versions.setdefault(inst.version, {}).setdefault(inst.arch, []).append(inst)

    present_arches = sorted({a for v in versions.values() for a in v})
    if not present_arches:
        present_arches = X86_ARCHES

    table = Table(title="Installed glibc versions")
    table.add_column("Version", style="bold")
    for a in present_arches:
        table.add_column(a)
    table.add_column("Debug", justify="center")
    table.add_column("Source", justify="center")
    table.add_column("Naming")

    for ver in sorted(versions.keys(), key=lambda v: parse_version(v)):
        data = versions[ver]
        row = []
        any_inst = None
        for a in present_arches:
            arch_installs = data.get(a, [])
            if not arch_installs:
                row.append("[dim]-[/dim]")
            else:
                variants = [i.variant for i in arch_installs]
                labels = []
                if "deb" in variants:
                    labels.append("deb")
                if "built" in variants:
                    labels.append("built")
                row.append("[green]" + "+".join(labels) + "[/green]")
                if any_inst is None:
                    any_inst = arch_installs[0]

        if any_inst and any_inst.has_debug:
            debug_str = "[green]yes[/green]"
        elif any_inst:
            debug_str = "[yellow]no[/yellow]"
        else:
            debug_str = "[dim]-[/dim]"

        source_str = "[green]yes[/green]" if any_inst and any_inst.has_source else "[dim]-[/dim]"
        naming = "new (>=2.34)" if uses_new_naming(ver) else "old"
        table.add_row(ver, *row, debug_str, source_str, naming)

    console.print(table)

    if not versions:
        console.print("[dim]No glibc versions found.[/dim]")
        console.print(f"[dim]Looking in: {glibc_dir}[/dim]")
        console.print("[dim]Use 'pwnlibc available' to see downloadable versions.[/dim]")


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
@click.pass_context
def available(ctx, arch, mirror):
    """List glibc versions available for download."""
    glibc_dir = ctx.obj["glibc_dir"]

    arches = ALL_ARCHES if arch == "all" else [arch]
    mirrors_to_try: set[str] = set()
    if mirror == "auto":
        for a in arches:
            mirrors_to_try.add(_mirror_for_arch(a))
        mirrors_to_try.add("old-ubuntu")
    else:
        mirrors_to_try.add(mirror)

    console.print("[bold]Fetching package lists...[/bold]")
    packages = _scrape_mirrors(mirrors_to_try)
    if not packages:
        console.print("[red]No packages found.[/red]")
        return

    installs = discover_installed(glibc_dir)
    installed_keys = {(i.version, i.arch, i.variant) for i in installs}
    installed_ver_arch = {(i.version, i.arch) for i in installs}

    best = _pick_best([p for p in packages if p.arch in arches])

    by_version: dict[str, dict[str, DebPackage]] = {}
    for (ver, a), pkg in best.items():
        by_version.setdefault(ver, {})[a] = pkg

    table = Table(title="Available glibc packages")
    table.add_column("#", style="dim")
    table.add_column("Version", style="bold")
    table.add_column("Arch")
    table.add_column("Installed", justify="center")

    entries: list[tuple[str, str, DebPackage]] = []
    idx = 1
    for ver in sorted(by_version.keys(), key=lambda v: parse_version(v)):
        for a in sorted(by_version[ver].keys()):
            pkg = by_version[ver][a]

            if (ver, a) in installed_ver_arch:
                inst_str = "[green]yes[/green]"
            else:
                inst_str = "[dim]-[/dim]"

            table.add_row(str(idx), ver, a, inst_str)
            entries.append((ver, a, pkg))
            idx += 1

    console.print(table)
    console.print(f"\n[dim]Total: {len(entries)} entries. "
                  f"Use 'pwnlibc download VERSION --arch ARCH' to download specific entries.[/dim]")
    console.print(f"[dim]Use 'pwnlibc download-all --arch ARCH' to download all for one arch.[/dim]")
    console.print(f"[dim]Use 'pwnlibc download-all' to download all for x86 (amd64+i686).[/dim]")


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
    help="inplace: absolute paths to /glibc/ (default). copy: libs to binary dir.",
)
@click.option("--variant", type=click.Choice(["deb", "built", "auto"]), default="auto",
              help="Which glibc variant to use.")
@click.option("--no-rpath", is_flag=True, help="Don't set RPATH.")
@click.pass_context
def patch(ctx, binary, glibc_version, arch, mode, variant, no_rpath):
    """Patch an ELF binary to use a specific glibc version.

    Creates <binary>.patched — the original is never modified.
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

    glibc = None
    if variant == "auto":
        for v in ["deb", "built"]:
            try:
                glibc = resolve_lib_paths(glibc_version, arch, glibc_dir, v)
                break
            except FileNotFoundError:
                continue
    else:
        try:
            glibc = resolve_lib_paths(glibc_version, arch, glibc_dir, variant)
        except FileNotFoundError:
            pass

    if glibc is None:
        console.print(f"[red]Glibc {glibc_version} ({arch}) not found.[/red]")
        console.print(f"[dim]Run: pwnlibc download {glibc_version} --arch {arch}[/dim]")
        sys.exit(1)

    if glibc.variant != "deb":
        console.print(f"Using [bold]{glibc.variant}[/bold] variant")

    if not glibc.has_debug:
        console.print(
            f"[yellow]Warning: no debug symbols. "
            f"Try: pwnlibc download {glibc_version} --with-dbg  or  pwnlibc build {glibc_version} --arch {arch}[/yellow]"
        )

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
        f"glibc {glibc_version} ({arch}, {mode}, {glibc.variant})[/green]"
    )


# ---------------------------------------------------------------------------
# restore
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("binary", type=click.Path(exists=True, path_type=Path))
def restore(binary):
    """Remove .patched file (and copied libs from copy-mode patching)."""
    binary = binary.resolve()

    from .patcher import PATCHED_SUFFIX
    patched = binary.parent / (binary.name + PATCHED_SUFFIX)

    if patched.exists():
        patched.unlink()
        console.print(f"[green]Removed {patched.name}[/green]")
    else:
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
    _check_writable(glibc_dir)

    for version in versions:
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

        if variant in ("source", "all"):
            source_dir = ver_dir / "source"
            if source_dir.is_dir():
                _rmtree_verbose(source_dir, "source")
                removed_any = True

        # Auto-remove source when no deb/built remains
        if variant not in ("source", "all") and ver_dir.is_dir():
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
                for deb_file in cache_dir.glob(f"libc6*_{version}-*"):
                    deb_file.unlink()
                    console.print(f"  [dim]Removed cache: {deb_file.name}[/dim]")

        if ver_dir.is_dir() and not any(ver_dir.iterdir()):
            ver_dir.rmdir()
            console.print(f"  [dim]Removed empty {version}/ directory[/dim]")

        if not removed_any:
            console.print(f"  [yellow]Nothing to remove for given filters[/yellow]")


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
@click.pass_context
def download(ctx, versions, arch, mirror, with_dbg, source):
    """Download one or more glibc versions.

    Examples:

      pwnlibc download 2.31

      pwnlibc download 2.27 2.31 2.35

      pwnlibc download 2.31 --arch arm64
    """
    glibc_dir = ctx.obj["glibc_dir"]
    _check_writable(glibc_dir)
    archs_to_download = X86_ARCHES if arch == "all" else [arch]

    mirrors_to_try: set[str] = set()
    if mirror == "auto":
        for a in archs_to_download:
            mirrors_to_try.add(_mirror_for_arch(a))
    else:
        mirrors_to_try.add(mirror)

    console.print("[bold]Fetching package lists...[/bold]")
    all_packages = _scrape_mirrors(mirrors_to_try)

    any_success = False
    for version in versions:
        matching = [
            p for p in all_packages
            if p.version == version and p.arch in archs_to_download
        ]

        if not matching:
            console.print(f"[red]{version}: not found on mirrors. Try --mirror old-ubuntu[/red]")
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

                dl_mirror = _mirror_for_arch(pkg_arch) if mirror == "auto" else mirror
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
                console.print(f"  [green]{version}/{pkg_arch} installed[/green]")

        if source:
            console.print(f"[dim]Downloading source for {version}...[/dim]")
            try:
                download_source(version, glibc_dir)
            except Exception as e:
                console.print(f"[yellow]Source download failed: {e}[/yellow]")

    if not any_success:
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
@click.pass_context
def download_all(ctx, arch, mirror, with_dbg, check):
    """Download all available glibc versions for the given arch(es).

    Skips versions already installed. With --arch all, downloads amd64 + i686
    (x86). Specify --arch arm64 etc. to download all versions for that arch.
    Use --check to see what would be downloaded without downloading.
    """
    glibc_dir = ctx.obj["glibc_dir"]
    if not check:
        _check_writable(glibc_dir)
    arches = X86_ARCHES if arch == "all" else [arch]

    mirrors_to_try: set[str] = set()
    if mirror == "auto":
        for a in arches:
            mirrors_to_try.add(_mirror_for_arch(a))
        mirrors_to_try.add("old-ubuntu")
    else:
        mirrors_to_try.add(mirror)

    console.print("[bold]Fetching all package lists...[/bold]")
    all_packages = _scrape_mirrors(mirrors_to_try)

    filtered = [p for p in all_packages if p.arch in arches]
    best = _pick_best(filtered)

    installs = discover_installed(glibc_dir)
    installed_keys = {(i.version, i.arch) for i in installs}

    to_download = {k: v for k, v in best.items() if k not in installed_keys}

    if not to_download:
        console.print("[green]All versions already installed.[/green]")
        return

    console.print(f"[bold]{len(to_download)} entries to download:[/bold]")
    for (ver, a) in sorted(to_download.keys(), key=lambda k: (parse_version(k[0]), k[1])):
        console.print(f"  {ver} / {a}")

    if check:
        return

    for (ver, a), pkg in sorted(to_download.items(), key=lambda x: (parse_version(x[0][0]), x[0][1])):
        dl_mirror = _mirror_for_arch(a) if mirror == "auto" else mirror
        try:
            download_glibc(pkg, glibc_dir, mirror=dl_mirror, include_dbg=with_dbg)
            console.print(f"  [green]{ver}/{a} installed[/green]")
        except Exception as e:
            console.print(f"  [red]{ver}/{a} failed: {e}[/red]")


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
    _check_writable(glibc_dir)

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
            console.print(f"  [green]{version}/{arch}-built installed at {result_dir}[/green]")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--fix", is_flag=True, help="Re-download and replace mismatched files.")
@click.option("--verbose", "-v", is_flag=True, help="Show MATCH entries too.")
@click.option("--mirror", type=click.Choice(ALL_MIRRORS), default="auto")
@click.pass_context
def verify(ctx, fix, verbose, mirror):
    """Verify installed glibc against official Ubuntu packages."""
    glibc_dir = ctx.obj["glibc_dir"]
    if fix:
        _check_writable(glibc_dir)

    installs = [i for i in discover_installed(glibc_dir) if i.variant == "deb"]
    if not installs:
        console.print("[dim]No deb-installed versions to verify.[/dim]")
        return

    mirrors_to_try: set[str] = set()
    if mirror == "auto":
        for inst in installs:
            mirrors_to_try.add(_mirror_for_arch(inst.arch))
    else:
        mirrors_to_try.add(mirror)

    console.print("[bold]Fetching package lists...[/bold]")
    all_packages = _scrape_mirrors(mirrors_to_try)
    pkg_map = _pick_best(all_packages)

    table = Table(title="Verification results")
    table.add_column("Version")
    table.add_column("Arch")
    table.add_column("File")
    table.add_column("Status")
    table.add_column("Details")

    versions_to_fix = []
    match_count = 0
    problem_count = 0
    has_rows = False

    for inst in installs:
        key = (inst.version, inst.arch)
        pkg = pkg_map.get(key)
        if pkg is None:
            table.add_row(inst.version, inst.arch, "*", "[dim]no ref pkg[/dim]", "")
            has_rows = True
            continue

        console.print(f"[dim]Verifying {inst.version}/{inst.arch}...[/dim]")
        dl_mirror = _mirror_for_arch(inst.arch) if mirror == "auto" else mirror
        try:
            results = verify_against_deb(pkg, glibc_dir, mirror=dl_mirror)
        except Exception as e:
            table.add_row(inst.version, inst.arch, "*", "[red]error[/red]", str(e))
            has_rows = True
            problem_count += 1
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
            dl_mirror = _mirror_for_arch(inst.arch) if mirror == "auto" else mirror
            try:
                download_glibc(pkg, glibc_dir, mirror=dl_mirror)
                console.print(f"  [green]{inst.version}/{inst.arch} replaced[/green]")
            except Exception as e:
                console.print(f"  [red]{inst.version}/{inst.arch} fix failed: {e}[/red]")


# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--archive-dir",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Directory with .tar.gz archives.",
)
@click.option(
    "--target-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Where to extract (default: glibc-dir).",
)
@click.pass_context
def setup(ctx, archive_dir, target_dir):
    """Extract .tar.gz archives from debug_glibc to glibc dir."""
    glibc_dir = ctx.obj["glibc_dir"]
    if target_dir is None:
        target_dir = glibc_dir
    _check_writable(target_dir if target_dir.exists() else glibc_dir)
    if archive_dir is None:
        guess = Path.home() / "Desktop" / "infrastructure" / "pwn-env" / "debug_glibc"
        if guess.is_dir():
            archive_dir = guess
        else:
            console.print("[red]Specify --archive-dir (directory with .tar.gz files)[/red]")
            sys.exit(1)

    archives = sorted(archive_dir.glob("*.tar.gz"))
    if not archives:
        console.print(f"[red]No .tar.gz files found in {archive_dir}[/red]")
        sys.exit(1)

    target_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"Extracting {len(archives)} archives to {target_dir}")

    for arc in archives:
        version = arc.stem.replace(".tar", "")
        dest = target_dir / version
        if dest.is_dir():
            console.print(f"  [dim]{version} already exists, skipping[/dim]")
            continue
        console.print(f"  Extracting {arc.name}...")
        with tarfile.open(arc, "r:gz") as tf:
            tf.extractall(path=target_dir)
        console.print(f"  [green]{version} done[/green]")

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
