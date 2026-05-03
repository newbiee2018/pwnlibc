from __future__ import annotations

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
    TextColumn,
    TransferSpeedColumn,
)
from rich.table import Table

from .backup import create_backup, restore_backup
from .config import ALL_ARCHES, ARCH_INFO, DEFAULT_GLIBC_DIR, X86_ARCHES, parse_version, uses_new_naming
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


def _mirror_for_arch(arch: str) -> str:
    return ARCH_INFO.get(arch, {}).get("mirror", "ubuntu")

console = Console()


@click.group()
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


@cli.command("list")
@click.option("--arch", type=click.Choice(ALL_ARCHES + ["all"]), default="all")
@click.option("--available", is_flag=True, help="Show versions available for download.")
@click.pass_context
def list_cmd(ctx, arch, available):
    """List installed glibc versions."""
    glibc_dir = ctx.obj["glibc_dir"]
    installs = discover_installed(glibc_dir)

    versions: dict[str, dict] = {}
    for inst in installs:
        if arch != "all" and inst.arch != arch:
            continue
        if inst.version not in versions:
            versions[inst.version] = {}
        versions[inst.version][inst.arch] = inst

    present_arches = sorted({a for v in versions.values() for a in v})
    if not present_arches:
        present_arches = X86_ARCHES

    table = Table(title="Installed glibc versions")
    table.add_column("Version", style="bold")
    for a in present_arches:
        table.add_column(a)
    table.add_column("Debug", justify="center")
    table.add_column("Naming")

    for ver in sorted(versions.keys(), key=lambda v: parse_version(v)):
        data = versions[ver]
        row = []
        any_inst = None
        for a in present_arches:
            inst = data.get(a)
            row.append("[green]yes[/green]" if inst else "[dim]-[/dim]")
            if inst:
                any_inst = inst

        if any_inst and any_inst.has_debug:
            debug_str = "[green]yes[/green]"
        elif any_inst:
            debug_str = "[yellow]no[/yellow]"
        else:
            debug_str = "[dim]-[/dim]"

        naming = "new (>=2.34)" if uses_new_naming(ver) else "old"
        table.add_row(ver, *row, debug_str, naming)

    console.print(table)

    if not versions:
        console.print("[dim]No glibc versions found.[/dim]")
        console.print(f"[dim]Looking in: {glibc_dir}[/dim]")

    if available:
        console.print()
        _show_available(glibc_dir, set(versions.keys()))


def _show_available(glibc_dir: Path, installed: set[str]):
    console.print("[bold]Checking available versions from Ubuntu mirrors...[/bold]")
    packages: list[DebPackage] = []
    for m in ["ubuntu", "ports"]:
        try:
            packages.extend(scrape_available(m))
        except Exception:
            pass
    if not packages:
        try:
            packages = scrape_available("old-ubuntu")
        except Exception:
            console.print("[red]Failed to fetch mirrors.[/red]")
            return

    available_versions: dict[str, list[DebPackage]] = {}
    for pkg in packages:
        if pkg.version not in installed:
            available_versions.setdefault(pkg.version, []).append(pkg)

    if not available_versions:
        console.print("[green]All available versions are installed.[/green]")
        return

    table = Table(title="Available for download")
    table.add_column("Version", style="bold")
    table.add_column("Packages")
    table.add_column("Has debug .deb", justify="center")

    for ver in sorted(available_versions.keys(), key=lambda v: parse_version(v)):
        pkgs = available_versions[ver]
        archs = ", ".join(sorted(set(p.arch for p in pkgs)))
        has_dbg = any(p.dbg_filename for p in pkgs)
        dbg_str = "[green]yes[/green]" if has_dbg else "[yellow]no (source compile needed)[/yellow]"
        table.add_row(ver, archs, dbg_str)

    console.print(table)


@cli.command()
@click.argument("binary", type=click.Path(exists=True, path_type=Path))
@click.option("-v", "--version", "glibc_version", required=True, help="Glibc version.")
@click.option("-a", "--arch", type=click.Choice(ALL_ARCHES), default=None)
@click.option(
    "-m", "--mode",
    type=click.Choice(["copy", "inplace"]),
    default="copy",
    help="copy: libs to binary dir. inplace: absolute paths to /glibc/.",
)
@click.option("--no-backup", is_flag=True, help="Skip backup.")
@click.option("--no-rpath", is_flag=True, help="Don't set RPATH.")
@click.pass_context
def patch(ctx, binary, glibc_version, arch, mode, no_backup, no_rpath):
    """Patch an ELF binary to use a specific glibc version."""
    binary = binary.resolve()
    glibc_dir = ctx.obj["glibc_dir"]

    if arch is None:
        try:
            arch = detect_arch(binary)
            console.print(f"Detected architecture: [bold]{arch}[/bold]")
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)

    try:
        glibc = resolve_lib_paths(glibc_version, arch, glibc_dir)
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    if not glibc.has_debug:
        console.print(
            f"[yellow]Warning: glibc {glibc_version} has no debug symbols. "
            f"Consider: pwnlibc download {glibc_version} --with-dbg[/yellow]"
        )

    if not no_backup:
        bak = create_backup(binary)
        console.print(f"Backup: {bak}")

    try:
        if mode == "copy":
            copied = patch_copy(binary, glibc, set_rpath=not no_rpath)
            console.print(f"Copied {len(copied)} files to {binary.parent}")
        else:
            patch_inplace(binary, glibc, set_rpath=not no_rpath)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    console.print(
        f"[green]Patched [bold]{binary.name}[/bold] -> "
        f"glibc {glibc_version} ({arch}, {mode} mode)[/green]"
    )


@cli.command()
@click.argument("binary", type=click.Path(exists=True, path_type=Path))
def restore(binary):
    """Restore a binary from backup."""
    binary = binary.resolve()
    removed = restore_backup(binary)
    if removed:
        console.print(f"[green]Restored {binary.name} from {removed.name}[/green]")
    else:
        console.print(f"[red]No backup found for {binary.name}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("version")
@click.option("--arch", type=click.Choice(ALL_ARCHES + ["all"]), default="all")
@click.option(
    "--mirror",
    type=click.Choice(["ubuntu", "old-ubuntu", "tsinghua", "ports", "auto"]),
    default="auto",
    help="auto: pick mirror per arch (ubuntu for x86, ports for arm/ppc/...).",
)
@click.option("--with-dbg/--no-dbg", default=True, help="Include debug symbols.")
@click.option("--source", is_flag=True, help="Also download GNU source.")
@click.pass_context
def download(ctx, version, arch, mirror, with_dbg, source):
    """Download a glibc version from Ubuntu mirrors."""
    glibc_dir = ctx.obj["glibc_dir"]
    archs_to_download = X86_ARCHES if arch == "all" else [arch]

    all_packages: list[DebPackage] = []
    mirrors_to_try: set[str] = set()
    if mirror == "auto":
        for a in archs_to_download:
            mirrors_to_try.add(_mirror_for_arch(a))
    else:
        mirrors_to_try.add(mirror)

    for m in sorted(mirrors_to_try):
        console.print(f"[bold]Fetching package list from {m} mirror...[/bold]")
        try:
            all_packages.extend(scrape_available(m))
        except Exception as e:
            console.print(f"[yellow]Failed to fetch {m} index: {e}[/yellow]")

    matching = [
        p for p in all_packages
        if p.version == version and p.arch in archs_to_download
    ]

    if not matching:
        console.print(f"[red]Version {version} not found for {arch}.[/red]")
        console.print("[dim]Try: --mirror old-ubuntu, or --arch to pick a specific arch[/dim]")
        sys.exit(1)

    best: dict[str, DebPackage] = {}
    for pkg in matching:
        existing = best.get(pkg.arch)
        if existing is None or pkg.full_id > existing.full_id:
            best[pkg.arch] = pkg

    with Progress(
        TextColumn("[bold]{task.fields[label]}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        console=console,
    ) as progress:
        for pkg_arch, pkg in sorted(best.items()):
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
                console.print(f"[red]Failed to download {pkg.filename}: {e}[/red]")
                continue

            console.print(f"  [green]Installed {version}/{pkg_arch}[/green]")

    if source:
        console.print(f"[bold]Downloading GNU source for {version}...[/bold]")
        try:
            download_source(version, glibc_dir)
            console.print(f"  [green]Source installed to {glibc_dir}/{version}/source/[/green]")
        except Exception as e:
            console.print(f"[red]Failed to download source: {e}[/red]")


@cli.command()
@click.option("--check", is_flag=True, help="Dry run.")
@click.option("--arch", type=click.Choice(ALL_ARCHES + ["all"]), default="all",
              help="Which arches to update (default: all installed + x86).")
@click.option(
    "--mirror",
    type=click.Choice(["ubuntu", "old-ubuntu", "tsinghua", "ports", "auto"]),
    default="auto",
)
@click.pass_context
def update(ctx, check, arch, mirror):
    """Download missing glibc versions."""
    glibc_dir = ctx.obj["glibc_dir"]
    installs = discover_installed(glibc_dir)
    installed_keys = {(i.version, i.arch) for i in installs}

    arches = X86_ARCHES if arch == "all" else [arch]
    mirrors_to_try: set[str] = set()
    if mirror == "auto":
        for a in arches:
            mirrors_to_try.add(_mirror_for_arch(a))
    else:
        mirrors_to_try.add(mirror)

    all_packages: list[DebPackage] = []
    for m in sorted(mirrors_to_try):
        console.print(f"[bold]Checking {m} mirror...[/bold]")
        try:
            all_packages.extend(scrape_available(m))
        except Exception as e:
            console.print(f"[yellow]Failed to fetch {m} index: {e}[/yellow]")

    missing: dict[str, list[DebPackage]] = {}
    for pkg in all_packages:
        if pkg.arch in arches and (pkg.version, pkg.arch) not in installed_keys:
            missing.setdefault(pkg.version, []).append(pkg)

    if not missing:
        console.print("[green]All available versions are installed.[/green]")
        return

    table = Table(title="Missing versions")
    table.add_column("Version")
    table.add_column("Architectures")
    for ver in sorted(missing.keys(), key=lambda v: parse_version(v)):
        archs_str = ", ".join(sorted(set(p.arch for p in missing[ver])))
        table.add_row(ver, archs_str)
    console.print(table)

    if check:
        console.print(f"[dim]{len(missing)} versions would be downloaded.[/dim]")
        return

    for ver in sorted(missing.keys(), key=lambda v: parse_version(v)):
        console.print(f"\n[bold]Downloading {ver}...[/bold]")
        best: dict[str, DebPackage] = {}
        for pkg in missing[ver]:
            existing = best.get(pkg.arch)
            if existing is None or pkg.full_id > existing.full_id:
                best[pkg.arch] = pkg

        for pkg in best.values():
            dl_mirror = _mirror_for_arch(pkg.arch) if mirror == "auto" else mirror
            try:
                download_glibc(pkg, glibc_dir, mirror=dl_mirror)
                console.print(f"  [green]{ver}/{pkg.arch} installed[/green]")
            except Exception as e:
                console.print(f"  [red]{ver}/{pkg.arch} failed: {e}[/red]")


@cli.command()
@click.option("--fix", is_flag=True, help="Re-download and replace mismatched files.")
@click.option(
    "--mirror",
    type=click.Choice(["ubuntu", "old-ubuntu", "tsinghua", "ports", "auto"]),
    default="auto",
)
@click.pass_context
def verify(ctx, fix, mirror):
    """Verify installed glibc against official Ubuntu packages."""
    glibc_dir = ctx.obj["glibc_dir"]

    installs = discover_installed(glibc_dir)
    if not installs:
        console.print("[dim]No installed versions to verify.[/dim]")
        return

    mirrors_to_try: set[str] = set()
    if mirror == "auto":
        for inst in installs:
            mirrors_to_try.add(_mirror_for_arch(inst.arch))
    else:
        mirrors_to_try.add(mirror)

    all_packages: list[DebPackage] = []
    for m in sorted(mirrors_to_try):
        console.print(f"[bold]Fetching package list from {m}...[/bold]")
        try:
            all_packages.extend(scrape_available(m))
        except Exception as e:
            console.print(f"[yellow]Failed to fetch {m} index: {e}[/yellow]")

    pkg_map: dict[tuple[str, str], DebPackage] = {}
    for pkg in all_packages:
        key = (pkg.version, pkg.arch)
        existing = pkg_map.get(key)
        if existing is None or pkg.full_id > existing.full_id:
            pkg_map[key] = pkg

    table = Table(title="Verification results")
    table.add_column("Version")
    table.add_column("Arch")
    table.add_column("File")
    table.add_column("Status")
    table.add_column("Details")

    versions_to_fix = []

    for inst in installs:
        key = (inst.version, inst.arch)
        pkg = pkg_map.get(key)
        if pkg is None:
            table.add_row(inst.version, inst.arch, "*", "[dim]no ref pkg[/dim]", "")
            continue

        console.print(f"[dim]Verifying {inst.version}/{inst.arch}...[/dim]")
        dl_mirror = _mirror_for_arch(inst.arch) if mirror == "auto" else mirror
        try:
            results = verify_against_deb(pkg, glibc_dir, mirror=dl_mirror)
        except Exception as e:
            table.add_row(inst.version, inst.arch, "*", "[red]error[/red]", str(e))
            continue

        needs_fix = False
        for fname, status, detail in results:
            if status == "MATCH":
                style = "[green]MATCH[/green]"
            elif status == "MISSING":
                style = "[red]MISSING[/red]"
                needs_fix = True
            elif status == "MISMATCH":
                style = "[yellow]MISMATCH[/yellow]"
                needs_fix = True
            else:
                style = f"[red]{status}[/red]"
                needs_fix = True
            table.add_row(inst.version, inst.arch, fname, style, detail)

        if needs_fix:
            versions_to_fix.append((inst, pkg))

    console.print(table)

    if fix and versions_to_fix:
        console.print(f"\n[bold]Fixing {len(versions_to_fix)} installs...[/bold]")
        for inst, pkg in versions_to_fix:
            dl_mirror = _mirror_for_arch(inst.arch) if mirror == "auto" else mirror
            try:
                download_glibc(pkg, glibc_dir, mirror=dl_mirror)
                console.print(f"  [green]{inst.version}/{inst.arch} replaced[/green]")
            except Exception as e:
                console.print(f"  [red]{inst.version}/{inst.arch} fix failed: {e}[/red]")


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
