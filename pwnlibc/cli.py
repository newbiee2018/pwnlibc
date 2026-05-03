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
    SpinnerColumn,
    TextColumn,
    TransferSpeedColumn,
)
from rich.table import Table

from .backup import create_backup, restore_backup
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

ALL_MIRRORS = ["ubuntu", "old-ubuntu", "tsinghua", "ports", "auto"]


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
    table.add_column("Debug .deb", justify="center")
    table.add_column("GNU source", justify="center")
    table.add_column("Installed", justify="center")

    entries: list[tuple[str, str, DebPackage]] = []
    idx = 1
    for ver in sorted(by_version.keys(), key=lambda v: parse_version(v)):
        for a in sorted(by_version[ver].keys()):
            pkg = by_version[ver][a]
            has_dbg = "[green]yes[/green]" if pkg.dbg_filename else "[yellow]no[/yellow]"
            src_avail = "[dim]?[/dim]"

            if (ver, a) in installed_ver_arch:
                inst_str = "[green]yes[/green]"
            else:
                inst_str = "[dim]-[/dim]"

            table.add_row(str(idx), ver, a, has_dbg, src_avail, inst_str)
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
    default="copy",
    help="copy: libs to binary dir. inplace: absolute paths to /glibc/.",
)
@click.option("--variant", type=click.Choice(["deb", "built", "auto"]), default="auto",
              help="Which glibc variant to use.")
@click.option("--no-backup", is_flag=True, help="Skip backup.")
@click.option("--no-rpath", is_flag=True, help="Don't set RPATH.")
@click.pass_context
def patch(ctx, binary, glibc_version, arch, mode, variant, no_backup, no_rpath):
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

    # Try variants in order of preference
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
        f"glibc {glibc_version} ({arch}, {mode} mode, {glibc.variant})[/green]"
    )


# ---------------------------------------------------------------------------
# restore
# ---------------------------------------------------------------------------

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
@click.option("--source", is_flag=True, help="Also download GNU source.")
@click.pass_context
def download(ctx, versions, arch, mirror, with_dbg, source):
    """Download one or more glibc versions.

    Examples:

      pwnlibc download 2.31

      pwnlibc download 2.27 2.31 2.35

      pwnlibc download 2.31 --arch arm64
    """
    glibc_dir = ctx.obj["glibc_dir"]
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

    With --arch all, downloads amd64 + i686 (x86).
    Specify --arch arm64 etc. to download all versions for that arch.
    """
    glibc_dir = ctx.obj["glibc_dir"]
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
                console.print(f"  [green]{version}/{arch}-built installed at {result_dir}[/green]")
            except Exception as e:
                console.print(f"  [red]{version}/{arch} build failed: {e}[/red]")


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--check", is_flag=True, help="Dry run.")
@click.option("--arch", type=click.Choice(ALL_ARCHES + ["all"]), default="all",
              help="Which arches to update.")
@click.option("--mirror", type=click.Choice(ALL_MIRRORS), default="auto")
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

    console.print("[bold]Checking mirrors...[/bold]")
    all_packages = _scrape_mirrors(mirrors_to_try)

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
        best_for_ver = _pick_best(missing[ver])
        for (_, pkg_arch), pkg in sorted(best_for_ver.items()):
            dl_mirror = _mirror_for_arch(pkg_arch) if mirror == "auto" else mirror
            try:
                download_glibc(pkg, glibc_dir, mirror=dl_mirror)
                console.print(f"  [green]{ver}/{pkg_arch} installed[/green]")
            except Exception as e:
                console.print(f"  [red]{ver}/{pkg_arch} failed: {e}[/red]")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--fix", is_flag=True, help="Re-download and replace mismatched files.")
@click.option("--mirror", type=click.Choice(ALL_MIRRORS), default="auto")
@click.pass_context
def verify(ctx, fix, mirror):
    """Verify installed glibc against official Ubuntu packages."""
    glibc_dir = ctx.obj["glibc_dir"]

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
