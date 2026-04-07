#!/usr/bin/env python3
"""
PhantomRaven NPM Supply-Chain Attack — Susceptibility Checker
Reads PhantomRaven.csv and compares against installed packages in:
  - The current/specified project (package.json, lock file, node_modules)
  - Global npm installs
  - Global bun installs
  - Homebrew-managed Node.js package paths

Usage:
    python check_phantomraven.py                     # scan current directory + all global stores
    python check_phantomraven.py /path/to/project    # scan a specific project + all global stores
    python check_phantomraven.py --no-node-modules   # skip node_modules (faster)
    python check_phantomraven.py --no-global         # skip all global/system scans

Output:
    Prints a summary and details for every matched (vulnerable) package.
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
from pathlib import Path

CSV_FILE = Path(__file__).parent / "PhantomRaven.csv"

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def no_colour():
    global RED, YELLOW, GREEN, CYAN, BOLD, RESET
    RED = YELLOW = GREEN = CYAN = BOLD = RESET = ""

if not sys.stdout.isatty():
    no_colour()


# ── CSV loading ───────────────────────────────────────────────────────────────

def load_malicious_packages(csv_path: Path) -> list[dict]:
    """Return list of dicts with keys: package, version, status, wave."""
    packages = []
    with open(csv_path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            packages.append({
                "package": row["Package"].strip(),
                "version": row["Version"].strip(),
                "status":  row["Status"].strip(),
                "wave":    row["Wave"].strip(),
            })
    return packages


def build_lookup(packages: list[dict]) -> dict[str, list[dict]]:
    """Build a dict keyed by package name (lower-case) → list of entries."""
    lookup: dict[str, list[dict]] = {}
    for p in packages:
        key = p["package"].lower()
        lookup.setdefault(key, []).append(p)
    return lookup


# ── Installed-package discovery ───────────────────────────────────────────────

def parse_package_json(project_dir: Path) -> dict[str, str]:
    """Return {name: version_spec} from package.json (direct deps only)."""
    pkg_json = project_dir / "package.json"
    if not pkg_json.exists():
        return {}
    with open(pkg_json, encoding="utf-8") as fh:
        data = json.load(fh)
    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps.update(data.get(section, {}))
    return deps


def parse_package_lock(project_dir: Path) -> dict[str, str]:
    """Return {name: resolved_version} from package-lock.json (all deps)."""
    lock = project_dir / "package-lock.json"
    if not lock.exists():
        return {}
    with open(lock, encoding="utf-8") as fh:
        data = json.load(fh)

    installed: dict[str, str] = {}
    lock_version = data.get("lockfileVersion", 1)

    if lock_version >= 2 and "packages" in data:
        # v2/v3 format: keys are paths like "node_modules/foo" or "node_modules/@scope/foo"
        for path_key, meta in data["packages"].items():
            if not path_key or path_key == "":
                continue  # root entry
            # Strip leading "node_modules/" and handle nested paths
            # We want the innermost package name
            parts = path_key.split("node_modules/")
            name = parts[-1]  # e.g. "@scope/pkg" or "pkg"
            version = meta.get("version", "")
            if name and version:
                installed[name] = version
    else:
        # v1 format: "dependencies" dict
        def walk_v1(deps_dict):
            for name, meta in deps_dict.items():
                installed[name] = meta.get("version", "")
                if "dependencies" in meta:
                    walk_v1(meta["dependencies"])
        walk_v1(data.get("dependencies", {}))

    return installed


def scan_node_modules(project_dir: Path) -> dict[str, str]:
    """
    Walk node_modules and read each package's package.json for its version.
    More thorough than the lock file for workspaces / hoisted deps.
    """
    nm = project_dir / "node_modules"
    if not nm.exists():
        return {}

    installed: dict[str, str] = {}

    def read_pkg(pkg_dir: Path):
        pj = pkg_dir / "package.json"
        if pj.exists():
            try:
                with open(pj, encoding="utf-8") as fh:
                    data = json.load(fh)
                name    = data.get("name", "")
                version = data.get("version", "")
                if name and version:
                    installed[name] = version
            except (json.JSONDecodeError, OSError):
                pass

    for entry in nm.iterdir():
        if entry.is_dir():
            if entry.name.startswith("@"):          # scoped package
                for sub in entry.iterdir():
                    if sub.is_dir():
                        read_pkg(sub)
            else:
                read_pkg(entry)

    return installed


def get_npm_global_packages() -> dict[str, str]:
    """Return globally installed npm packages via `npm list -g --json`."""
    try:
        result = subprocess.run(
            ["npm", "list", "-g", "--json", "--depth=0"],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(result.stdout or "{}")
        deps = data.get("dependencies", {})
        return {name: meta.get("version", "") for name, meta in deps.items()}
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"{YELLOW}[warn] Could not query global npm packages: {exc}{RESET}")
        return {}


def get_bun_global_packages() -> dict[str, str]:
    """
    Return globally installed bun packages.
    Tries two methods:
      1. Scan ~/.bun/install/global/node_modules/ directly (most reliable)
      2. Fall back to `bun pm ls -g` text output
    """
    # Method 1: scan bun's global node_modules directory
    bun_global_nm = Path.home() / ".bun" / "install" / "global" / "node_modules"
    if bun_global_nm.exists():
        return scan_node_modules(bun_global_nm.parent)

    # Method 2: parse `bun pm ls -g` output  (format: "pkg@version")
    try:
        result = subprocess.run(
            ["bun", "pm", "ls", "-g"],
            capture_output=True, text=True, timeout=30
        )
        pkgs: dict[str, str] = {}
        for line in result.stdout.splitlines():
            line = line.strip().lstrip("├─└─ \t")
            # lines look like:  package-name@1.2.3
            m = re.match(r"^(@?[^@\s]+)@(\S+)$", line)
            if m:
                pkgs[m.group(1)] = m.group(2)
        return pkgs
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}


def get_brew_node_packages() -> dict[str, str]:
    """
    Scan Homebrew-managed Node.js package paths.
    Homebrew installs global npm packages under its own prefix, e.g.:
      /opt/homebrew/lib/node_modules/   (Apple Silicon)
      /usr/local/lib/node_modules/      (Intel Mac / Linux)
    Also checks any formula cellar entries that contain node_modules.
    """
    candidates: list[Path] = [
        Path("/opt/homebrew/lib/node_modules"),
        Path("/usr/local/lib/node_modules"),
        Path("/home/linuxbrew/.linuxbrew/lib/node_modules"),
    ]

    # Ask brew for its prefix to catch non-standard installs
    try:
        result = subprocess.run(
            ["brew", "--prefix"], capture_output=True, text=True, timeout=10
        )
        prefix = result.stdout.strip()
        if prefix:
            candidates.append(Path(prefix) / "lib" / "node_modules")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    installed: dict[str, str] = {}
    seen_paths: set[Path] = set()

    for nm_path in candidates:
        try:
            resolved = nm_path.resolve()
        except OSError:
            continue
        if not nm_path.exists() or resolved in seen_paths:
            continue
        seen_paths.add(resolved)
        # Reuse the existing node_modules walker by passing the parent
        pkgs = scan_node_modules(nm_path.parent)
        installed.update(pkgs)

    return installed


# ── Version comparison helpers ────────────────────────────────────────────────

def parse_version(v: str) -> tuple[int, ...]:
    """Parse a semver-ish string into a tuple of ints for comparison."""
    # Strip leading ^ ~ >= <= > < = and whitespace
    v = re.sub(r"^[^0-9]*", "", v)
    parts = re.split(r"[.\-]", v)
    result = []
    for p in parts:
        m = re.match(r"(\d+)", p)
        if m:
            result.append(int(m.group(1)))
        else:
            break
    return tuple(result) if result else (0,)


def version_matches(installed_ver: str, malicious_ver: str) -> bool:
    """
    Return True if the installed version exactly matches the known-bad version.
    For supply-chain attacks the attacker publishes a specific version, so exact
    match is the primary check.  A looser check (installed >= malicious) is also
    flagged as a warning because some repos may pin '^X.Y.Z'.
    """
    installed_ver = installed_ver.lstrip("^~>=< ")
    malicious_ver = malicious_ver.lstrip("^~>=< ")
    return installed_ver == malicious_ver


def version_gte(installed_ver: str, malicious_ver: str) -> bool:
    """Return True if installed version >= malicious version."""
    try:
        return parse_version(installed_ver) >= parse_version(malicious_ver)
    except Exception:
        return False


# ── Matching logic ────────────────────────────────────────────────────────────

def find_matches(
    installed: dict[str, str],
    lookup:    dict[str, list[dict]],
    source_label: str,
) -> list[dict]:
    """
    Cross-reference installed packages against the malicious-package lookup.
    Returns a list of match records.
    """
    matches = []
    for pkg_name, inst_ver in installed.items():
        key = pkg_name.lower()
        if key not in lookup:
            continue
        for entry in lookup[key]:
            exact = version_matches(inst_ver, entry["version"])
            gte   = version_gte(inst_ver, entry["version"])
            if exact or gte:
                matches.append({
                    "package":         pkg_name,
                    "installed_ver":   inst_ver,
                    "malicious_ver":   entry["version"],
                    "status":          entry["status"],
                    "wave":            entry["wave"],
                    "exact_match":     exact,
                    "source":          source_label,
                })
    return matches


# ── Reporting ─────────────────────────────────────────────────────────────────

def print_match(m: dict, idx: int):
    sev_colour = RED if m["exact_match"] else YELLOW
    sev_label  = "EXACT MATCH" if m["exact_match"] else "VERSION >= MALICIOUS"
    still_live = m["status"].upper() == "LIVE"

    print(f"\n  {BOLD}{sev_colour}[{idx}] {m['package']}{RESET}")
    print(f"      Installed version : {m['installed_ver']}")
    print(f"      CSV (malicious) v : {m['malicious_ver']}")
    print(f"      Match type        : {sev_colour}{sev_label}{RESET}")
    print(f"      Registry status   : {'⚠️  ' if still_live else ''}{m['status']}")
    print(f"      Attack wave       : {m['wave']}")
    print(f"      Found in          : {m['source']}")
    if still_live:
        print(f"      {RED}Still LIVE on npm — remove immediately!{RESET}")
    else:
        print(f"      {YELLOW}Removed from npm but may still be in your project.{RESET}")


def print_scanned_table(scanned: dict[str, int], all_installed: dict[str, dict[str, str]], unique_matches: list[dict]):
    """
    Print a per-source table showing package count and any matches inline.
    all_installed maps source_label -> {pkg_name: version}.
    """
    # Build a quick lookup: (pkg_lower, source) -> match record
    match_index: dict[tuple[str, str], dict] = {}
    for m in unique_matches:
        match_index[(m["package"].lower(), m["source"])] = m

    W_NAME = 40
    W_INST = 14
    W_CSV  = 14
    W_TYPE = 22
    header = f"  {'Package':<{W_NAME}} {'Installed':<{W_INST}} {'CSV Version':<{W_CSV}} Match Type"
    rule   = "  " + "─" * (W_NAME + W_INST + W_CSV + W_TYPE + 6)

    for source, count in scanned.items():
        installed_for_source = all_installed.get(source, {})
        # Filter to only packages that have a match in this source
        source_matches = [m for m in unique_matches if m["source"] == source]

        print(f"\n  {BOLD}Source: {source}{RESET}  ({count} packages scanned, "
              f"{len(source_matches)} match{'es' if len(source_matches) != 1 else ''})")

        if source_matches:
            print(header)
            print(rule)
            for m in sorted(source_matches, key=lambda x: x["package"].lower()):
                sev_colour = RED if m["exact_match"] else YELLOW
                match_label = "EXACT" if m["exact_match"] else ">= malicious"
                live_tag = " [LIVE]" if m["status"].upper() == "LIVE" else " [removed]"
                print(
                    f"  {sev_colour}{m['package']:<{W_NAME}}{RESET} "
                    f"{m['installed_ver']:<{W_INST}} "
                    f"{m['malicious_ver']:<{W_CSV}} "
                    f"{sev_colour}{match_label}{live_tag}{RESET}"
                )
        else:
            print(f"  {GREEN}  No matches in this source.{RESET}")


def write_csv_report(path: Path, all_matches: list[dict], scanned: dict[str, int], total_malicious: int):
    """Write match results to a CSV file."""
    import datetime
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        # Header block
        writer.writerow(["PhantomRaven Susceptibility Report"])
        writer.writerow(["Generated", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
        writer.writerow(["Malicious packages in CSV", total_malicious])
        writer.writerow([])
        writer.writerow(["Sources Scanned", "Package Count"])
        for source, count in scanned.items():
            writer.writerow([source, count])
        writer.writerow([])

        # Match detail rows
        writer.writerow([
            "Package", "Installed Version", "CSV (Malicious) Version",
            "Match Type", "Registry Status", "Attack Wave", "Source"
        ])
        if all_matches:
            for m in sorted(all_matches, key=lambda x: (x["source"], x["package"].lower())):
                writer.writerow([
                    m["package"],
                    m["installed_ver"],
                    m["malicious_ver"],
                    "EXACT MATCH" if m["exact_match"] else "VERSION >= MALICIOUS",
                    m["status"],
                    m["wave"],
                    m["source"],
                ])
        else:
            writer.writerow(["No vulnerable packages found."])


def print_summary(
    all_matches: list[dict],
    scanned: dict[str, int],
    total_malicious: int,
    all_installed: dict[str, dict[str, str]],
    output_csv: Path | None,
):
    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  PhantomRaven Susceptibility Report{RESET}")
    print(f"{'═'*60}")
    print(f"  Malicious packages in CSV : {total_malicious}")

    if not all_matches:
        print(f"\n  {GREEN}No matches found — system appears clean.{RESET}")
        # Still print per-source counts
        print_scanned_table(scanned, all_installed, all_matches)
    else:
        exact   = [m for m in all_matches if m["exact_match"]]
        inexact = [m for m in all_matches if not m["exact_match"]]
        live    = [m for m in all_matches if m["status"].upper() == "LIVE"]

        print(f"\n  {RED}{BOLD}VULNERABLE — {len(all_matches)} match(es) found:{RESET}")
        print(f"    • Exact version matches  : {len(exact)}")
        print(f"    • Version >= malicious   : {len(inexact)}")
        print(f"    • Still LIVE on registry : {len(live)}")

        print_scanned_table(scanned, all_installed, all_matches)

        print(f"\n  {BOLD}Full Match Details:{RESET}")
        for i, m in enumerate(all_matches, 1):
            print_match(m, i)

    if output_csv:
        write_csv_report(output_csv, all_matches, scanned, total_malicious)
        print(f"\n  {CYAN}Report written to: {output_csv}{RESET}")

    print(f"\n{BOLD}{'═'*60}{RESET}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Check if your npm project is susceptible to the PhantomRaven supply-chain attack."
    )
    parser.add_argument(
        "project_dir",
        nargs="?",
        default=".",
        help="Path to the npm project directory (default: current directory)",
    )
    parser.add_argument(
        "--no-global", dest="skip_global", action="store_true",
        help="Skip all global/system package scans (npm global, bun global, Homebrew)",
    )
    parser.add_argument(
        "--no-node-modules", dest="skip_nm", action="store_true",
        help="Skip scanning node_modules (faster, relies on lock file only)",
    )
    parser.add_argument(
        "--output", "-o", dest="output_csv", metavar="FILE",
        help="Write results to a CSV file instead of (or in addition to) stdout",
    )
    parser.add_argument(
        "--no-colour", dest="no_colour", action="store_true",
        help="Disable ANSI colour output",
    )
    args = parser.parse_args()

    if args.no_colour:
        no_colour()

    if not CSV_FILE.exists():
        print(f"{RED}Error: {CSV_FILE} not found.{RESET}")
        sys.exit(1)

    project_dir = Path(args.project_dir).resolve()
    print(f"\n{CYAN}PhantomRaven Supply-Chain Attack Checker{RESET}")
    print(f"CSV source : {CSV_FILE}")
    print(f"Project    : {project_dir}")
    print(f"Global scan: {'disabled (--no-global)' if args.skip_global else 'npm + bun + Homebrew'}")

    # Load malicious package list
    malicious = load_malicious_packages(CSV_FILE)
    lookup    = build_lookup(malicious)

    all_matches:  list[dict] = []
    scanned:      dict[str, int] = {}
    all_installed: dict[str, dict[str, str]] = {}   # source → {pkg: version}

    def register(source: str, deps: dict[str, str]):
        """Record a source's packages and collect matches."""
        if not deps:
            return
        scanned[source] = len(deps)
        all_installed[source] = deps
        all_matches.extend(find_matches(deps, lookup, source))

    # 1. package.json (declared deps)
    register("package.json", parse_package_json(project_dir))

    # 2. package-lock.json (resolved tree)
    register("package-lock.json", parse_package_lock(project_dir))

    # 3. node_modules (on-disk)
    if not args.skip_nm:
        register("node_modules", scan_node_modules(project_dir))

    # 4. Global stores (always on unless --no-global)
    if not args.skip_global:
        # 4a. Global npm
        print(f"  {CYAN}Scanning global npm...{RESET}", end=" ", flush=True)
        npm_global = get_npm_global_packages()
        register("global npm", npm_global)
        print(f"{len(npm_global)} packages" if npm_global else "not found / empty")

        # 4b. Global bun
        print(f"  {CYAN}Scanning global bun...{RESET}", end=" ", flush=True)
        bun_global = get_bun_global_packages()
        register("global bun", bun_global)
        print(f"{len(bun_global)} packages" if bun_global else "not found / empty")

        # 4c. Homebrew node paths
        print(f"  {CYAN}Scanning Homebrew node paths...{RESET}", end=" ", flush=True)
        brew_pkgs = get_brew_node_packages()
        register("Homebrew node_modules", brew_pkgs)
        print(f"{len(brew_pkgs)} packages" if brew_pkgs else "not found / empty")

    if not scanned:
        print(f"\n{YELLOW}No package.json, package-lock.json, node_modules, or global installs found.{RESET}")
        print("Specify the correct project directory, or check that npm/bun/brew are installed.\n")
        sys.exit(0)

    # De-duplicate: same package+version+source can appear across sources
    seen = set()
    unique_matches = []
    for m in all_matches:
        key = (m["package"].lower(), m["installed_ver"], m["source"])
        if key not in seen:
            seen.add(key)
            unique_matches.append(m)

    output_csv = Path(args.output_csv) if args.output_csv else None
    print_summary(unique_matches, scanned, len(malicious), all_installed, output_csv)

    sys.exit(1 if unique_matches else 0)


if __name__ == "__main__":
    main()
