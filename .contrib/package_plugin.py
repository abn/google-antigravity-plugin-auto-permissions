#!/usr/bin/env python3
"""
Plugin Packaging Script for Google Antigravity Auto-Permissions.
Packages only runtime plugin files, README.md, and LICENSE into distribution archives.
Strictly excludes all development files, test suites, CI workflows, and build caches.
"""

import argparse
import json
import os
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

# Directories and files required for plugin execution
INCLUDED_FILES = [
    "plugin.json",
    "hooks.json",
    "LICENSE",
    "README.md",
]

INCLUDED_DIRECTORIES = [
    "hooks",
    "rules",
    "skills",
]

# Patterns to strictly exclude from packaged directories
EXCLUDED_PATTERNS = [
    "__pycache__",
    "*.pyc",
    "*.pyo",
    ".pytest_cache",
    ".ruff_cache",
    ".DS_Store",
]


def should_exclude(path: Path) -> bool:
    """Checks if a file or directory matches any exclusion pattern."""
    for part in path.parts:
        if part in ("__pycache__", ".pytest_cache", ".ruff_cache"):
            return True
        if part.endswith(".pyc") or part.endswith(".pyo"):
            return True
    return False


def get_plugin_version(root_dir: Path) -> str:
    """Extracts plugin version from plugin.json."""
    manifest_path = root_dir / "plugin.json"
    if not manifest_path.is_file():
        return "0.1.0"
    try:
        with open(manifest_path, encoding="utf-8") as f:
            data = json.load(f)
            return data.get("version", "0.1.0")
    except Exception:
        return "0.1.0"


def build_package(root_dir: Path, output_dir: Path) -> tuple[Path, Path]:
    """
    Builds clean distribution archives containing only plugin runtime files, README, and LICENSE.
    Returns paths to (.tar.gz, .zip) artifacts.
    """
    version = get_plugin_version(root_dir)
    pkg_name = f"auto-permissions-v{version}"
    stage_dir = output_dir / "staging" / "auto-permissions"

    # Clean staging directory
    if stage_dir.parent.exists():
        shutil.rmtree(stage_dir.parent)
    stage_dir.mkdir(parents=True, exist_ok=True)

    # Copy top-level files
    for fname in INCLUDED_FILES:
        src = root_dir / fname
        if src.is_file():
            shutil.copy2(src, stage_dir / fname)
        else:
            print(f"Warning: Expected file not found: {fname}", file=sys.stderr)

    # Copy runtime directories recursively, excluding development artifacts
    for dname in INCLUDED_DIRECTORIES:
        src_dir = root_dir / dname
        if not src_dir.is_dir():
            continue
        dest_dir = stage_dir / dname
        dest_dir.mkdir(parents=True, exist_ok=True)
        for root, dirs, files in os.walk(src_dir):
            # Prune excluded directories in-place
            dirs[:] = [d for d in dirs if not should_exclude(Path(d))]

            rel_root = Path(root).relative_to(src_dir)
            target_sub = dest_dir / rel_root
            target_sub.mkdir(parents=True, exist_ok=True)

            for file in files:
                src_file = Path(root) / file
                if not should_exclude(src_file):
                    shutil.copy2(src_file, target_sub / file)

    output_dir.mkdir(parents=True, exist_ok=True)
    tar_path = output_dir / f"{pkg_name}.tar.gz"
    zip_path = output_dir / f"{pkg_name}.zip"

    # Build tar.gz
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(stage_dir, arcname="auto-permissions")

    # Build zip
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(stage_dir):
            for file in files:
                file_path = Path(root) / file
                arcname = Path("auto-permissions") / file_path.relative_to(stage_dir)
                zipf.write(file_path, arcname=str(arcname))

    # Clean up staging
    shutil.rmtree(stage_dir.parent)

    return tar_path, zip_path


def main():
    parser = argparse.ArgumentParser(description="Package auto-permissions plugin for release.")
    parser.add_argument(
        "--root-dir",
        "-r",
        default=os.getcwd(),
        help="Repository root directory (default: current directory).",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default="./dist",
        help="Directory to output release archives (default: ./dist).",
    )

    args = parser.parse_args()
    root_path = Path(args.root_dir).resolve()
    out_path = Path(args.output_dir).resolve()

    tar_path, zip_path = build_package(root_path, out_path)
    print(f"✓ Packaged tar.gz: {tar_path} ({tar_path.stat().st_size} bytes)")
    print(f"✓ Packaged zip:    {zip_path} ({zip_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
