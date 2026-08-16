"""
Built-in Permission Bundles Catalog & Registry.
Provides zero-dependency access to standard pre-audited bundles.
"""

import json
import os
from typing import Any

BUNDLES_DIR = os.path.dirname(os.path.abspath(__file__))


def load_bundle_from_file(file_path: str) -> dict[str, Any] | None:
    """Loads and parses a single bundle JSON file."""
    if not file_path or not os.path.isfile(file_path):
        return None
    try:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict) and "name" in data:
                return data
    except Exception:
        return None
    return None


def get_builtin_bundle(name: str) -> dict[str, Any] | None:
    """Retrieves a built-in bundle definition by slug name."""
    clean_name = name.strip().lower().replace("-", "_")
    file_path = os.path.join(BUNDLES_DIR, f"{clean_name}.json")
    if os.path.isfile(file_path):
        return load_bundle_from_file(file_path)
    # Also check with exact slug filename
    slug_path = os.path.join(BUNDLES_DIR, f"{name.strip().lower()}.json")
    if os.path.isfile(slug_path):
        return load_bundle_from_file(slug_path)
    return None


def list_builtin_bundles() -> dict[str, dict[str, Any]]:
    """Lists all built-in bundles keyed by bundle slug name."""
    catalog: dict[str, dict[str, Any]] = {}
    if not os.path.isdir(BUNDLES_DIR):
        return catalog

    for fname in sorted(os.listdir(BUNDLES_DIR)):
        if fname.endswith(".json"):
            fpath = os.path.join(BUNDLES_DIR, fname)
            bundle = load_bundle_from_file(fpath)
            if bundle and "name" in bundle:
                catalog[bundle["name"]] = bundle
    return catalog
