#!/usr/bin/env python3
"""
fetch_data.py - Fetch and parse CVE Supplier ADP records from CVEProject/sadp-pilot.

This script:
1. Walks the "Published SADP Records" directory in the cloned sadp-pilot repo
2. Parses each CVE JSON record
3. Extracts Supplier ADP containers (x_adpType == "supplier" or shortName ends with "-SADP")
4. Writes a consolidated data/data.json for the static site builder
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path


BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"

# Environment variable set by the GitHub Actions workflow pointing to the
# locally cloned sadp-pilot repo.
SADP_REPO_ENV = "SADP_REPO_PATH"

PUBLISHED_DIR_NAME = "Published SADP Records"
ARCHIVED_DIR_NAME = "Archived Pilot Data"

_DATA_TYPE_KEYS = ["affected", "references", "metrics", "descriptions"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_sadp_container(adp: dict) -> bool:
    """Return True if this ADP container is a Supplier ADP entry."""
    meta = adp.get("providerMetadata", {})
    short_name: str = meta.get("shortName", "")
    x_adp_type: str = adp.get("x_adpType", "")
    return x_adp_type.lower() == "supplier" or short_name.endswith("-SADP")


def extract_data_types(adp_container: dict) -> list[str]:
    """Return a sorted list of data-type labels present in an ADP container."""
    found = []
    for key in _DATA_TYPE_KEYS:
        val = adp_container.get(key)
        if val:
            found.append(key)
    return found


def extract_affected_products(adp_container: dict) -> list[dict]:
    """Return deduplicated list of {vendor, product} dicts from the affected array."""
    products: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in adp_container.get("affected", []):
        vendor = item.get("vendor", "")
        product = item.get("product", "")
        key = (vendor.lower(), product.lower())
        if key not in seen and (vendor or product):
            seen.add(key)
            products.append({"vendor": vendor, "product": product})
    return products


def parse_record(path: Path, source_dir: Path | None = None) -> list[dict]:
    """Parse a single CVE JSON record and return a list of SADP contribution dicts."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"WARNING: Could not parse {path}: {exc}", file=sys.stderr)
        return []

    cve_id: str = data.get("cveMetadata", {}).get("cveId", path.stem)
    containers = data.get("containers", {})
    adp_list = containers.get("adp", [])
    if source_dir is None:
        file_rel = path.name
    else:
        try:
            file_rel = str(path.relative_to(source_dir)).replace("\\", "/")
        except ValueError:
            file_rel = path.name

    results = []
    for adp in adp_list:
        if not is_sadp_container(adp):
            continue

        meta = adp.get("providerMetadata", {})
        short_name: str = meta.get("shortName", "")
        org_id: str = meta.get("orgId", "")
        date_updated: str = meta.get("dateUpdated", "")

        data_types = extract_data_types(adp)
        affected_products = extract_affected_products(adp)

        results.append(
            {
                "cve_id": cve_id,
                "short_name": short_name,
                "org_id": org_id,
                "date_updated": date_updated,
                "data_types": data_types,
                "file_path": file_rel,
                "affected_products": affected_products,
            }
        )

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _build_suppliers_dict(json_files: list[Path], source_dir: Path) -> tuple[dict, int, int]:
    """Shared logic: parse files and aggregate into a suppliers dict."""
    suppliers: dict[str, dict] = {}
    parsed = 0
    sadp_hits = 0
    for path in json_files:
        contributions = parse_record(path, source_dir)
        parsed += 1
        for contrib in contributions:
            short_name = contrib["short_name"]
            if short_name not in suppliers:
                suppliers[short_name] = {
                    "short_name": short_name,
                    "org_id": contrib["org_id"],
                    "cves": [],
                }
            suppliers[short_name]["cves"].append(
                {
                    "cve_id": contrib["cve_id"],
                    "date_updated": contrib["date_updated"],
                    "data_types": contrib["data_types"],
                    "file_path": contrib["file_path"],
                    "affected_products": contrib["affected_products"],
                }
            )
            sadp_hits += 1
    return suppliers, parsed, sadp_hits


def fetch_and_parse(sadp_repo_path: Path) -> dict:
    """Walk the sadp-pilot repo and aggregate supplier contributions."""
    published_dir = sadp_repo_path / PUBLISHED_DIR_NAME
    if not published_dir.is_dir():
        print(f"ERROR: '{PUBLISHED_DIR_NAME}' directory not found at {published_dir}", file=sys.stderr)
        sys.exit(1)

    # supplier_short_name -> {org_id, cves: [...]}
    suppliers: dict[str, dict] = {}

    json_files = sorted(published_dir.rglob("*.json"))
    print(f"📂 Found {len(json_files)} JSON file(s) in '{PUBLISHED_DIR_NAME}'")

    suppliers, parsed, sadp_hits = _build_suppliers_dict(json_files, published_dir)
    print(f"✅ Parsed {parsed} records, found {sadp_hits} SADP contribution(s) from {len(suppliers)} supplier(s)")

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "suppliers": sorted(suppliers.values(), key=lambda s: s["short_name"]),
    }


def fetch_and_parse_archived(sadp_repo_path: Path) -> dict:
    """Walk the Archived Pilot Data directory (flat, Phase I test records)."""
    archived_dir = sadp_repo_path / ARCHIVED_DIR_NAME
    if not archived_dir.is_dir():
        print(f"WARNING: '{ARCHIVED_DIR_NAME}' not found at {archived_dir}", file=sys.stderr)
        return {"generated_at": datetime.now(UTC).isoformat(), "suppliers": []}

    json_files = sorted(archived_dir.glob("*.json"))
    print(f"📂 Found {len(json_files)} JSON file(s) in '{ARCHIVED_DIR_NAME}'")

    suppliers, parsed, sadp_hits = _build_suppliers_dict(json_files, archived_dir)
    print(f"✅ Parsed {parsed} archived records, found {sadp_hits} SADP contribution(s) from {len(suppliers)} supplier(s)")

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "suppliers": sorted(suppliers.values(), key=lambda s: s["short_name"]),
    }


def main() -> None:
    sadp_path_str = os.environ.get(SADP_REPO_ENV)
    if not sadp_path_str:
        # Try a positional argument as fallback
        if len(sys.argv) > 1:
            sadp_path_str = sys.argv[1]
        else:
            print(
                f"ERROR: Set the {SADP_REPO_ENV} environment variable to the path of the "
                "cloned sadp-pilot repository, or pass it as the first argument.",
                file=sys.stderr,
            )
            sys.exit(1)

    sadp_repo_path = Path(sadp_path_str).resolve()
    if not sadp_repo_path.is_dir():
        print(f"ERROR: sadp-pilot repo path does not exist: {sadp_repo_path}", file=sys.stderr)
        sys.exit(1)

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    output = fetch_and_parse(sadp_repo_path)
    out_path = DATA_DIR / "data.json"
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"💾 Written to {out_path}")

    archived = fetch_and_parse_archived(sadp_repo_path)
    archived_path = DATA_DIR / "archived_data.json"
    archived_path.write_text(json.dumps(archived, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"💾 Written to {archived_path}")


if __name__ == "__main__":
    main()
