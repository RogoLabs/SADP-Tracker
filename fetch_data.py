#!/usr/bin/env python3
"""
fetch_data.py - Fetch and parse CVE Supplier ADP records.

This script fetches SADP records from two sources:
1. CVEProject/sadp-pilot  – the pilot/staging repo (cloned locally)
2. CVEProject/cvelistV5   – the official CVE list (via GitHub Search API)

For each source it:
- Parses CVE JSON records
- Extracts Supplier ADP containers (x_adpType == "supplier" or shortName ends with "-SADP")
- Writes consolidated data/data.json for the static site builder
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"

# Environment variable set by the GitHub Actions workflow pointing to the
# locally cloned sadp-pilot repo.
SADP_REPO_ENV = "SADP_REPO_PATH"

# Optional GitHub token for authenticated API calls (higher rate limits).
GITHUB_TOKEN_ENV = "GITHUB_TOKEN"

# CVEProject/cvelistV5 coordinates
CVELISTV5_OWNER = "CVEProject"
CVELISTV5_REPO = "cvelistV5"

PUBLISHED_DIR_NAME = "Published SADP Records"
ARCHIVED_DIR_NAME = "Archived Pilot Data"

_DATA_TYPE_KEYS = ["affected", "references", "metrics", "descriptions"]

# Source labels stored on each CVE entry
SOURCE_SADP_PILOT = "sadp-pilot"
SOURCE_CVELISTV5 = "cvelistv5"


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


def _parse_adp_list(cve_id: str, adp_list: list, file_rel: str, source: str = SOURCE_SADP_PILOT) -> list[dict]:
    """Extract SADP contribution dicts from an ADP container list."""
    results = []
    for adp in adp_list:
        if not is_sadp_container(adp):
            continue

        meta = adp.get("providerMetadata", {})
        results.append(
            {
                "cve_id": cve_id,
                "short_name": meta.get("shortName", ""),
                "org_id": meta.get("orgId", ""),
                "date_updated": meta.get("dateUpdated", ""),
                "data_types": extract_data_types(adp),
                "file_path": file_rel,
                "affected_products": extract_affected_products(adp),
                "source": source,
            }
        )
    return results


def parse_record(path: Path, source_dir: Path | None = None, source: str = SOURCE_SADP_PILOT) -> list[dict]:
    """Parse a single CVE JSON record and return a list of SADP contribution dicts."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"WARNING: Could not parse {path}: {exc}", file=sys.stderr)
        return []

    cve_id: str = data.get("cveMetadata", {}).get("cveId", path.stem)
    adp_list = data.get("containers", {}).get("adp", [])

    if source_dir is None:
        file_rel = path.name
    else:
        try:
            file_rel = str(path.relative_to(source_dir)).replace("\\", "/")
        except ValueError:
            file_rel = path.name

    return _parse_adp_list(cve_id, adp_list, file_rel, source)


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def _github_api_get(url: str, token: str | None) -> dict:
    """Make a GET request to the GitHub API and return parsed JSON."""
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _fetch_raw_github_file(owner: str, repo: str, path: str, token: str | None) -> str:
    """Fetch raw file content from a public GitHub repository."""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{urllib.parse.quote(path, safe='/')}"
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


# ---------------------------------------------------------------------------
# CVEProject/cvelistV5 source
# ---------------------------------------------------------------------------

def fetch_from_cvelistv5(github_token: str | None = None) -> dict:
    """
    Search CVEProject/cvelistV5 for SADP containers via the GitHub Search API,
    fetch each matching file, and return an aggregated supplier dict.
    """
    query = f'x_adpType repo:{CVELISTV5_OWNER}/{CVELISTV5_REPO}'
    base_url = "https://api.github.com/search/code"

    paths: list[str] = []
    page = 1
    while True:
        url = f"{base_url}?q={urllib.parse.quote(query)}&per_page=100&page={page}"
        try:
            data = _github_api_get(url, github_token)
        except Exception as exc:
            print(f"WARNING: GitHub Search API error: {exc}", file=sys.stderr)
            break

        items = data.get("items", [])
        paths.extend(item["path"] for item in items)
        total = data.get("total_count", 0)
        print(f"🔍 cvelistV5 search page {page}: {len(items)} result(s) (total reported: {total})")

        if len(items) < 100 or len(paths) >= total:
            break
        page += 1
        time.sleep(1)  # respect search rate limit

    print(f"📋 Found {len(paths)} candidate file(s) in cvelistV5")

    suppliers: dict[str, dict] = {}
    sadp_hits = 0
    for file_path in paths:
        try:
            raw = _fetch_raw_github_file(CVELISTV5_OWNER, CVELISTV5_REPO, file_path, github_token)
            record = json.loads(raw)
        except Exception as exc:
            print(f"WARNING: Could not fetch/parse {file_path}: {exc}", file=sys.stderr)
            continue

        cve_id: str = record.get("cveMetadata", {}).get("cveId", Path(file_path).stem)
        adp_list = record.get("containers", {}).get("adp", [])
        contributions = _parse_adp_list(cve_id, adp_list, file_path, SOURCE_CVELISTV5)

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
                    "source": contrib["source"],
                }
            )
            sadp_hits += 1

    print(f"✅ cvelistV5: found {sadp_hits} SADP contribution(s) from {len(suppliers)} supplier(s)")

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "suppliers": sorted(suppliers.values(), key=lambda s: s["short_name"]),
    }


# ---------------------------------------------------------------------------
# Merge helpers
# ---------------------------------------------------------------------------

def merge_sources(primary: dict, secondary: dict) -> dict:
    """
    Merge two supplier result dicts (each with a "suppliers" list).

    Records present in *secondary* that are not in *primary* are added.
    Records present in both are deduplicated by (short_name, cve_id); the
    primary version is kept but the source is updated to reflect both origins.
    """
    # Build a mutable map from the primary result
    suppliers: dict[str, dict] = {s["short_name"]: s for s in primary.get("suppliers", [])}

    for sec_supplier in secondary.get("suppliers", []):
        name = sec_supplier["short_name"]
        if name not in suppliers:
            suppliers[name] = sec_supplier
            continue

        # Merge CVE lists, deduplicating by cve_id
        existing_cves: dict[str, dict] = {c["cve_id"]: c for c in suppliers[name]["cves"]}
        for cve in sec_supplier["cves"]:
            cve_id = cve["cve_id"]
            if cve_id not in existing_cves:
                existing_cves[cve_id] = cve
            else:
                # Record exists in both sources – mark it accordingly
                existing_cves[cve_id]["source"] = "both"
        suppliers[name]["cves"] = list(existing_cves.values())

    # Use the most-recent generated_at timestamp
    ts_primary = primary.get("generated_at", "")
    ts_secondary = secondary.get("generated_at", "")
    generated_at = max(ts_primary, ts_secondary) if ts_primary and ts_secondary else ts_primary or ts_secondary

    return {
        "generated_at": generated_at,
        "suppliers": sorted(suppliers.values(), key=lambda s: s["short_name"]),
    }


# ---------------------------------------------------------------------------
# sadp-pilot source
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
                    "source": contrib["source"],
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

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

    github_token = os.environ.get(GITHUB_TOKEN_ENV)

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # --- sadp-pilot (primary source) ---
    sadp_pilot_output = fetch_and_parse(sadp_repo_path)

    # --- CVEProject/cvelistV5 (secondary source) ---
    print("\n🌐 Fetching SADP records from CVEProject/cvelistV5 via GitHub API…")
    cvelistv5_output = fetch_from_cvelistv5(github_token)

    # --- Merge both sources ---
    output = merge_sources(sadp_pilot_output, cvelistv5_output)
    total_cves = sum(len(s["cves"]) for s in output["suppliers"])
    print(f"\n📊 Merged: {total_cves} total SADP contribution(s) from {len(output['suppliers'])} supplier(s)")

    out_path = DATA_DIR / "data.json"
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"💾 Written to {out_path}")

    archived = fetch_and_parse_archived(sadp_repo_path)
    archived_path = DATA_DIR / "archived_data.json"
    archived_path.write_text(json.dumps(archived, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"💾 Written to {archived_path}")


if __name__ == "__main__":
    main()
