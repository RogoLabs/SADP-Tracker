#!/usr/bin/env python3
"""
SADP Tracker - Static Site Generator
Fetches CVE Supplier ADP Pilot data and builds a static HTML dashboard.
"""

from __future__ import annotations

import json
import sys
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
WEB_DIR = BASE_DIR / "web"
STATIC_SRC_DIR = WEB_DIR / "static"
SUPPLIER_OUT_DIR = WEB_DIR / "supplier"
DATA_JSON = BASE_DIR / "data" / "data.json"
ARCHIVED_JSON = BASE_DIR / "data" / "archived_data.json"


# ---------------------------------------------------------------------------
# Data types extraction helpers
# ---------------------------------------------------------------------------

_DATA_TYPE_KEYS = ["affected", "references", "metrics", "descriptions"]


def extract_data_types(adp_container: dict) -> list[str]:
    """Return a sorted list of data-type labels present in an ADP container."""
    found = []
    for key in _DATA_TYPE_KEYS:
        val = adp_container.get(key)
        if val:  # non-empty list / truthy value
            found.append(key)
    return found


def is_sadp_container(adp: dict) -> bool:
    """Return True if this ADP container is a Supplier ADP entry."""
    meta = adp.get("providerMetadata", {})
    short_name: str = meta.get("shortName", "")
    x_adp_type: str = adp.get("x_adpType", "")
    return x_adp_type.lower() == "supplier" or short_name.endswith("-SADP")


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_data(data_path: Path) -> dict:
    """Load the consolidated data.json produced by the fetch step."""
    if not data_path.exists():
        print(f"WARNING: {data_path} not found – using empty data.", file=sys.stderr)
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "suppliers": [],
        }
    with data_path.open(encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Site builder
# ---------------------------------------------------------------------------

class SADPSiteBuilder:
    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self.current_year = datetime.now(UTC).year

        self.jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.jinja_env.globals["current_year"] = self.current_year

    def log(self, msg: str) -> None:
        if not self.quiet:
            print(msg)

    # ------------------------------------------------------------------
    # Ensure output directories exist
    # ------------------------------------------------------------------
    def prepare_dirs(self) -> None:
        WEB_DIR.mkdir(parents=True, exist_ok=True)
        SUPPLIER_OUT_DIR.mkdir(parents=True, exist_ok=True)
        self.log(f"✅ Output directories ready: {WEB_DIR}")

    # ------------------------------------------------------------------
    # Enrich supplier data with computed fields
    # ------------------------------------------------------------------
    @staticmethod
    def _enrich_suppliers(suppliers: list[dict], github_dir: str = "Published%20SADP%20Records") -> list[dict]:
        for s in suppliers:
            cves = s.get("cves", [])
            s["cve_count"] = len(cves)

            # Aggregate data types across all CVEs
            all_dts: set[str] = set()
            affected_count = references_count = metrics_count = descriptions_count = 0
            last_updated = ""
            first_enriched = ""
            year_counts: dict[str, int] = {}
            all_products: list[dict] = []
            seen_products: set[tuple[str, str]] = set()

            for cve in cves:
                dts = cve.get("data_types", [])
                all_dts.update(dts)
                if "affected" in dts:
                    affected_count += 1
                if "references" in dts:
                    references_count += 1
                if "metrics" in dts:
                    metrics_count += 1
                if "descriptions" in dts:
                    descriptions_count += 1
                du = cve.get("date_updated", "")
                if du:
                    if du > last_updated:
                        last_updated = du
                    if not first_enriched or du < first_enriched:
                        first_enriched = du

                # CVE year breakdown
                cve_id = cve.get("cve_id", "")
                year = cve_id[4:8] if cve_id.startswith("CVE-") and len(cve_id) > 8 else "Unknown"
                year_counts[year] = year_counts.get(year, 0) + 1

                # Aggregate unique products
                for p in cve.get("affected_products", []):
                    key = (p.get("vendor", "").lower(), p.get("product", "").lower())
                    if key not in seen_products:
                        seen_products.add(key)
                        all_products.append(p)

                # Build GitHub URL per CVE based on source
                file_path = cve.get("file_path", "")
                source = cve.get("source", "sadp-pilot")
                if source == "cvelistv5":
                    if file_path:
                        encoded = urllib.parse.quote(file_path, safe="/")
                        cve["github_url"] = (
                            f"https://github.com/CVEProject/cvelistV5/blob/main/{encoded}"
                        )
                    else:
                        cve["github_url"] = "https://github.com/CVEProject/cvelistV5/tree/main/cves"
                elif source == "both":
                    # Record exists in both sources; link to the official cvelistV5 entry
                    if file_path:
                        encoded = urllib.parse.quote(file_path, safe="/")
                        cve["github_url"] = (
                            f"https://github.com/CVEProject/cvelistV5/blob/main/{encoded}"
                        )
                    else:
                        cve["github_url"] = "https://github.com/CVEProject/cvelistV5/tree/main/cves"
                else:
                    # sadp-pilot (default)
                    if file_path:
                        encoded = urllib.parse.quote(file_path, safe="/")
                        cve["github_url"] = (
                            f"https://github.com/CVEProject/sadp-pilot/blob/main/"
                            f"{github_dir}/{encoded}"
                        )
                    else:
                        cve["github_url"] = (
                            "https://github.com/CVEProject/sadp-pilot/tree/main/Published%20SADP%20Records"
                        )

            # Keep a deterministic sorted order for data-type tags
            s["all_data_types"] = sorted(all_dts, key=lambda x: _DATA_TYPE_KEYS.index(x) if x in _DATA_TYPE_KEYS else 99)
            s["affected_count"] = affected_count
            s["references_count"] = references_count
            s["metrics_count"] = metrics_count
            s["descriptions_count"] = descriptions_count
            s["last_updated"] = last_updated
            s["first_enriched"] = first_enriched
            s["cve_years"] = dict(sorted(year_counts.items()))
            s["unique_products"] = sorted(all_products, key=lambda p: (p.get("vendor", ""), p.get("product", "")))

        return suppliers

    # ------------------------------------------------------------------
    # Render the archived pilot data page
    # ------------------------------------------------------------------
    def build_archived_page(self) -> None:
        if not ARCHIVED_JSON.exists():
            self.log("  ⚠️  archived_data.json not found – skipping archived.html")
            return

        raw = load_data(ARCHIVED_JSON)
        generated_at: str = raw.get("generated_at", "")
        suppliers: list[dict] = raw.get("suppliers", [])

        if not suppliers:
            self.log("  ℹ️  No archived supplier records found – generating archived.html with empty state")

        suppliers = self._enrich_suppliers(suppliers, github_dir="Archived%20Pilot%20Data")

        total_records = sum(s["cve_count"] for s in suppliers)
        unique_cves: set[str] = set()
        year_breakdown: dict[str, int] = {}
        dt_breakdown: dict[str, int] = dict.fromkeys(_DATA_TYPE_KEYS, 0)
        latest_enrichment_date = ""
        latest_enrichment_cve = ""

        # Build a flat CVE list for the full table (all suppliers)
        all_cves: list[dict] = []
        for s in suppliers:
            for cve in s.get("cves", []):
                cve_id = cve["cve_id"]
                unique_cves.add(cve_id)
                du = cve.get("date_updated", "")
                dts = cve.get("data_types", [])
                if du and (du > latest_enrichment_date or (du == latest_enrichment_date and cve_id < latest_enrichment_cve)):
                    latest_enrichment_date = du
                    latest_enrichment_cve = cve_id
                year = cve_id[4:8] if cve_id.startswith("CVE-") and len(cve_id) > 8 else "Unknown"
                year_breakdown[year] = year_breakdown.get(year, 0) + 1
                for dt in dts:
                    if dt in dt_breakdown:
                        dt_breakdown[dt] += 1
                all_cves.append({
                    **cve,
                    "supplier": s["short_name"],
                })

        all_cves.sort(key=lambda c: c.get("date_updated", ""), reverse=True)
        year_breakdown_sorted = dict(sorted(year_breakdown.items()))
        pilot_start = min(
            (s["first_enriched"] for s in suppliers if s.get("first_enriched")),
            default="",
        )

        template = self.jinja_env.get_template("archived.html")
        html = template.render(
            suppliers=suppliers,
            all_cves=all_cves,
            total_records=total_records,
            unique_cves=len(unique_cves),
            data_types_count=len([k for k, v in dt_breakdown.items() if v > 0]),
            last_updated=generated_at,
            year_breakdown=year_breakdown_sorted,
            dt_breakdown=dt_breakdown,
            pilot_start=pilot_start,
            latest_enrichment_date=latest_enrichment_date,
            latest_enrichment_cve=latest_enrichment_cve,
            base_path="",
        )
        out = WEB_DIR / "archived.html"
        out.write_text(html, encoding="utf-8")
        self.log(f"  📄 {out.relative_to(BASE_DIR)}")

    # ------------------------------------------------------------------
    # Render the dashboard index page
    # ------------------------------------------------------------------
    def build_index(self, suppliers: list[dict], generated_at: str) -> None:
        template = self.jinja_env.get_template("index.html")

        # Summary counts
        total_records = sum(s["cve_count"] for s in suppliers)
        unique_cves: set[str] = set()
        all_data_types: set[str] = set()
        year_breakdown: dict[str, int] = {}
        dt_breakdown: dict[str, int] = dict.fromkeys(_DATA_TYPE_KEYS, 0)
        latest_enrichment_date = ""
        latest_enrichment_cve = ""

        for s in suppliers:
            for cve in s.get("cves", []):
                cve_id = cve["cve_id"]
                unique_cves.add(cve_id)
                dts = cve.get("data_types", [])
                du = cve.get("date_updated", "")
                all_data_types.update(dts)
                if du and (du > latest_enrichment_date or (du == latest_enrichment_date and cve_id < latest_enrichment_cve)):
                    latest_enrichment_date = du
                    latest_enrichment_cve = cve_id
                # Year breakdown
                year = cve_id[4:8] if cve_id.startswith("CVE-") and len(cve_id) > 8 else "Unknown"
                year_breakdown[year] = year_breakdown.get(year, 0) + 1
                # Data type breakdown
                for dt in dts:
                    if dt in dt_breakdown:
                        dt_breakdown[dt] += 1

        year_breakdown_sorted = dict(sorted(year_breakdown.items()))

        # Earliest first_enriched across all suppliers
        pilot_start = min(
            (s["first_enriched"] for s in suppliers if s.get("first_enriched")),
            default="",
        )

        html = template.render(
            suppliers=suppliers,
            total_records=total_records,
            unique_cves=len(unique_cves),
            data_types_count=len(all_data_types),
            last_updated=generated_at,
            year_breakdown=year_breakdown_sorted,
            dt_breakdown=dt_breakdown,
            pilot_start=pilot_start,
            latest_enrichment_date=latest_enrichment_date,
            latest_enrichment_cve=latest_enrichment_cve,
            base_path="",
        )

        out = WEB_DIR / "index.html"
        out.write_text(html, encoding="utf-8")
        self.log(f"  📄 {out.relative_to(BASE_DIR)}")

    # ------------------------------------------------------------------
    # Render one supplier detail page
    # ------------------------------------------------------------------
    def build_supplier_page(self, supplier: dict) -> None:
        template = self.jinja_env.get_template("supplier.html")
        slug = supplier["short_name"].lower().replace(" ", "-")
        html = template.render(supplier=supplier, last_updated=supplier.get("last_updated", ""), base_path="../")
        out = SUPPLIER_OUT_DIR / f"{slug}.html"
        out.write_text(html, encoding="utf-8")
        self.log(f"  📄 {out.relative_to(BASE_DIR)}")

    # ------------------------------------------------------------------
    # Main build entry point
    # ------------------------------------------------------------------
    def build(self) -> None:
        self.log("🚀 SADP Tracker Site Builder")
        self.prepare_dirs()

        # Load data
        raw = load_data(DATA_JSON)
        generated_at: str = raw.get("generated_at", "")
        suppliers: list[dict] = raw.get("suppliers", [])

        self.log(f"📊 Loaded {len(suppliers)} supplier(s) from data.json")

        # Enrich
        suppliers = self._enrich_suppliers(suppliers)

        # Build index
        self.log("🏗️  Building pages…")
        self.build_index(suppliers, generated_at)

        # Build supplier detail pages
        for supplier in suppliers:
            self.build_supplier_page(supplier)

        # Build archived pilot data page
        self.build_archived_page()

        self.log(f"✅ Build complete → {WEB_DIR}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    quiet = "--quiet" in sys.argv or "-q" in sys.argv
    builder = SADPSiteBuilder(quiet=quiet)
    builder.build()


if __name__ == "__main__":
    main()
