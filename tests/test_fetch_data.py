"""
Tests for fetch_data.py - SADP data fetching and parsing logic.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fetch_data import (
    extract_data_types,
    fetch_and_parse,
    fetch_and_parse_archived,
    is_sadp_container,
    parse_record,
)


# ---------------------------------------------------------------------------
# is_sadp_container
# ---------------------------------------------------------------------------

class TestIsSadpContainer:
    def test_x_adp_type_supplier_lowercase(self):
        adp = {"x_adpType": "supplier", "providerMetadata": {"shortName": "SomeOrg"}}
        assert is_sadp_container(adp) is True

    def test_x_adp_type_supplier_uppercase(self):
        adp = {"x_adpType": "Supplier", "providerMetadata": {"shortName": "SomeOrg"}}
        assert is_sadp_container(adp) is True

    def test_short_name_ends_with_sadp(self):
        adp = {"providerMetadata": {"shortName": "siemens-SADP"}}
        assert is_sadp_container(adp) is True

    def test_short_name_ends_with_sadp_any_prefix(self):
        adp = {"providerMetadata": {"shortName": "cisco-SADP"}}
        assert is_sadp_container(adp) is True

    def test_non_sadp_container(self):
        adp = {"providerMetadata": {"shortName": "CISA-ADP"}}
        assert is_sadp_container(adp) is False

    def test_empty_container(self):
        assert is_sadp_container({}) is False

    def test_cisa_adp_not_sadp(self):
        adp = {
            "providerMetadata": {
                "shortName": "CISA-ADP",
                "orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
            }
        }
        assert is_sadp_container(adp) is False

    def test_cve_program_not_sadp(self):
        adp = {
            "providerMetadata": {
                "shortName": "CVE",
                "orgId": "af854a3a-2127-422b-91ae-364da2661108",
            }
        }
        assert is_sadp_container(adp) is False


# ---------------------------------------------------------------------------
# extract_data_types
# ---------------------------------------------------------------------------

class TestExtractDataTypes:
    def test_affected_and_references(self):
        adp = {
            "affected": [{"vendor": "Acme", "product": "Widget"}],
            "references": [{"url": "https://example.com"}],
        }
        result = extract_data_types(adp)
        assert "affected" in result
        assert "references" in result
        assert "metrics" not in result
        assert "descriptions" not in result

    def test_metrics(self):
        adp = {
            "metrics": [{"cvssV3_1": {"baseScore": 7.5}}],
        }
        result = extract_data_types(adp)
        assert "metrics" in result

    def test_descriptions(self):
        adp = {
            "descriptions": [{"lang": "en", "value": "A vulnerability."}],
        }
        result = extract_data_types(adp)
        assert "descriptions" in result

    def test_empty_lists_not_counted(self):
        adp = {"affected": [], "references": []}
        result = extract_data_types(adp)
        assert result == []

    def test_empty_container(self):
        assert extract_data_types({}) == []


# ---------------------------------------------------------------------------
# parse_record
# ---------------------------------------------------------------------------

def _make_cve_json(cve_id: str, adp_containers: list[dict]) -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
        "containers": {
            "cna": {"providerMetadata": {"shortName": "TestCNA"}},
            "adp": adp_containers,
        },
    }


class TestParseRecord:
    def test_extracts_sadp_by_x_adp_type(self, tmp_path):
        adp = {
            "x_adpType": "supplier",
            "providerMetadata": {
                "shortName": "test-SADP",
                "orgId": "abc-123",
                "dateUpdated": "2025-01-01T00:00:00Z",
            },
            "affected": [{"vendor": "Acme"}],
            "references": [{"url": "https://example.com"}],
        }
        record = _make_cve_json("CVE-2025-9999", [adp])
        path = tmp_path / "CVE-2025-9999.json"
        path.write_text(json.dumps(record), encoding="utf-8")

        results = parse_record(path)
        assert len(results) == 1
        r = results[0]
        assert r["cve_id"] == "CVE-2025-9999"
        assert r["short_name"] == "test-SADP"
        assert "affected" in r["data_types"]
        assert "references" in r["data_types"]

    def test_extracts_sadp_by_short_name(self, tmp_path):
        adp = {
            "providerMetadata": {
                "shortName": "cisco-SADP",
                "orgId": "def-456",
                "dateUpdated": "2025-06-01T00:00:00Z",
            },
            "affected": [{"vendor": "Cisco"}],
        }
        record = _make_cve_json("CVE-2025-1111", [adp])
        path = tmp_path / "CVE-2025-1111.json"
        path.write_text(json.dumps(record), encoding="utf-8")

        results = parse_record(path)
        assert len(results) == 1
        assert results[0]["short_name"] == "cisco-SADP"

    def test_skips_non_sadp_containers(self, tmp_path):
        adp = {
            "providerMetadata": {
                "shortName": "CISA-ADP",
                "orgId": "134c704f-xxxx",
                "dateUpdated": "2025-01-01T00:00:00Z",
            },
        }
        record = _make_cve_json("CVE-2025-2222", [adp])
        path = tmp_path / "CVE-2025-2222.json"
        path.write_text(json.dumps(record), encoding="utf-8")

        results = parse_record(path)
        assert results == []

    def test_handles_invalid_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("NOT JSON", encoding="utf-8")
        results = parse_record(path)
        assert results == []

    def test_handles_missing_adp(self, tmp_path):
        record = {"cveMetadata": {"cveId": "CVE-2025-3333"}, "containers": {"cna": {}}}
        path = tmp_path / "CVE-2025-3333.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        results = parse_record(path)
        assert results == []


# ---------------------------------------------------------------------------
# fetch_and_parse (integration)
# ---------------------------------------------------------------------------

class TestFetchAndParse:
    def _make_sadp_repo(self, tmp_path: Path, records: list[tuple[str, list[dict]]]) -> Path:
        """Create a minimal fake sadp-pilot repo layout."""
        pub_dir = tmp_path / "Published SADP Records" / "2025" / "1xxx"
        pub_dir.mkdir(parents=True)
        for cve_id, adp_containers in records:
            record = _make_cve_json(cve_id, adp_containers)
            (pub_dir / f"{cve_id}.json").write_text(json.dumps(record), encoding="utf-8")
        return tmp_path

    def test_aggregates_by_supplier(self, tmp_path):
        adp1 = {
            "x_adpType": "supplier",
            "providerMetadata": {"shortName": "siemens-SADP", "orgId": "aaa", "dateUpdated": "2025-01-01T00:00:00Z"},
            "affected": [{"vendor": "Siemens"}],
            "references": [{"url": "https://siemens.com"}],
        }
        adp2 = {
            "x_adpType": "supplier",
            "providerMetadata": {"shortName": "siemens-SADP", "orgId": "aaa", "dateUpdated": "2025-02-01T00:00:00Z"},
            "affected": [{"vendor": "Siemens"}],
        }
        repo = self._make_sadp_repo(tmp_path, [("CVE-2025-1001", [adp1]), ("CVE-2025-1002", [adp2])])

        result = fetch_and_parse(repo)
        assert result["generated_at"]
        suppliers = result["suppliers"]
        assert len(suppliers) == 1
        s = suppliers[0]
        assert s["short_name"] == "siemens-SADP"
        assert len(s["cves"]) == 2

    def test_multiple_suppliers(self, tmp_path):
        adp_siemens = {
            "x_adpType": "supplier",
            "providerMetadata": {"shortName": "siemens-SADP", "orgId": "aaa", "dateUpdated": "2025-01-01T00:00:00Z"},
            "affected": [{"vendor": "Siemens"}],
        }
        adp_cisco = {
            "x_adpType": "supplier",
            "providerMetadata": {"shortName": "cisco-SADP", "orgId": "bbb", "dateUpdated": "2025-01-01T00:00:00Z"},
            "affected": [{"vendor": "Cisco"}],
        }
        # One record with both suppliers
        repo = self._make_sadp_repo(tmp_path, [("CVE-2025-5000", [adp_siemens, adp_cisco])])

        result = fetch_and_parse(repo)
        names = {s["short_name"] for s in result["suppliers"]}
        assert "siemens-SADP" in names
        assert "cisco-SADP" in names


class TestFetchAndParseArchived:
    def _make_sadp_repo(self, tmp_path: Path, records: list[tuple[str, list[dict]]]) -> Path:
        """Create a minimal fake sadp-pilot repo layout for archived data."""
        archived_dir = tmp_path / "Archived Pilot Data"
        archived_dir.mkdir(parents=True)
        for cve_id, adp_containers in records:
            record = _make_cve_json(cve_id, adp_containers)
            (archived_dir / f"{cve_id}.json").write_text(json.dumps(record), encoding="utf-8")
        return tmp_path

    def test_parses_flat_archived_directory(self, tmp_path):
        adp1 = {
            "x_adpType": "supplier",
            "providerMetadata": {
                "shortName": "siemens-SADP",
                "orgId": "aaa",
                "dateUpdated": "2026-03-01T00:00:00Z",
            },
            "affected": [{"vendor": "Siemens", "product": "SIMATIC"}],
            "references": [{"url": "https://example.com/advisory"}],
        }
        adp2 = {
            "x_adpType": "supplier",
            "providerMetadata": {
                "shortName": "cisco-SADP",
                "orgId": "bbb",
                "dateUpdated": "2026-03-02T00:00:00Z",
            },
            "metrics": [{"cvssV3_1": {"baseScore": 6.5}}],
        }
        repo = self._make_sadp_repo(
            tmp_path,
            [("CVE-2026-0001", [adp1]), ("CVE-2026-0002", [adp2])],
        )

        result = fetch_and_parse_archived(repo)

        assert result["generated_at"]
        suppliers = {s["short_name"]: s for s in result["suppliers"]}
        assert set(suppliers.keys()) == {"siemens-SADP", "cisco-SADP"}
        assert len(suppliers["siemens-SADP"]["cves"]) == 1
        assert len(suppliers["cisco-SADP"]["cves"]) == 1

        cve = suppliers["siemens-SADP"]["cves"][0]
        assert cve["cve_id"] == "CVE-2026-0001"
        assert cve["file_path"] == "CVE-2026-0001.json"
        assert cve["affected_products"] == [{"vendor": "Siemens", "product": "SIMATIC"}]
