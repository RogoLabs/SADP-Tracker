"""
Tests for fetch_data.py - SADP data fetching and parsing logic.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch


# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fetch_data import (
    SOURCE_BOTH,
    SOURCE_CVELISTV5,
    SOURCE_SADP_PILOT,
    _parse_adp_list,
    extract_data_types,
    fetch_and_parse,
    fetch_and_parse_archived,
    fetch_from_cvelistv5,
    is_sadp_container,
    merge_sources,
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


# ---------------------------------------------------------------------------
# _parse_adp_list (source field)
# ---------------------------------------------------------------------------

class TestParseAdpList:
    def test_source_field_defaults_to_sadp_pilot(self):
        adp = {
            "x_adpType": "supplier",
            "providerMetadata": {"shortName": "siemens-SADP", "orgId": "aaa", "dateUpdated": "2025-01-01T00:00:00Z"},
            "affected": [{"vendor": "Siemens"}],
        }
        results = _parse_adp_list("CVE-2025-9999", [adp], "CVE-2025-9999.json")
        assert len(results) == 1
        assert results[0]["source"] == SOURCE_SADP_PILOT

    def test_source_field_cvelistv5(self):
        adp = {
            "x_adpType": "supplier",
            "providerMetadata": {"shortName": "siemens-SADP", "orgId": "aaa", "dateUpdated": "2025-01-01T00:00:00Z"},
        }
        results = _parse_adp_list("CVE-2025-9999", [adp], "cves/2025/9xxx/CVE-2025-9999.json", SOURCE_CVELISTV5)
        assert results[0]["source"] == SOURCE_CVELISTV5

    def test_skips_non_sadp_entries(self):
        adp = {"providerMetadata": {"shortName": "CISA-ADP"}}
        results = _parse_adp_list("CVE-2025-1111", [adp], "CVE-2025-1111.json")
        assert results == []


# ---------------------------------------------------------------------------
# parse_record (source propagation)
# ---------------------------------------------------------------------------

class TestParseRecordSource:
    def test_source_propagated_to_result(self, tmp_path):
        adp = {
            "x_adpType": "supplier",
            "providerMetadata": {"shortName": "siemens-SADP", "orgId": "aaa", "dateUpdated": "2025-01-01T00:00:00Z"},
        }
        record = {
            "dataType": "CVE_RECORD",
            "cveMetadata": {"cveId": "CVE-2025-1234"},
            "containers": {"cna": {}, "adp": [adp]},
        }
        path = tmp_path / "CVE-2025-1234.json"
        path.write_text(json.dumps(record), encoding="utf-8")

        results = parse_record(path, source=SOURCE_CVELISTV5)
        assert results[0]["source"] == SOURCE_CVELISTV5


# ---------------------------------------------------------------------------
# fetch_from_cvelistv5
# ---------------------------------------------------------------------------

def _make_cvelistv5_record(cve_id: str, adp_containers: list) -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
        "containers": {
            "cna": {"providerMetadata": {"shortName": "TestCNA"}},
            "adp": adp_containers,
        },
    }


class TestFetchFromCvelistv5:
    def _make_search_response(self, paths: list[str]) -> dict:
        return {
            "total_count": len(paths),
            "incomplete_results": False,
            "items": [{"path": p, "name": Path(p).name} for p in paths],
        }

    def test_returns_sadp_records(self):
        """fetch_from_cvelistv5 parses SADP containers found via the search API."""
        file_path = "cves/2025/6xxx/CVE-2025-6965.json"
        adp = {
            "x_adpType": "supplier",
            "providerMetadata": {
                "orgId": "0b142b55-0307-4c5a-b3c9-f314f3fb7c5e",
                "shortName": "siemens-SADP",
                "dateUpdated": "2026-04-14T08:58:07.313Z",
            },
            "affected": [{"vendor": "Siemens", "product": "RUGGEDCOM"}],
            "references": [{"url": "https://cert-portal.siemens.com/productcert/html/ssa-485750.html"}],
        }
        raw_content = json.dumps(_make_cvelistv5_record("CVE-2025-6965", [adp]))

        search_response = self._make_search_response([file_path])

        with patch("fetch_data._github_api_get", return_value=search_response), \
             patch("fetch_data._fetch_raw_github_file", return_value=raw_content):
            result = fetch_from_cvelistv5(github_token="fake-token")

        assert result["generated_at"]
        suppliers = {s["short_name"]: s for s in result["suppliers"]}
        assert "siemens-SADP" in suppliers
        cves = suppliers["siemens-SADP"]["cves"]
        assert len(cves) == 1
        assert cves[0]["cve_id"] == "CVE-2025-6965"
        assert cves[0]["source"] == SOURCE_CVELISTV5
        assert cves[0]["file_path"] == file_path

    def test_skips_non_sadp_files(self):
        """Files found by search that have no SADP container are silently skipped."""
        file_path = "cves/2023/1xxx/CVE-2023-1000.json"
        # A record with only a non-SADP ADP container
        adp = {"providerMetadata": {"shortName": "CISA-ADP"}}
        raw_content = json.dumps(_make_cvelistv5_record("CVE-2023-1000", [adp]))

        search_response = self._make_search_response([file_path])

        with patch("fetch_data._github_api_get", return_value=search_response), \
             patch("fetch_data._fetch_raw_github_file", return_value=raw_content):
            result = fetch_from_cvelistv5()

        assert result["suppliers"] == []

    def test_handles_api_error_gracefully(self):
        """A Search API failure returns an empty result rather than crashing."""
        with patch("fetch_data._github_api_get", side_effect=Exception("network error")):
            result = fetch_from_cvelistv5()

        assert result["suppliers"] == []

    def test_handles_file_fetch_error_gracefully(self):
        """If fetching an individual file fails, it is skipped and others continue."""
        paths = [
            "cves/2025/1xxx/CVE-2025-1001.json",
            "cves/2025/1xxx/CVE-2025-1002.json",
        ]
        good_adp = {
            "x_adpType": "supplier",
            "providerMetadata": {"shortName": "siemens-SADP", "orgId": "aaa", "dateUpdated": "2025-01-01T00:00:00Z"},
        }
        good_content = json.dumps(_make_cvelistv5_record("CVE-2025-1002", [good_adp]))
        search_response = self._make_search_response(paths)

        call_count = 0

        def mock_fetch(owner, repo, path, token):
            nonlocal call_count
            call_count += 1
            if "1001" in path:
                raise Exception("HTTP 404")
            return good_content

        with patch("fetch_data._github_api_get", return_value=search_response), \
             patch("fetch_data._fetch_raw_github_file", side_effect=mock_fetch):
            result = fetch_from_cvelistv5()

        # Only the successful file contributed a record
        assert len(result["suppliers"]) == 1
        assert result["suppliers"][0]["cves"][0]["cve_id"] == "CVE-2025-1002"

    def test_no_token_still_works(self):
        """fetch_from_cvelistv5 works without a token (unauthenticated)."""
        search_response = {"total_count": 0, "incomplete_results": False, "items": []}

        with patch("fetch_data._github_api_get", return_value=search_response) as mock_get:
            result = fetch_from_cvelistv5(github_token=None)

        assert result["suppliers"] == []
        # Verify the search was attempted
        mock_get.assert_called_once()


# ---------------------------------------------------------------------------
# merge_sources
# ---------------------------------------------------------------------------

class TestMergeSources:
    def _make_supplier_result(self, entries: list[tuple[str, str, str]]) -> dict:
        """Create a minimal result dict. entries = [(short_name, cve_id, source)]"""
        from datetime import UTC, datetime
        suppliers: dict[str, dict] = {}
        for short_name, cve_id, source in entries:
            if short_name not in suppliers:
                suppliers[short_name] = {"short_name": short_name, "org_id": "xxx", "cves": []}
            suppliers[short_name]["cves"].append({"cve_id": cve_id, "source": source, "data_types": [], "affected_products": []})
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "suppliers": list(suppliers.values()),
        }

    def test_secondary_adds_new_suppliers(self):
        primary = self._make_supplier_result([("siemens-SADP", "CVE-2025-1001", SOURCE_SADP_PILOT)])
        secondary = self._make_supplier_result([("cisco-SADP", "CVE-2025-2001", SOURCE_CVELISTV5)])

        result = merge_sources(primary, secondary)
        names = {s["short_name"] for s in result["suppliers"]}
        assert names == {"siemens-SADP", "cisco-SADP"}

    def test_secondary_adds_new_cves_to_existing_supplier(self):
        primary = self._make_supplier_result([("siemens-SADP", "CVE-2025-1001", SOURCE_SADP_PILOT)])
        secondary = self._make_supplier_result([("siemens-SADP", "CVE-2025-1002", SOURCE_CVELISTV5)])

        result = merge_sources(primary, secondary)
        assert len(result["suppliers"]) == 1
        cve_ids = {c["cve_id"] for c in result["suppliers"][0]["cves"]}
        assert cve_ids == {"CVE-2025-1001", "CVE-2025-1002"}

    def test_duplicate_cve_marked_as_both(self):
        primary = self._make_supplier_result([("siemens-SADP", "CVE-2025-1001", SOURCE_SADP_PILOT)])
        secondary = self._make_supplier_result([("siemens-SADP", "CVE-2025-1001", SOURCE_CVELISTV5)])

        result = merge_sources(primary, secondary)
        cves = result["suppliers"][0]["cves"]
        assert len(cves) == 1
        assert cves[0]["source"] == SOURCE_BOTH

    def test_empty_secondary(self):
        primary = self._make_supplier_result([("siemens-SADP", "CVE-2025-1001", SOURCE_SADP_PILOT)])
        secondary = {"generated_at": "", "suppliers": []}

        result = merge_sources(primary, secondary)
        assert len(result["suppliers"]) == 1
        assert result["suppliers"][0]["cves"][0]["source"] == SOURCE_SADP_PILOT

    def test_empty_primary(self):
        primary = {"generated_at": "", "suppliers": []}
        secondary = self._make_supplier_result([("siemens-SADP", "CVE-2025-1001", SOURCE_CVELISTV5)])

        result = merge_sources(primary, secondary)
        assert len(result["suppliers"]) == 1
        assert result["suppliers"][0]["cves"][0]["source"] == SOURCE_CVELISTV5

    def test_result_sorted_by_short_name(self):
        primary = self._make_supplier_result([("z-SADP", "CVE-2025-1001", SOURCE_SADP_PILOT)])
        secondary = self._make_supplier_result([("a-SADP", "CVE-2025-2001", SOURCE_CVELISTV5)])

        result = merge_sources(primary, secondary)
        names = [s["short_name"] for s in result["suppliers"]]
        assert names == sorted(names)
