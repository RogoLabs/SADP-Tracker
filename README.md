# SADP Tracker

A dashboard for monitoring which CNAs (Suppliers) are adding enrichment data to CVE records through the [CVE Program Supplier ADP (SADP) Pilot](https://github.com/CVEProject/sadp-pilot).

Built with the same look, feel, and tech stack as [CVE.ICU](https://github.com/RogoLabs/cve.icu).

## Data Disclaimer

- Production dashboard data comes from `Published SADP Records` and reflects current Supplier ADP enrichment.
- Archive page data comes from `Archived Pilot Data` and represents historical Phase I test records.
- Archived Phase I records are not published to the official CVE List and should be treated as pilot/test data.

## What is the Supplier ADP Pilot?

The **Supplier ADP Pilot** allows CVE Numbering Authorities (CNAs) that are also product vendors to add enrichment data to CVE records for vulnerabilities assigned by *other* CNAs that affect their products. This enrichment can include:

- **Affected** — product version ranges impacted by the CVE
- **References** — vendor advisories and patch links
- **Metrics** — CVSS scores from the vendor's perspective
- **Descriptions** — additional context from the supplier

Supplier ADP containers are identified by:
- `containers.adp[].x_adpType == "supplier"`, **OR**
- `containers.adp[].providerMetadata.shortName` ending in `-SADP`

## Tech Stack

| Layer | Technology |
|---|---|
| Site Generation | Python 3.12 + Jinja2 (static HTML) |
| Hosting | GitHub Pages |
| Data Source | [`CVEProject/sadp-pilot`](https://github.com/CVEProject/sadp-pilot) |
| Automation | GitHub Actions (`.github/workflows/update-data.yml`) |

## Project Structure

```
SADP-Tracker/
├── build.py            # Static site generator (Jinja2 → web/)
├── fetch_data.py       # Parses sadp-pilot repo → data/data.json + data/archived_data.json
├── requirements.txt    # Python dependencies
├── pyproject.toml      # Project metadata + tool config
├── templates/
│   ├── base.html       # Base template (nav, dark mode, footer)
│   ├── index.html      # Dashboard — supplier list + stats
│   ├── supplier.html   # Individual supplier detail page
│   └── archived.html   # Phase I archive dashboard (test data)
├── web/
│   └── static/
│       └── css/
│           └── style.css   # Design system (from CVE.ICU)
├── data/
│   ├── data.json            # Consolidated published SADP data (auto-generated)
│   └── archived_data.json   # Consolidated Phase I archived/test data (auto-generated)
├── tests/
│   └── test_fetch_data.py
└── .github/
    └── workflows/
        └── update-data.yml  # CI: fetch → build → deploy
```

## Dashboard Features

### Dashboard View (`/index.html`)
- Summary statistics: supplier count, enriched record count, unique CVEs
- Sortable table of participating suppliers with:
  - CVE record count per supplier
  - Data types contributed (affected, references, metrics, descriptions)
  - Date of last update
  - Link to supplier detail page
- Client-side search/filter
- Dark/light mode toggle

### Supplier Detail View (`/supplier/<name>.html`)
- Breadcrumb navigation back to dashboard
- Per-supplier stats: total records, counts by data type
- Full table of enriched CVE IDs linking to `cve.org`
- Sorted by most recent update date
- Client-side search/filter

### Phase I Archive View (`/archived.html`)
- Dedicated dashboard for historical archived/test records from `Archived Pilot Data`
- Prominent warning banner clarifying records are Phase I test data and not in the official CVE List
- CVE year distribution chart + data type coverage breakdown
- Supplier summary table and full archived CVE table
- Client-side search/filter and sortable columns

## Local Development

```bash
# 1. Clone the sadp-pilot data source
git clone --depth=1 https://github.com/CVEProject/sadp-pilot.git /tmp/sadp-pilot

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Parse SADP data
SADP_REPO_PATH=/tmp/sadp-pilot python fetch_data.py

# 4. Build the site
python build.py

# 5. Preview
python -m http.server 8080 --directory web
# open http://localhost:8080
```

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## Automation

The [GitHub Actions workflow](.github/workflows/update-data.yml) runs every 6 hours and:

1. Checks out this repository
2. Clones `CVEProject/sadp-pilot`
3. Runs `fetch_data.py` to parse all SADP records and generate `data/data.json` and `data/archived_data.json`
4. Runs `build.py` to render HTML from templates
5. Deploys the `web/` directory to GitHub Pages using the GitHub Actions Pages deployment API
6. Commits updated generated data files back to `main` on scheduled/manual runs

## License

MIT © [RogoLabs](https://rogolabs.net)