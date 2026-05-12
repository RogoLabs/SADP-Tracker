# SADP Tracker

SADP Tracker is a static dashboard for monitoring Supplier ADP enrichment activity in CVE records.

Live site: https://rogolabs.github.io/SADP-Tracker/

Data source: https://github.com/CVEProject/sadp-pilot

## What It Tracks

- Participating supplier CNAs and their enrichment activity
- Total enriched records and unique CVEs
- Coverage for affected, references, metrics, and descriptions
- Latest enrichment date with linked CVE record on CVE.org
- Historical Phase I test data in a separate archived view

## Data Disclaimer

- Production dashboard data comes from Published SADP Records.
- Archived page data comes from Archived Pilot Data.
- Archived Phase I records are pilot/test records and are not official CVE List publications.

## Tech Stack

- Python 3.12+
- Jinja2 static site generation
- GitHub Actions for scheduled data refresh + deployment
- GitHub Pages hosting

## Project Layout

```text
SADP-Tracker/
|- build.py
|- fetch_data.py
|- data/
|  |- data.json
|  |- archived_data.json
|- templates/
|  |- base.html
|  |- index.html
|  |- supplier.html
|  `- archived.html
|- web/
|  |- index.html
|  |- archived.html
|  |- supplier/
|  `- static/css/style.css
`- .github/workflows/update-data.yml
```

## Local Development

```bash
# 1) Clone SADP data source
git clone --depth=1 https://github.com/CVEProject/sadp-pilot.git /tmp/sadp-pilot

# 2) Install dependencies
python3 -m pip install -r requirements.txt

# 3) Build data files
SADP_REPO_PATH=/tmp/sadp-pilot python3 fetch_data.py

# 4) Build static site
python3 build.py

# 5) Preview
python3 -m http.server 8080 --directory web
# open http://localhost:8080
```

## Testing

```bash
python3 -m pip install pytest
pytest tests -v
```

## Automation

The workflow in .github/workflows/update-data.yml runs every 6 hours, and on pushes to main, to:

1. Clone this repository and CVEProject/sadp-pilot
2. Parse SADP records into data/data.json and data/archived_data.json
3. Build the static site into web/
4. Deploy web/ to GitHub Pages
5. Commit updated production data on scheduled/manual runs

## License

MIT Copyright (c) RogoLabs