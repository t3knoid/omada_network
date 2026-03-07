# omada_network

A Python application that uses the **Unofficial Omada SDN API** to extract
network configuration data into YAML files (source of truth) and generate
Markdown documentation tables.

## Features

| Resource | YAML | Markdown |
|---|---|---|
| ACL Rules | ✓ | ✓ |
| IP Groups | ✓ | ✓ |
| Port Groups | ✓ | ✓ |
| Networks | ✓ | ✓ |
| VLANs | ✓ | ✓ |
| Switch Port Profiles | ✓ | ✓ |
| Gateway Settings | ✓ | ✓ |
| SSIDs | ✓ | ✓ |
| DHCP Reservations | ✓ | ✓ |

---

## Web UI

![Omada Network Documentation Generator web UI](https://github.com/user-attachments/assets/0b9f3db7-2231-4c28-bfbd-6865afa39d9f)

---

## Project Structure

```
omada_network/
├── omada/
│   ├── api/
│   │   └── client.py              # Omada SDN HTTP client
│   ├── exporters/
│   │   ├── yaml_exporter.py       # Writes resources to YAML files
│   │   └── markdown_generator.py  # Generates Markdown documentation
│   ├── web/
│   │   ├── app.py                 # Flask application factory
│   │   └── templates/
│   │       ├── index.html         # Main configuration form
│   │       └── doc_view.html      # Document viewer
│   ├── registry.py                # Resource registry (single place to add a resource)
│   └── service.py                 # Orchestration service layer
├── cli.py                         # Click CLI entry-point
├── tests/                         # pytest test suite
├── requirements.txt
├── requirements-dev.txt
└── pyproject.toml
```

---

## Requirements

- Python 3.10+
- An Omada SDN Controller (v5.x+) with a valid API token

---

## Installation

```bash
# Clone the repository
git clone https://github.com/t3knoid/omada_network.git
cd omada_network

# Install dependencies
pip install -r requirements.txt

# For development (includes test dependencies)
pip install -r requirements-dev.txt
```

---

## Configuration

The application requires four parameters:

| Parameter | CLI Option | Environment Variable |
|---|---|---|
| Base API URL | `--base-url` | `OMADA_BASE_URL` |
| Controller ID | `--controller-id` | `OMADA_CONTROLLER_ID` |
| API Token | `--token` | `OMADA_TOKEN` |
| Site ID | `--site-id` | `OMADA_SITE_ID` |
| Output directory | `--output-dir` | `OMADA_OUTPUT_DIR` |
| Skip SSL verify | `--no-verify-ssl` | `OMADA_NO_VERIFY_SSL` |

### Getting your Controller ID (omadacId)

The `omadacId` can be found by navigating to
`https://<controller-ip>:<port>/api/info` in your browser.

### Getting a Token

Use your Omada controller's login API to obtain a token, or obtain one from
the Omada portal.  Pass it via `--token` or the `OMADA_TOKEN` environment
variable.

---

## CLI Usage

### `fetch` — pull from the controller and generate docs

```bash
# Fetch and generate documentation with explicit options
python cli.py fetch \
  --base-url    https://192.168.1.1:8043 \
  --controller-id abc123def456 \
  --token       YOUR_TOKEN \
  --site-id     SITE_ID \
  --output-dir  docs

# Same using environment variables (ideal for CI/CD)
export OMADA_BASE_URL=https://192.168.1.1:8043
export OMADA_CONTROLLER_ID=abc123def456
export OMADA_TOKEN=YOUR_TOKEN
export OMADA_SITE_ID=SITE_ID
python cli.py fetch

# Self-signed certificate (skip SSL verification)
python cli.py fetch --no-verify-ssl ...
```

### `generate` — regenerate Markdown from existing YAML (no API credentials)

```bash
# Regenerate all Markdown files from the YAML source-of-truth in docs/
python cli.py generate --input-dir docs

# Write Markdown to a different directory
python cli.py generate --input-dir docs --output-dir site/docs

# Via environment variable
OMADA_OUTPUT_DIR=docs python cli.py generate
```

### `serve` — start the web server

```bash
python cli.py serve --host 0.0.0.0 --port 5000
# Open http://127.0.0.1:5000 in your browser
```

---

## Web UI

```bash
python cli.py serve
# Open http://127.0.0.1:5000 in your browser
```

Fill in the configuration form and click **⚡ Fetch & Generate Documentation** to
pull data from the controller and create YAML + Markdown files.

To regenerate the Markdown tables from existing YAML files without connecting
to the controller, click **🔄 Regenerate Markdown from YAML**.

Generated Markdown files appear in the **Generated Documents** panel and can
be viewed directly in the browser.

### Persistent sessions (`FLASK_SECRET_KEY`)

By default the web server generates a random secret key on startup.  This
means browser sessions — and the CSRF tokens embedded in every form — are
invalidated every time the server restarts.  For deployments that need
persistent sessions, set the `FLASK_SECRET_KEY` environment variable to a
stable, secret value:

```bash
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python cli.py serve
```

### Air-gapped networks

The web UI loads **Bootstrap 5** and **GitHub Markdown CSS** from public CDNs
(`cdn.jsdelivr.net` and `cdnjs.cloudflare.com`).  On networks without
internet access the UI will still function but will render without styling.
If you need fully offline operation, download those assets locally and update
the `<link>` / `<script>` tags in `omada/web/templates/`.

---

## GitHub Actions Integration

Store your controller credentials as **repository secrets** and use them in a
workflow.

### Adding Repository Secrets

The GitHub Actions workflow requires the following secrets to be configured in
your repository:

| Secret Name | Description |
|---|---|
| `OMADA_BASE_URL` | Base URL of your Omada controller (e.g. `https://192.168.1.1:8043`) |
| `OMADA_CONTROLLER_ID` | The `omadacId` value (see [Getting your Controller ID](#getting-your-controller-id-omadacid)) |
| `OMADA_TOKEN` | A valid API access token |
| `OMADA_SITE_ID` | The site ID to query |
| `OMADA_NO_VERIFY_SSL` | *(Optional)* Set to `true` if your controller uses a self-signed certificate |

To add these secrets:

1. Navigate to your repository on GitHub.
2. Click **Settings** → **Secrets and variables** → **Actions**.
3. Click **New repository secret**.
4. Enter the **Name** (e.g. `OMADA_BASE_URL`) and **Secret** value.
5. Click **Add secret**.
6. Repeat for each secret listed above.

> **Tip:** You can also add secrets via the GitHub CLI:
> ```bash
> gh secret set OMADA_BASE_URL --body "https://192.168.1.1:8043"
> gh secret set OMADA_CONTROLLER_ID --body "your-controller-id"
> gh secret set OMADA_TOKEN --body "your-api-token"
> gh secret set OMADA_SITE_ID --body "your-site-id"
> ```

### Workflow Configuration

```yaml
# .github/workflows/generate-docs.yml
name: Generate Omada Network Documentation

on:
  schedule:
    - cron: "0 2 * * *"   # Run nightly at 02:00 UTC
  workflow_dispatch:        # Allow manual trigger

jobs:
  generate:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Generate documentation
        env:
          OMADA_BASE_URL:       ${{ secrets.OMADA_BASE_URL }}
          OMADA_CONTROLLER_ID:  ${{ secrets.OMADA_CONTROLLER_ID }}
          OMADA_TOKEN:          ${{ secrets.OMADA_TOKEN }}
          OMADA_SITE_ID:        ${{ secrets.OMADA_SITE_ID }}
          OMADA_NO_VERIFY_SSL:  "true"   # omit for valid TLS certs
        run: python cli.py fetch --output-dir docs

      - name: Commit generated docs
        run: |
          git config user.name  "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add docs/
          git diff --cached --quiet || git commit -m "docs: update network documentation [skip ci]"
          git push
```

---

## Output

After a successful run the `docs/` directory contains:

```
docs/
├── acl_rules.yaml          ← Source of truth (YAML)
├── acl_rules.md            ← Markdown documentation table
├── ip_groups.yaml
├── ip_groups.md
├── port_groups.yaml
├── port_groups.md
├── networks.yaml
├── networks.md
├── vlans.yaml
├── vlans.md
├── switch_port_profiles.yaml
├── switch_port_profiles.md
├── gateway_settings.yaml
├── gateway_settings.md
├── ssids.yaml
├── ssids.md
├── dhcp_reservations.yaml
└── dhcp_reservations.md
```

### Example – DHCP Reservations Markdown

```markdown
# DHCP Reservations

| Network | IP Address | MAC Address | Hostname | Description |
| --- | --- | --- | --- | --- |
| LAN | 192.168.1.50 | aa:bb:cc:dd:ee:ff | printer | Office printer |
```

---

## Development

```bash
# Run tests
python -m pytest tests/ -v

# Run a specific test module
python -m pytest tests/test_client.py -v
```

### Architecture

```
CLI / Web UI
     │
     ▼
OmadaService              ← orchestrates everything
     │
     ├─► OmadaClient      ← HTTP calls to the controller API
     ├─► YamlExporter     ← writes *.yaml source-of-truth files
     └─► MarkdownGenerator ← renders *.md documentation tables
              │
              └─► Registry (registry.py)
                       └─ ResourceDefinition per resource type
                          (title, fetch_method, row_formatter, sort_key)
```

Adding a new resource type only requires:
1. A new `get_*` method on `OmadaClient`
2. A new `ResourceDefinition` entry in `omada/registry.py`

No other files need to be modified.

---

## License

MIT

