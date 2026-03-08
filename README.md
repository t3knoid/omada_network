# omada_network

A Python application that uses the **Omada Open API** (Northbound API) to
extract network configuration data into YAML files (source of truth) and
generate Markdown documentation tables.

Supports both official Open API authentication modes:

- **Client Credentials Mode** — direct token exchange with Client ID + Secret
- **Authorization Code Mode** — three-step flow with user credentials

## Features

| Resource | YAML | Markdown |
| --- | --- | --- |
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

## Web Front End

![Web UI](image.png)

---

## Project Structure

```text
omada_network/
├── omada/
│   ├── api/
│   │   └── openapi_client.py      # Official Open API (Northbound) client
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
- An Omada SDN Controller (v5.x / v6.x) with:
  - **Open API enabled** and a Client ID + Client Secret generated in the controller settings

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

The application supports two authentication modes, both using the official
Omada Open API (Northbound API):

### Option A — Client Credentials Mode (simplest)

Direct token exchange using the Client ID and Client Secret only. No
controller login credentials are needed.

**Prerequisites:** Enable the Open API on your Omada controller and generate
a Client ID and Client Secret in the controller settings.

| Parameter | CLI Option | Environment Variable | Default |
| --- | --- | --- | --- |
| Controller IP / hostname | `--controller` | `OMADA_CONTROLLER` | |
| Management port | `--port` | `OMADA_PORT` | `443` |
| Controller ID | `--controller-id` | `OMADA_CONTROLLER_ID` | auto-discovered |
| Client ID | `--client-id` | `OMADA_CLIENT_ID` | |
| Client Secret | `--client-secret` | `OMADA_CLIENT_SECRET` | |
| Site name | `--site-name` | `OMADA_SITE_NAME` | |
| Output directory | `--output-dir` | `OMADA_OUTPUT_DIR` | `docs` |
| Verify SSL cert | `--verify-ssl` | `OMADA_VERIFY_SSL` | off |

```bash
python cli.py fetch \
  --controller 192.168.1.1 \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_CLIENT_SECRET

# Multi-site controller — select by name
python cli.py fetch \
  --controller 192.168.1.1 \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_CLIENT_SECRET \
  --site-name "My Office"

# Using environment variables
export OMADA_CONTROLLER=192.168.1.1
export OMADA_CLIENT_ID=YOUR_CLIENT_ID
export OMADA_CLIENT_SECRET=YOUR_CLIENT_SECRET
python cli.py fetch
```

### Option B — Authorization Code Mode

Three-step OAuth2 flow that additionally requires controller admin
credentials (username and password). Use this mode when your Open API
configuration requires user-level authorization.

| Parameter | CLI Option | Environment Variable | Default |
| --- | --- | --- | --- |
| Controller IP / hostname | `--controller` | `OMADA_CONTROLLER` | |
| Management port | `--port` | `OMADA_PORT` | `443` |
| Controller ID | `--controller-id` | `OMADA_CONTROLLER_ID` | auto-discovered |
| Client ID | `--client-id` | `OMADA_CLIENT_ID` | |
| Client Secret | `--client-secret` | `OMADA_CLIENT_SECRET` | |
| Username | `--username` | `OMADA_USERNAME` | |
| Password | `--password` | `OMADA_PASSWORD` | |
| Site name | `--site-name` | `OMADA_SITE_NAME` | |
| Output directory | `--output-dir` | `OMADA_OUTPUT_DIR` | `docs` |
| Verify SSL cert | `--verify-ssl` | `OMADA_VERIFY_SSL` | off |

```bash
python cli.py fetch \
  --controller 192.168.1.1 \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_CLIENT_SECRET \
  --username admin \
  --password secret
```

> **Note:** When `--username` and `--password` are provided alongside the
> client credentials, the tool automatically uses Authorization Code mode.
> Without them, it defaults to Client Credentials mode.

### Auto-discovery

Both modes automatically discover:

1. **Controller ID** — `GET /api/info` → `result.omadacId` (unless
   `--controller-id` is explicitly provided)
2. **Site ID** — via the Open API sites endpoint. For controllers with
   multiple sites, pass `--site-name` to select by display name
   (case-insensitive).

---

## CLI Usage

### `fetch` — pull from the controller and generate docs

```bash
# Client Credentials mode (simplest)
python cli.py fetch \
  --controller 192.168.1.1 \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_CLIENT_SECRET

# Authorization Code mode (add --username / --password)
python cli.py fetch \
  --controller 192.168.1.1 \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_CLIENT_SECRET \
  --username admin \
  --password secret

# Multi-site controller — select by name
python cli.py fetch \
  --controller 192.168.1.1 \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_CLIENT_SECRET \
  --site-name "My Office"

# Same using environment variables (ideal for CI/CD)
export OMADA_CONTROLLER=192.168.1.1
export OMADA_CLIENT_ID=YOUR_CLIENT_ID
export OMADA_CLIENT_SECRET=YOUR_CLIENT_SECRET
python cli.py fetch

# Enable SSL verification (off by default)
python cli.py fetch --verify-ssl ...
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

The configuration form offers two authentication tabs:

- **🔒 Client Credentials** — enter your Client ID and Client Secret for a
  direct token exchange (simplest mode).
- **🔑 Authorization Code** — enter Client ID, Client Secret, plus your
  controller username and password for the three-step OAuth2 flow.

> **Note on SSL verification defaults:** The web UI defaults to SSL
> verification **enabled** (checkbox checked) to encourage secure connections
> in the browser-based workflow. The CLI defaults to SSL verification **off**
> (`--verify-ssl` must be passed explicitly) because most self-signed
> controller setups are managed from the command line. This difference is
> intentional — set `OMADA_VERIFY_SSL=true` or pass `--verify-ssl` in the CLI
> if your controller has a valid (non-self-signed) certificate.

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

If you need fully offline operation, download the three assets listed below
and place them in a local directory (e.g. `omada/web/static/`):

| Asset | CDN URL |
| --- | --- |
| Bootstrap 5.3.3 CSS | `https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css` |
| Bootstrap 5.3.3 JS | `https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js` |
| GitHub Markdown CSS 5.5.1 | `https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.5.1/github-markdown-light.min.css` |

Then update the `<link>` and `<script>` tags in both
`omada/web/templates/index.html` and `omada/web/templates/doc_view.html` to
point to the local files instead of the CDN URLs. For example, replace:

```html
<link rel="stylesheet"
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
```

with:

```html
<link rel="stylesheet"
      href="{{ url_for('static', filename='bootstrap.min.css') }}">
```

Repeat for the Bootstrap JS bundle and the GitHub Markdown CSS file.

---

## GitHub Actions Integration

Store your controller credentials as **repository secrets** and use them in a
workflow.

### Adding Repository Secrets

The GitHub Actions workflow requires the following secrets to be configured in
your repository:

| Secret Name | Description |
| --- | --- |
| `OMADA_CONTROLLER` | IP address or hostname of your Omada controller (e.g. `192.168.1.1`) |
| `OMADA_PORT` | *(Optional)* Management port if not the default `443` |
| `OMADA_CLIENT_ID` | Client ID from controller Open API settings |
| `OMADA_CLIENT_SECRET` | Client Secret from controller Open API settings |
| `OMADA_USERNAME` | *(Authorization Code mode)* Controller admin username |
| `OMADA_PASSWORD` | *(Authorization Code mode)* Controller admin password |
| `OMADA_CONTROLLER_ID` | *(Optional)* The `omadacId` — auto-discovered if omitted |
| `OMADA_SITE_NAME` | *(Optional)* Human-readable site name for multi-site controllers |
| `OMADA_VERIFY_SSL` | *(Optional)* Set to `true` if your controller has a valid (non-self-signed) certificate |

To add these secrets:

1. Navigate to your repository on GitHub.
2. Click **Settings** → **Secrets and variables** → **Actions**.
3. Click **New repository secret**.
4. Enter the **Name** (e.g. `OMADA_CONTROLLER`) and **Secret** value.
5. Click **Add secret**.
6. Repeat for each secret listed above.

**Tip:** You can also add secrets via the GitHub CLI:

```bash
gh secret set OMADA_CONTROLLER --body "192.168.1.1"
gh secret set OMADA_CLIENT_ID --body "your-client-id"
gh secret set OMADA_CLIENT_SECRET --body "your-client-secret"
# For Authorization Code mode, also set:
# gh secret set OMADA_USERNAME --body "admin"
# gh secret set OMADA_PASSWORD --body "your-password"
# For multi-site controllers:
# gh secret set OMADA_SITE_NAME --body "My Office"
```

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
          OMADA_CONTROLLER:     ${{ secrets.OMADA_CONTROLLER }}
          OMADA_CLIENT_ID:      ${{ secrets.OMADA_CLIENT_ID }}
          OMADA_CLIENT_SECRET:  ${{ secrets.OMADA_CLIENT_SECRET }}
          OMADA_SITE_NAME:      ${{ secrets.OMADA_SITE_NAME }}
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

```text
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

| Network | IP Address | MAC Address | Name | Status | Server |
| --- | --- | --- | --- | --- | --- |
| LAN | 192.168.1.50 | AA-BB-CC-DD-EE-FF | printer | Enabled | Gateway |
```

---

## Development

```bash
# Run tests
python -m pytest tests/ -v

# Run a specific test module
python -m pytest tests/test_openapi_client.py -v
```

### Architecture

```text
CLI / Web UI
     │
     ▼
OmadaService                ← orchestrates everything
     │
     ├─► OmadaOpenApiClient  ← HTTP calls to the Open API
     ├─► YamlExporter        ← writes *.yaml source-of-truth files
     └─► MarkdownGenerator   ← renders *.md documentation tables
              │
              └─► Registry (registry.py)
                       └─ ResourceDefinition per resource type
                          (title, fetch_method, row_formatter, sort_key)
```

Adding a new resource type only requires:

1. A new `get_*` method on `OmadaOpenApiClient`
2. A new `ResourceDefinition` entry in `omada/registry.py`

No other files need to be modified.

---

## License

MIT
