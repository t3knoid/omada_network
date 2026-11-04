# Architecture

## Overview

The application connects to TP-Link Omada controllers via the official
**Omada Open API (Northbound API)** to extract network configuration data,
persist it as YAML (source of truth), and generate Markdown documentation
tables. The resources it covers are listed in the
[API reference resource index](api_reference.md#resource-index). It is
read-only towards the controller.

**Design principles:**

- **Registry-driven** — all resource definitions live in a single registry;
  adding a resource requires minimal code changes.
- **Two-mode operation** — fetch from the API *or* regenerate Markdown from
  existing YAML files (no credentials needed for generation).
- **CLI + Web UI** — both interfaces share the same service layer.
- **Graceful degradation** — if one resource fails to fetch, the remaining
  resources continue; failures are logged and reported.
- **YAML as source of truth** — Markdown can be regenerated at any time from
  the YAML files without API access.
- **Secrets redacted by default** — credentials never reach the exports
  unless explicitly requested (`--include-secrets`).

---

## Layer Diagram

```text
┌──────────────────────────────────────────────────────────────┐
│  CLI (cli.py)                    │  Web UI (omada/web/app.py)│
│  - fetch  (API → YAML + MD)      │  - /run  (API → YAML + MD)│
│  - generate (YAML → MD)          │  - /regenerate (YAML → MD)│
│  - serve  (start web server)     │  - /docs/* (view docs)    │
│  - diagnose (debug endpoints)    │  - /download (get files)  │
└──────────────┬───────────────────────────────┬───────────────┘
               │                               │
               └───────────────┬───────────────┘
                               │
                 ┌─────────────▼──────────────┐
                 │      Service Layer         │
                 │    (omada/service.py)      │
                 │  OmadaService              │
                 │  generate_from_yaml()      │
                 └───┬─────────┬───────────┬──┘
                     │         │           │
          ┌──────────▼──┐  ┌───▼──────┐  ┌─▼────────────────┐
          │  API Client │  │ Registry │  │   Exporters      │
          │ openapi_    │  │ registry │  │ YamlExporter     │
          │ client.py   │  │ .py      │  │ MarkdownGenerator│
          │  - Auth     │  │  - Defns │  └──────────────────┘
          │  - GET/POST │  │  - Row / │
          │  - Paging   │  │  detail  │
          │  - Enrich   │  │  fmts    │
          └─────────────┘  └──────────┘

          ┌─────────────────────────┐   ┌─────────────────────────┐
          │   Credential Redaction  │   │   Logging Config        │
          │   (redaction.py)        │   │  (logging_config.py)    │
          │  redact_secrets()       │   │  setup_logging()        │
          │  contains_secrets()     │   └─────────────────────────┘
          └─────────────────────────┘
```

---

## Components

### CLI — `cli.py`

Command-line entry point built with [Click](https://click.palletsprojects.com/).

| Command | Purpose |
| --- | --- |
| `fetch` | Authenticate, pull every resource from the controller, write YAML + Markdown |
| `generate` | Regenerate Markdown from existing YAML (no API credentials needed) |
| `serve` | Start the Flask web server |
| `diagnose` | Probe each API endpoint and display raw response structure for debugging |

Key helpers:

- `_env()` / `_env_bool()` — read typed values from environment variables.
- `_openapi_options()` — shared decorator applying common CLI options.
- `_build_client()` — authenticate (auto-selecting the correct mode) and
  discover the site; returns `(api_client, site_id, site_name, controller_id,
  login_result)`, used by `fetch` and `diagnose`. The web UI follows the same
  steps inline.

Running `cli.py` without a subcommand invokes `fetch`. `fetch` takes
`--output-dir` and `--include-secrets` in addition to the connection options.
`serve` takes `--host`, `--port`, `--output-dir` and `--debug`. `diagnose`
prints record counts and field names, never values.

All CLI options have corresponding `OMADA_*` environment variables for
headless / CI usage.

---

### Service Layer — `omada/service.py`

High-level orchestration that both the CLI and web UI delegate to.

**`OmadaService(client, site_id, output_dir, site_name=None,
include_secrets=False)`** — files are written to
`{output_dir}/{safe site name}/`. The site name is made filesystem-safe,
including Windows reserved names. When `include_secrets` is set, it also sets
`client.include_secrets` so the client's own getters stop redacting.

| Method | Description |
| --- | --- |
| `fetch_all()` | Iterate over every `ResourceDefinition` in the registry and call its fetch method on the API client, passing each result through `redact_secrets()` (unless `include_secrets`) so no credential reaches the exports. Failures are caught per resource: the resource is stored as `[]` and listed in an error summary, and the remaining resources continue. |
| `export_yaml(data)` | Delegate to `YamlExporter.export_all()` |
| `generate_docs(data)` | Delegate to `MarkdownGenerator.generate_all()` |
| `run()` | Orchestrate the full pipeline: create output dir → `fetch_all` → `export_yaml` → `generate_docs` → return paths |

**`generate_from_yaml(input_dir, output_dir, site_name=None)`** — standalone
function that loads `*.yaml` files from disk (from the site subdirectory when
`site_name` is given), passes the full data set as cross-reference context,
and writes Markdown. No API interaction.

---

### API Client — `omada/api/openapi_client.py`

HTTP client for the Omada Open API supporting both official OAuth 2 modes.

**Authentication & discovery functions:**

| Function | Purpose |
| --- | --- |
| `discover_controller_id()` | `GET /api/info` (unauthenticated) → extract `omadacId` |
| `openapi_login()` | Client Credentials grant → access token |
| `openapi_auth_code_login()` | Three-step Authorization Code flow → access token |
| `openapi_discover_site()` | List sites and resolve by name (case-insensitive); returns `(site_id, site_name)`. A single site is auto-selected. `openapi_discover_site_id()` is a wrapper returning only the ID |

**`OmadaOpenApiClient`** — authenticated client for data retrieval.

| Internal method | Description |
| --- | --- |
| `_api_url(path, api_version)` | Build full URL from relative path + `omadacId` |
| `_get(path)` | Single GET request; check `errorCode`; return `result` |
| `_get_paged(path, page_size, max_pages)` | Paginated GET; auto-detect response shape; aggregate pages |
| `_post(path, payload)` | Read-only POST query (only `switches/ports/select`); same error handling as `_get` |
| `_collect(site_id, parts, label)` | Fetch several endpoints into one dict, each best-effort; raise only if all fail |
| `_redact(data)` | Apply `redact_secrets()` unless `include_secrets` is set |

Public `get_*` methods (one per resource) call these helpers. Three
patterns recur:

- **Fallback:** try a preferred endpoint, then an alternative if it returns
  an error (e.g. `/lan-networks/all`, then paginated `/lan-networks`).
- **Enrichment:** list endpoints are often summaries, so records are merged
  with per-item detail. Examples: SSID detail and AP overrides; portal
  detail; full switch-port config from `switches/ports/select`; PoE / port
  schedule membership; LAG names; WAN status for gateway ports; DHCP pool
  usage.
- **Composition:** some resources combine several endpoints into one dict:
  `wan_failover`, `dns_settings`, `time_settings`, `multicast_services`,
  `wireless_settings`, `ssl_vpn`, `switch_settings`, `switch_security`,
  `oui_vlans`, `switch_qos`, `lags`, `uplinks`, `port_schedules`.

Per-device lookups (switch, gateway and AP endpoints) iterate over
`get_devices()`, filtered by device type. Results are tagged with
`deviceName` / `deviceMac` / `deviceModel`.

---

### Resource Registry — `omada/registry.py`

Single source of truth for every resource type the application supports.

**`ResourceDefinition`** (frozen dataclass):

| Field | Description |
| --- | --- |
| `name` | Snake-case identifier (e.g. `acl_rules`) |
| `title` | Human-readable Markdown heading |
| `fetch_method` | Method name on `OmadaOpenApiClient` |
| `row_formatter` | Callable that converts raw data → list of display dicts |
| `sort_key` | Column name to sort rows by |
| `needs_context` | If `True`, the row formatter receives the full data set for cross-reference resolution |
| `detail_formatter` | Optional callable `(data, context) -> [(title, rows)]`; each pair becomes a `##` section below the summary table |

**Global objects:**

- `RESOURCES` — ordered list of all `ResourceDefinition` instances.
- `REGISTRY` — dict mapping resource name → definition for fast lookup.

**Row formatter helpers** handle enum-to-label conversion (codes as defined
in the Open API schemas), nested-data flattening, and ID-to-name resolution
using the other resources as context. Examples: networks, IP / port groups
(`_build_id_lookup()`); WAN port IDs (`_wan_port_names()`); RADIUS / rate
limit / schedule profiles (`_ssid_lookups()`); devices. Derived views are
computed here as well, such as per-port overrides
(`_port_overrides()` compares each port with its profile), switch
loop-prevention coverage, the uplink remapping checklist, the port-bound
rule references (`_port_rule_refs()`: DHCP snooping / ARP detection / OUI-VLAN /
QoS rules that name specific switch ports), the gateway port references
(`_gw_port_refs()`: every setting that names a gateway port ID), and the
replacement sheets (`switch_port_sheets`, `gateway_port_sheets`,
`ap_sheets`). The switch and gateway sheets are built entirely from other
resources, so they also regenerate from YAML. The AP sheet fetches its own
per-AP settings and takes radios and SSID overrides from other resources.

---

### Exporters — `omada/exporters/`

**`YamlExporter`** (`yaml_exporter.py`)

- `export(name, data)` — write a single resource to `{output_dir}/{name}.yaml`
  with sorted keys and Unicode support.
- `export_all(data)` — export every resource; return `{name: Path}` mapping.

**`MarkdownGenerator`** (`markdown_generator.py`)

- `generate(name, data, context)` — look up the resource in `REGISTRY`, call
  its row formatter, sort rows by `sort_key` (if set), render a
  GitHub-Flavoured Markdown table, and append one `##` section per
  `detail_formatter` item. If the data contains a plaintext credential
  (`contains_secrets()`), a warning banner is inserted below the title.
  Writes `{output_dir}/{name}.md`. Falls back to a generic table for
  unknown resources.
- `generate_all(data)` — generate Markdown for every resource.

Table rendering helpers: `_table()`, `_sanitize()` (escapes pipes, renders
booleans as ✓/✗), `_column_header()` (snake_case → Title Case).

---

### Web Application — `omada/web/app.py`

Flask application created via the `create_app()` factory.

| Route | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Configuration form + list of generated docs (every `*.md` under the output dir, as `Site/file.md`) |
| `/run` | POST | Fetch from controller & generate docs (mirrors CLI `fetch`) |
| `/regenerate` | POST | Regenerate Markdown from existing YAML (site from the last fetch or the form) |
| `/docs/<filename>` | GET | Render a Markdown file as HTML |
| `/download/<filename>` | GET | Download a single file |
| `/download` | POST | Download selected files (single or ZIP archive) |

**Security:**

- Per-session CSRF tokens on all POST routes.
- Path-traversal prevention on all file-serving routes.
- `FLASK_SECRET_KEY` env var for persistent sessions (ephemeral random key
  by default).
- Only non-secret form values are kept in the session. Passwords and secrets
  are blanked, and the Include secrets checkbox is never pre-checked.

---

### Credential Redaction — `omada/redaction.py`

`redact_secrets(data)` returns a copy of any resource with every non-empty
string value whose key looks like a credential (`password`, `pwd`, `secret`,
`token`, `securityKey`, `preSharedKey`, `privateKey`, …) replaced by
`<redacted>`. Booleans such as `hidePwd` and nested setting objects are left
intact, and the key is kept so exports show that a secret is configured.
`OmadaService.fetch_all()` applies it to every resource; the VPN and wireless
client getters also apply it at the source.

`OmadaService(include_secrets=True)` (CLI `--include-secrets`, env
`OMADA_INCLUDE_SECRETS`, web UI checkbox) disables both: it skips the
service-level pass and sets `client.include_secrets`, so the getters return
credentials unredacted. `contains_secrets(data)` lets `MarkdownGenerator`
insert a warning banner into any file whose data holds a plaintext
credential, which also covers Markdown regenerated from YAML.

---

### Logging — `omada/logging_config.py`

Logging uses Python's built-in `logging` module from the standard library
(no third-party logging packages). `setup_logging()` configures the root
logger with:

- A **console handler** (always, to `stderr`).
- An optional **`RotatingFileHandler`** (5 MB / 3 backups) when a log file
  path is provided.
- Graceful fallback to console-only if the file path is invalid.

Repeated calls are safe — existing handlers are removed first.

**Configuration:**

| Parameter | CLI flag | Environment variable | Default |
| --- | --- | --- | --- |
| Log level | `--log-level` / `-v` | `OMADA_LOG_LEVEL` | `INFO` |
| Log file | `--log-file` | `OMADA_LOG_FILE` | disabled |
| Log format | — | `OMADA_LOG_FORMAT` | `%(levelname)s %(message)s` |

The `-v` / `--verbose` flag is a shortcut for `--log-level DEBUG`.

**Levels used in the codebase:**

| Level | Usage |
| --- | --- |
| `DEBUG` | HTTP request/response details, pagination progress, endpoint fallback attempts |
| `INFO` | Resource counts, startup messages, progress during fetch |
| `WARNING` | Max pages reached (data may be truncated), file logging fallback, unavailable best-effort endpoints, plaintext secrets requested |
| `ERROR` | Per-resource fetch failures, authentication errors, summary of failed resources |

**File rotation:**

| Setting | Default |
| --- | --- |
| Max file size | 5 MB (`DEFAULT_MAX_BYTES`) |
| Backup count | 3 (`DEFAULT_BACKUP_COUNT`) |
| Encoding | UTF-8 |

When a log file path is provided, `_add_file_handler()` creates parent
directories automatically. If the file cannot be opened (e.g. permission
error, invalid path), a warning is logged to the console and the application
continues with console-only logging.

**Integration points:**

- **CLI** — `setup_logging()` is called in the top-level `cli()` group
  callback before any subcommand runs, using values from `--log-level`,
  `--log-file`, and `OMADA_LOG_FORMAT`.
- **Web UI** — `create_app()` calls `setup_logging()` when
  `configure_logging=True`, reading from the same environment variables.
- **All modules** — use `logging.getLogger(__name__)` which inherits from the
  root logger configured by `setup_logging()`.

---

## Workflows

### Fetch (CLI)

```text
python cli.py fetch --controller 192.168.1.1 --client-id … --client-secret …

1. Parse CLI arguments / environment variables
2. _build_client()
   ├─ discover_controller_id()          GET /api/info
   ├─ openapi_login()                   POST /openapi/authorize/token
   │   (or openapi_auth_code_login()    3-step flow when --username is set)
   └─ openapi_discover_site_id()        GET /openapi/v1/{id}/sites
3. OmadaService(client, site_id, output_dir, site_name, include_secrets)
4. service.run()
   ├─ fetch_all()                       call each resource's get_* (redacted)
   ├─ export_yaml(data)                 write docs/<site>/*.yaml
   └─ generate_docs(data)               write docs/<site>/*.md
5. Print summary
```

### Generate (CLI)

```text
python cli.py generate --input-dir docs --site-name "My Office"

1. Scan docs/My Office/ (or docs/ without --site-name) for *.yaml files
2. yaml.safe_load() each file
3. Pass full data set as context to MarkdownGenerator
4. Write docs/My Office/*.md
5. Print summary
```

### Fetch (Web UI)

```text
User submits form at GET /

POST /run
 ├─ Validate CSRF token
 ├─ Parse form fields
 ├─ _build_client()          (same as CLI)
 ├─ OmadaService.run()      (same as CLI)
 ├─ Flash success message
 └─ Redirect → GET /
```

### Regenerate (Web UI)

```text
POST /regenerate
 ├─ Validate CSRF token
 ├─ generate_from_yaml(output_dir, output_dir, site_name)
 ├─ Flash success message
 └─ Redirect → GET /
```

### View / Download (Web UI)

```text
GET /docs/My%20Office/acl_rules.md
 ├─ Validate path (no traversal)
 ├─ Read file, render Markdown → HTML
 └─ Render doc_view.html with sidebar navigation

GET  /download/My%20Office/acl_rules.md   → single-file attachment
POST /download                 → selected files (single or ZIP)
```

---

## Authentication

### Client Credentials Mode

```text
1. GET  /api/info                                        → omadacId
2. POST /openapi/authorize/token?grant_type=client_credentials
   Body: { omadacId, client_id, client_secret }          → accessToken
3. All subsequent requests: Authorization: AccessToken={token}
```

### Authorization Code Mode (3-step)

```text
1. POST /openapi/authorize/login
   Params: ?client_id={id}&omadacId={id}
   Body: { username, password }                          → csrfToken, sessionId

2. POST /openapi/authorize/code
   Params: ?client_id={id}&omadacId={id}&response_type=code
   Headers: Csrf-Token, Cookie: TPOMADA_SESSIONID=…     → auth code (plain string)

3. POST /openapi/authorize/token?grant_type=authorization_code&code={code}
   Body: { omadacId, client_id, client_secret }          → accessToken
```

When `--username` and `--password` are provided the application automatically
selects Authorization Code mode; otherwise it uses Client Credentials.

---

## Pagination

All paginated endpoints use `page` (1-indexed) and `pageSize` query
parameters. The `_get_paged()` method handles three response shapes
transparently:

| Shape | Example `result` field | Detection |
| --- | --- | --- |
| Direct list | `[{…}, {…}]` | `isinstance(result, list)` |
| Wrapped dict | `{"data": […], "totalRows": N}` | `result.get("data")` |
| Custom key | `{"items": [{…}]}` | Iterate dict, find first list-of-dicts value |

Pagination stops when `len(items) >= totalRows`, the page returns no data,
or `max_pages` (default 200) is reached.

---

## Error Handling & Resilience

**Per-resource isolation** — `OmadaService.fetch_all()` catches exceptions
per resource and records the failure. Remaining resources continue. A summary
of failures is logged at the end.

**Endpoint fallbacks** — several API client methods try a preferred endpoint
first and fall back to an alternative if it returns an error code (e.g.
`-1600 Unsupported`). Examples:

| Resource | Primary endpoint | Fallback |
| --- | --- | --- |
| Networks | `/lan-networks/all` | `/lan-networks` (paginated) |
| IP / Port Groups | `/profiles/groups/0` (`/1`) | `/profiles/groups` + filter by type |
| Gateway Settings | `/internet/ports-config` | `/internet/basic-info`, then `/setting/virtual-wans` |
| Switch Port Profiles | `/lan-profiles` (v1) | `/lan-profiles` (v2), then `/lan-switch-setting` |
| SSID detail | `/wireless-network/ssids/{id}` | `/wireless-network/wlans/{wlanId}/ssids/{id}` |
| Switch ports | `/switches/ports/overview` | `/switches/{mac}` `portList` |
| Uplinks | `/switches/ports/switch-detail` | `POST /switches/ports/select` |

**Sub-resource independence** — multi-endpoint resources treat secondary
parts as best-effort. For example, `get_acl_rules()` tries gateway, switch,
and EAP ACLs independently; `get_remote_access_vpns()` keeps servers if
clients fail; `_collect()`-based resources raise only when every part fails;
per-device lookups skip a failing device and continue. Whether a failure is
logged at `WARNING` or `DEBUG` depends on whether it's expected (e.g. L2
switches without static routing are `DEBUG`).

---

## Extensibility

Adding a new resource type requires code changes in only two files:

1. **`omada/api/openapi_client.py`** — add a `get_*()` method. Use the
   `_collect()` / enrichment patterns for multi-endpoint data, and
   `self._redact()` if the endpoint returns credentials (the service layer
   redacts again regardless).
2. **`omada/registry.py`** — add a row formatter, and optionally a detail
   formatter, plus a `ResourceDefinition` entry in `RESOURCES`. Set
   `needs_context=True` to resolve IDs from other resources.

No changes are needed in the CLI, web UI, service layer, exporters, or
`diagnose` — they discover resources dynamically from the registry.

To keep the suite and docs consistent, also: add the new fetcher's mock
return value to the client fixtures in `tests/test_service.py` and
`tests/test_openapi_client.py`; update the resource-count test in
`tests/test_registry.py`; add tests and rows in `TESTS.md`; and document
the endpoints in `api_reference.md` (the resource index there is grouped by
area).

---

## Testing

The suite (see [TESTS.md](TESTS.md)) runs fully offline. `tests/conftest.py`
blocks real network access with an autouse fixture, so any unmocked HTTP call
fails immediately. Client tests patch `_get` / `_get_paged` / `_post` with
path-based `side_effect` functions; formatter tests feed representative API
records straight to the row and detail formatters. End-to-end tests run
`OmadaService` on the real client methods to confirm that no secret value
reaches any written file, and that `include_secrets` behaves as documented.
