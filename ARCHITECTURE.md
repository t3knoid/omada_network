# Architecture

## Overview

The application connects to TP-Link Omada controllers via the official
**Omada Open API (Northbound API)** to extract network configuration data,
persist it as YAML (source of truth), and generate Markdown documentation
tables.

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
          │  - HTTP GET │  │  - Row   │
          │  - Paging   │  │  fmts    │
          └─────────────┘  └──────────┘

                 ┌─────────────────────────┐
                 │   Logging Config        │
                 │  (logging_config.py)    │
                 │  setup_logging()        │
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
  discover the site ID; returns an `(api_client, site_id)` tuple used by
  both `fetch` and the web UI.

All CLI options have corresponding `OMADA_*` environment variables for
headless / CI usage.

---

### Service Layer — `omada/service.py`

High-level orchestration that both the CLI and web UI delegate to.

**`OmadaService`** — constructed with an authenticated API client, a site ID,
and an output directory.

| Method | Description |
| --- | --- |
| `fetch_all()` | Iterate over every `ResourceDefinition` in the registry and call its fetch method on the API client. Failures are caught per-resource so remaining resources continue. |
| `export_yaml(data)` | Delegate to `YamlExporter.export_all()` |
| `generate_docs(data)` | Delegate to `MarkdownGenerator.generate_all()` |
| `run()` | Orchestrate the full pipeline: create output dir → `fetch_all` → `export_yaml` → `generate_docs` → return paths |

**`generate_from_yaml(input_dir, output_dir)`** — standalone function that
loads `*.yaml` files from disk, passes the full data set as cross-reference
context, and writes Markdown. No API interaction.

---

### API Client — `omada/api/openapi_client.py`

HTTP client for the Omada Open API supporting both official OAuth 2 modes.

**Authentication & discovery functions:**

| Function | Purpose |
| --- | --- |
| `discover_controller_id()` | `GET /api/info` (unauthenticated) → extract `omadacId` |
| `openapi_login()` | Client Credentials grant → access token |
| `openapi_auth_code_login()` | Three-step Authorization Code flow → access token |
| `openapi_discover_site_id()` | List sites and resolve by name (case-insensitive) |

**`OmadaOpenApiClient`** — authenticated client for data retrieval.

| Internal method | Description |
| --- | --- |
| `_api_url(path, api_version)` | Build full URL from relative path + `omadacId` |
| `_get(path)` | Single GET request; check `errorCode`; return `result` |
| `_get_paged(path, page_size, max_pages)` | Paginated GET; auto-detect response shape; aggregate pages |

Public `get_*` methods (one per resource) call `_get` or `_get_paged` and
apply endpoint-specific fallback logic when an endpoint returns an error
(e.g. trying `/lan-networks/all` first, then falling back to paginated
`/lan-networks`).

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
| `needs_context` | If `True`, the formatter receives the full data set for cross-reference resolution |

**Global objects:**

- `RESOURCES` — ordered list of all `ResourceDefinition` instances.
- `REGISTRY` — dict mapping resource name → definition for fast lookup.

**Row formatter helpers** handle enum-to-label conversion (policy, band,
security mode, protocol), nested-data flattening, and ID-to-name resolution
via a context lookup built by `_build_id_lookup()`.

---

### Exporters — `omada/exporters/`

**`YamlExporter`** (`yaml_exporter.py`)

- `export(name, data)` — write a single resource to `{output_dir}/{name}.yaml`
  with sorted keys and Unicode support.
- `export_all(data)` — export every resource; return `{name: Path}` mapping.

**`MarkdownGenerator`** (`markdown_generator.py`)

- `generate(name, data, context)` — look up the resource in `REGISTRY`, call
  its row formatter, sort rows, render a GitHub-Flavoured Markdown table,
  and write to `{output_dir}/{name}.md`. Falls back to a generic table for
  unknown resources.
- `generate_all(data)` — generate Markdown for every resource.

Table rendering helpers: `_table()`, `_sanitize()` (escapes pipes, renders
booleans as ✓/✗), `_column_header()` (snake_case → Title Case).

---

### Web Application — `omada/web/app.py`

Flask application created via the `create_app()` factory.

| Route | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Configuration form + list of generated docs |
| `/run` | POST | Fetch from controller & generate docs (mirrors CLI `fetch`) |
| `/regenerate` | POST | Regenerate Markdown from existing YAML |
| `/docs/<filename>` | GET | Render a Markdown file as HTML |
| `/download/<filename>` | GET | Download a single file |
| `/download` | POST | Download selected files (single or ZIP archive) |

**Security:**

- Per-session CSRF tokens on all POST routes.
- Path-traversal prevention on all file-serving routes.
- `FLASK_SECRET_KEY` env var for persistent sessions (ephemeral random key
  by default).

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
| `WARNING` | Max pages reached (data may be truncated), file logging fallback |
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
3. OmadaService(client, site_id, output_dir)
4. service.run()
   ├─ fetch_all()                       GET each resource endpoint (paginated)
   ├─ export_yaml(data)                 write docs/*.yaml
   └─ generate_docs(data)              write docs/*.md
5. Print summary
```

### Generate (CLI)

```text
python cli.py generate --input-dir docs

1. Scan docs/ for *.yaml files
2. yaml.safe_load() each file
3. Pass full data set as context to MarkdownGenerator
4. Write docs/*.md
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
 ├─ generate_from_yaml(output_dir, output_dir)
 ├─ Flash success message
 └─ Redirect → GET /
```

### View / Download (Web UI)

```text
GET /docs/acl_rules.md
 ├─ Validate path (no traversal)
 ├─ Read file, render Markdown → HTML
 └─ Render doc_view.html with sidebar navigation

GET  /download/acl_rules.md   → single-file attachment
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
| IP Groups | `/profiles/groups?type=0` | `/profiles/groups` + filter |
| Gateway Settings | `/gateway/ports-config` | `/gateway/basic-info` |
| Switch Port Profiles | `/lan-profiles` | `/setting/lan/profilelist` |

**Sub-resource independence** — `get_acl_rules()` independently tries
gateway, switch, and EAP ACL endpoints. If one fails the others still
contribute their data.

---

## Extensibility

Adding a new resource type requires changes in only two files:

1. **`omada/registry.py`** — add a row-formatter function and a
   `ResourceDefinition` entry to the `RESOURCES` list.
2. **`omada/api/openapi_client.py`** — add a `get_*()` method.

No changes are needed in the CLI, web UI, service layer, or exporters — they
discover resources dynamically from the registry.
