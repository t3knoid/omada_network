# Test Suite

This document lists all available tests in the `tests/` directory.

Run the full suite with:

```bash
python -m pytest tests/ -v
```

---

## Testing Libraries

| Library | Purpose |
| --- | --- |
| **pytest** | Test framework and runner. Provides test discovery, fixtures, assertions, and plugins. |
| **unittest.mock** | Mocking library from the Python standard library. Used to isolate units under test from external dependencies. |
| **click.testing** | Test utilities for Click CLI applications. Provides `CliRunner` for invoking CLI commands in-process. |
| **PyYAML** | YAML serialisation library. Used in tests to create YAML fixture files for the `generate` command and exporter tests. |
| **requests** | HTTP library (mocked, not called). Test doubles are built with `MagicMock(spec=requests.Response)` to simulate API responses. |

### Library Usage Details

**pytest**

- `@pytest.fixture()` — Defines reusable test setup (e.g. `runner`, `app_client`, `mock_client`, `service`). The built-in `tmp_path` fixture provides isolated temporary directories, and `monkeypatch` is used to set/unset environment variables.
- `@pytest.mark.parametrize` — Drives data-driven tests, such as validating truthy/falsy environment variable strings and invalid port values.
- `pytest.raises` — Asserts that specific exceptions are raised (e.g. `OmadaAPIError`, `RuntimeError`, `click.UsageError`).
- `autouse=True` fixtures — Automatically reset shared state (e.g. the root logger) before each test in `test_logging_config.py`.

**unittest.mock**

- `MagicMock` — Creates mock objects for the API client, service layer, HTTP sessions, and responses. `spec=` is used to constrain mocks to real interfaces (e.g. `requests.Response`, `requests.Session`).
- `patch` — Context manager that temporarily replaces module-level objects (e.g. `openapi_login`, `OmadaService`, `Flask.run`) with mocks so tests run without network access or a live controller.
- `patch.object` — Patches individual methods on an existing instance (e.g. `openapi_client._session.get`) for fine-grained request simulation.
- `side_effect` — Configures mocks to return different values on successive calls or raise exceptions, enabling multi-page pagination tests and fallback-path coverage.

**click.testing**

- `CliRunner` — Invokes the Click CLI group (`cli`) with argument lists and optional environment variable overrides. Captures exit codes and stdout/stderr for assertion without spawning a subprocess.

**PyYAML (`yaml`)**

- `yaml.dump` — Serialises Python dicts/lists into YAML strings that are written to `tmp_path` files, simulating the output of a prior `fetch` run so `generate` and exporter tests have realistic input.
- `yaml.safe_load` — Reads YAML files back to verify round-trip correctness in `YamlExporter` tests (e.g. key ordering, Unicode preservation).

**requests (mocked)**

- `MagicMock(spec=requests.Response)` — Provides `.status_code`, `.json()`, and `.raise_for_status()` so the Open API client code exercises its real response-handling logic against controlled data.
- `MagicMock(spec=requests.Session)` — Stubs `.get()` and `.post()` with predetermined responses, allowing authentication, pagination, and error-path tests to run entirely offline.

---

## test_cli.py

CLI interface tests.

| Class | Test | Description |
| --- | --- | --- |
| `TestFetchCommand` | `test_missing_required_options` | Exits non-zero when required options are omitted |
| | `test_fetch_client_credentials` | Client Credentials mode with `--client-id` + `--client-secret` |
| | `test_fetch_auth_code_mode` | Authorization Code mode with `--username` + `--password` |
| | `test_fetch_reads_env_vars` | Reads configuration from `OMADA_*` environment variables |
| | `test_explicit_controller_id_skips_discovery` | `--controller-id` bypasses auto-discovery |
| | `test_missing_client_credentials_shows_error` | Shows error when client credentials are missing |
| `TestEnvBool` | `test_truthy_values` | Recognises truthy strings (`1`, `true`, `yes`, `on`, …) |
| | `test_falsy_values` | Recognises falsy strings (`0`, `false`, `no`, `off`, …) |
| | `test_unset_is_false` | Unset variable returns `False` |
| `TestGenerateCommand` | `test_generate_from_yaml_files` | Generates Markdown from YAML source files |
| | `test_generate_separate_output_dir` | Writes Markdown to a different output directory |
| | `test_generate_empty_dir_exits_nonzero` | Exits non-zero when no YAML files are found |
| | `test_generate_reads_env_var` | Reads `OMADA_OUTPUT_DIR` from environment |
| `TestServeCommand` | `test_serve_starts_flask` | Starts the Flask development server |
| `TestPasswordPromptBehaviour` | `test_client_credentials_no_password_prompt` | Client Credentials mode does not prompt for a password |
| | `test_password_prompt_when_username_provided_tty` | Prompts for password interactively when `--username` is set |
| | `test_non_tty_raises_usage_error` | Raises `UsageError` on non-TTY stdin instead of aborting |
| | `test_password_via_env_var` | Uses `OMADA_PASSWORD` env var without prompting |

---

## test_exporters.py

YAML exporter and Markdown generator tests.

| Class | Test | Description |
| --- | --- | --- |
| `TestYamlExporter` | `test_exports_list` | Exports a list to YAML |
| | `test_exports_dict` | Exports a dict to YAML |
| | `test_sort_keys_true` | YAML keys are sorted alphabetically |
| | `test_creates_output_dir` | Creates nested output directories automatically |
| | `test_export_all` | Exports multiple resources at once |
| | `test_unicode_content` | Handles Unicode content correctly |
| `TestMarkdownHelpers` | `test_column_header_converts_snake_case` | Converts `snake_case` keys to Title Case |
| | `test_table_empty` | Renders "No records found" for empty data |
| | `test_table_single_row` | Renders a single-row Markdown table |
| | `test_table_pipe_escaping` | Escapes pipe characters in cell values |
| | `test_table_bool_rendering` | Renders booleans as ✓ / ✗ |
| `TestMarkdownGenerator` | `test_generate_acl_rules` | Generates ACL Rules Markdown |
| | `test_generate_ip_groups` | Generates IP Groups Markdown |
| | `test_generate_networks` | Generates Networks Markdown |
| | `test_generate_vlans` | Generates VLANs Markdown |
| | `test_generate_ssids` | Generates SSIDs Markdown |
| | `test_generate_dhcp_reservations` | Generates DHCP Reservations Markdown |
| | `test_generate_gateway_settings` | Generates Gateway Settings Markdown |
| | `test_generate_all` | Generates all resource types at once |
| | `test_unknown_resource_fallback` | Falls back to generic table for unknown resources |
| | `test_rows_sorted_by_name` | Rows are sorted alphabetically by sort key |
| | `test_ssids_sorted_by_ssid_column` | SSIDs are sorted by SSID name |

---

## test_logging_config.py

Centralized logging configuration tests.

| Class | Test | Description |
| --- | --- | --- |
| `TestSetupLoggingConsoleOnly` | `test_default_level_is_info` | Default log level is `INFO` |
| | `test_console_handler_attached` | A `StreamHandler` is attached to the root logger |
| | `test_no_file_handler_by_default` | No `FileHandler` when log file is not specified |
| | `test_custom_level` | Accepts a custom log level (`DEBUG`) |
| | `test_custom_format` | Accepts a custom log format string |
| | `test_invalid_level_falls_back_to_info` | Invalid level string falls back to `INFO` |
| | `test_no_duplicate_handlers_on_repeat_calls` | Repeated calls don't duplicate handlers |
| `TestSetupLoggingWithFile` | `test_file_handler_created` | Creates a `FileHandler` when log file is set |
| | `test_log_file_written` | Log messages are written to the file |
| | `test_log_directory_created` | Creates parent directories for the log file |
| | `test_both_console_and_file_handlers` | Both console and file handlers are active |
| | `test_invalid_path_falls_back_to_console` | Falls back to console-only on invalid file path |
| `TestSetupLoggingRotation` | `test_rotation_params` | Rotation parameters are forwarded to `RotatingFileHandler` |
| `TestSetupLoggingEnvVarsViaCli` | `test_cli_reads_env_log_level` | Respects log level passed from CLI |
| | `test_cli_reads_env_log_file` | Creates file handler from CLI log file argument |
| | `test_cli_reads_env_log_format` | Respects log format from CLI |
| | `test_lowercase_level_is_normalized` | Normalises lowercase level strings |
| `TestDefaults` | `test_default_format` | Default format is `%(levelname)s %(message)s` |
| | `test_default_log_file_path` | Default log file path contains `omada_network.log` |
| | `test_default_max_bytes` | Default max bytes is 5 MB |
| | `test_default_backup_count` | Default backup count is 3 |

---

## test_openapi_client.py

Omada Open API client tests.

| Class | Test | Description |
| --- | --- | --- |
| `TestOpenApiLogin` | `test_successful_login` | Successful Client Credentials login returns token |
| | `test_login_error_code` | Raises `OmadaAPIError` on invalid credentials |
| | `test_login_missing_access_token` | Raises `RuntimeError` when access token is missing |
| `TestOpenApiAuthCodeLogin` | `test_successful_auth_code_login` | Three-step Authorization Code flow succeeds |
| | `test_auth_code_login_step1_error` | Raises error when step 1 (login) fails |
| `TestDiscoverControllerId` | `test_successful_discovery` | Discovers controller ID from `/api/info` |
| | `test_discovery_error_code` | Raises `OmadaAPIError` on discovery failure |
| | `test_discovery_missing_omadac_id` | Raises `RuntimeError` when `omadacId` is missing |
| `TestOpenApiDiscoverSite` | `test_single_site_auto_select` | Auto-selects the only available site |
| | `test_select_by_name` | Selects a site by display name |
| | `test_name_not_found` | Raises error when site name doesn't match |
| | `test_multiple_sites_no_name` | Raises error when multiple sites exist and no name given |
| | `test_no_sites` | Raises error when no sites are found |
| | `test_result_as_list` | Handles result returned as a list instead of `{data: [...]}` |
| `TestOpenApiClientUrl` | `test_api_url_v1` | Builds correct v1 API URL |
| | `test_api_url_v2` | Builds correct v2 API URL |
| | `test_api_url_strips_leading_slash` | Strips leading slash from path |
| `TestOpenApiClientGet` | `test_get_success` | Successful GET returns result |
| | `test_get_raises_on_error` | Raises `OmadaAPIError` on error response |
| | `test_get_paged_single_page` | Paged GET retrieves a single page |
| | `test_get_paged_multiple_pages` | Paged GET retrieves multiple pages |
| | `test_get_paged_result_is_list` | Handles result returned as a plain list |
| | `test_get_paged_stops_at_max_pages` | Stops pagination at `max_pages` limit |
| `TestOpenApiResourceMethods` | `test_get_acl_rules` | Fetches and tags gateway/switch ACL rules |
| | `test_get_acl_rules_gateway_fails` | Falls back when gateway ACL endpoint is unsupported |
| | `test_get_ip_groups` | Fetches IP groups |
| | `test_get_ip_groups_fallback` | Falls back to filtering from all groups |
| | `test_get_port_groups` | Fetches port groups |
| | `test_get_port_groups_fallback` | Falls back to filtering from all groups |
| | `test_get_networks` | Fetches networks |
| | `test_get_networks_fallback_to_paged` | Falls back to paged endpoint |
| | `test_get_vlans_filters_by_vlanid` | Filters networks by `vlanId` |
| | `test_get_switch_port_profiles` | Fetches switch port profiles |
| | `test_get_switch_port_profiles_all_fail` | Returns empty list when all endpoints fail |
| | `test_get_gateway_settings` | Fetches gateway settings |
| | `test_get_gateway_settings_fallback` | Falls back to alternative endpoints |
| | `test_get_gateway_settings_all_fail` | Returns empty dict when all endpoints fail |
| | `test_get_ssids` | Fetches SSIDs with WLAN group names |
| | `test_get_ssids_no_wlans` | Returns empty list when WLAN endpoint fails |
| | `test_get_dhcp_reservations` | Fetches DHCP reservations |
| `TestServiceWithOpenApiClient` | `test_service_accepts_injected_client` | Service uses injected client |
| | `test_service_fetch_all_uses_injected_client` | `fetch_all` calls injected client methods |

---

## test_registry.py

Resource registry and `generate_from_yaml` tests.

| Class | Test | Description |
| --- | --- | --- |
| `TestRegistry` | `test_all_nine_resources_defined` | All 9 resource types are registered |
| | `test_registry_lookup_matches_resources` | Registry lookup matches `RESOURCES` list |
| | `test_all_definitions_are_resource_definition` | All entries are `ResourceDefinition` instances |
| | `test_all_row_formatters_callable` | All row formatters are callable |
| | `test_row_formatters_return_list_for_empty_input` | Formatters return a list for empty input |
| | `test_row_formatters_return_list_for_dict_input` | Formatters handle dict input gracefully |
| | `test_sort_key_is_string` | Sort key is always a string |
| `TestRowFormatters` | `test_acl_rule_rows` | Formats ACL rule rows with policy/status labels |
| | `test_acl_rule_rows_resolves_names` | Resolves IP group, port group, and network names |
| | `test_acl_rule_rows_no_context_shows_raw_ids` | Shows raw IDs when no context is available |
| | `test_ip_group_rows` | Formats IP group rows with CIDR notation |
| | `test_gateway_rows_dict_input` | Formats gateway rows from dict input |
| | `test_gateway_rows_list_input` | Formats gateway rows from list input |
| | `test_ssid_rows` | Formats SSID rows with band and security labels |
| | `test_dhcp_reservation_rows` | Formats DHCP reservation rows |
| | `test_switch_port_profile_rows` | Formats switch port profile rows |
| | `test_switch_port_profile_rows_resolves_tagged_networks` | Resolves tagged network IDs to names |
| | `test_switch_port_profile_rows_no_context_shows_raw_ids` | Shows raw IDs without context |
| `TestGenerateFromYaml` | `test_generates_markdown_from_yaml_files` | Generates Markdown from YAML files |
| | `test_separate_input_output_dirs` | Supports separate input/output directories |
| | `test_empty_dir_returns_empty_dict` | Returns empty dict for empty directory |
| | `test_empty_yaml_file_handled` | Handles empty YAML files gracefully |
| | `test_creates_output_dir_if_missing` | Creates output directory if it doesn't exist |

---

## test_service.py

`OmadaService` service layer tests.

| Class | Test | Description |
| --- | --- | --- |
| `TestOmadaServiceFetchAll` | `test_fetch_all_returns_all_keys` | Returns all resource keys |
| | `test_fetch_all_handles_partial_failures` | Continues when individual fetchers fail |
| | `test_fetch_all_logs_error_summary_on_failures` | Logs an error summary for failed fetches |
| `TestOmadaServiceExport` | `test_export_yaml_writes_files` | Writes YAML files for all resources |
| | `test_generate_docs_writes_files` | Writes Markdown files for all resources |
| `TestOmadaServiceRun` | `test_run_creates_output_dir` | Creates the output directory if missing |
| | `test_run_returns_yaml_and_doc_paths` | Returns paths for both YAML and Markdown files |

---

## test_web.py

Flask web application tests.

| Class | Test | Description |
| --- | --- | --- |
| `TestIndexRoute` | `test_index_returns_200` | Index page returns HTTP 200 |
| | `test_index_contains_form` | Index page contains the configuration form |
| | `test_index_contains_csrf_token_field` | Form includes a CSRF token field |
| | `test_index_contains_auth_mode_tabs` | Form shows both authentication mode tabs |
| `TestRunRoute` | `test_run_missing_client_creds_flashes_error` | Flashes error when client credentials are missing |
| | `test_run_client_credentials_success` | Client Credentials mode succeeds end-to-end |
| | `test_run_auth_code_success` | Authorization Code mode succeeds end-to-end |
| | `test_run_auth_code_missing_username_flashes_error` | Flashes error when username is missing in auth code mode |
| | `test_run_service_error_flashes_error` | Flashes error when service raises an exception |
| | `test_run_csrf_enforced_outside_testing` | CSRF protection is enforced outside test mode |
| | `test_run_invalid_port_flashes_error` | Flashes error for invalid port values |
| `TestRegenerateRoute` | `test_regenerate_no_yaml_files_flashes_warning` | Warns when no YAML files are found |
| | `test_regenerate_with_yaml_files` | Regenerates Markdown from existing YAML |
| | `test_regenerate_missing_output_dir_flashes_warning` | Warns when output directory doesn't exist |
| | `test_regenerate_csrf_enforced_outside_testing` | CSRF protection is enforced outside test mode |
| `TestDocViewPathTraversal` | `test_path_traversal_is_blocked` | Blocks path traversal attempts |
| | `test_view_existing_doc` | Renders an existing Markdown document |
| | `test_view_missing_doc_redirects` | Redirects with warning for missing documents |
| `TestDownloadDoc` | `test_download_single_file` | Downloads a single file as attachment |
| | `test_download_missing_file_redirects` | Redirects with warning for missing files |
| | `test_download_path_traversal_blocked` | Blocks path traversal in download routes |
| `TestDownloadSelected` | `test_no_files_selected_flashes_warning` | Warns when no files are selected |
| | `test_download_single_selected_file` | Downloads a single selected file |
| | `test_download_multiple_files_as_zip` | Downloads multiple files as a ZIP archive |
| | `test_download_selected_path_traversal_blocked` | Blocks path traversal in selected downloads |
| | `test_download_selected_missing_file_redirects` | Redirects for missing selected files |
| | `test_download_csrf_enforced_outside_testing` | CSRF protection is enforced outside test mode |
