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
- `conftest.py` — an autouse fixture blocks real network access for every test, so an unstubbed HTTP call fails immediately instead of waiting for a timeout.

**unittest.mock**

- `MagicMock` — Creates mock objects for the API client, service layer, HTTP sessions, and responses. `spec=` is used to constrain mocks to real interfaces (e.g. `requests.Response`, `requests.Session`).
- `patch` — Context manager that temporarily replaces module-level objects (e.g. `openapi_login`, `OmadaService`, `Flask.run`) with mocks so tests run without network access or a live controller.
- `patch.object` — Patches individual methods on an existing instance (e.g. `openapi_client._session.get`, `_get`, `_get_paged`, `_post`) for fine-grained request simulation. Multi-endpoint resources are usually tested with a `side_effect` that maps each request path to its response.
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

## conftest.py

An autouse fixture, `_block_real_network`, makes any unstubbed HTTP request
raise `requests.ConnectionError` immediately, so a test that forgets to mock
an endpoint fails fast instead of waiting for a network timeout.

---

## test_cli.py

CLI interface tests.

| Class | Test | Description |
| --- | --- | --- |
| `TestFetchCommand` | `test_missing_required_options` | Exits non-zero when required options are omitted |
| | `test_fetch_client_credentials` | Client Credentials mode with `--client-id` + `--client-secret` |
| | `test_fetch_auth_code_mode` | Authorization Code mode with `--username` + `--password` |
| | `test_fetch_reads_env_vars` | Reads configuration from `OMADA_*` environment variables |
| | `test_fetch_include_secrets_option` | `--include-secrets` / `OMADA_INCLUDE_SECRETS` reach the service and print a warning; off by default |
| | `test_explicit_controller_id_skips_discovery` | `--controller-id` bypasses auto-discovery |
| | `test_missing_client_credentials_shows_error` | Shows error when client credentials are missing |
| `TestEnvBool` | `test_truthy_values` | Recognises truthy strings (`1`, `true`, `yes`, `on`, …) |
| | `test_falsy_values` | Recognises falsy strings (`0`, `false`, `no`, `off`, …) |
| | `test_unset_is_false` | Unset variable returns `False` |
| `TestGenerateCommand` | `test_generate_from_yaml_files` | Generates Markdown from YAML source files |
| | `test_generate_separate_output_dir` | Writes Markdown to a different output directory |
| | `test_generate_empty_dir_exits_nonzero` | Exits non-zero when no YAML files are found |
| | `test_generate_reads_env_var` | Reads `OMADA_OUTPUT_DIR` from environment |
| | `test_generate_site_specific_directory` | `--site-name` reads YAML from and writes Markdown to the site subdirectory |
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
| | `test_generate_switch_port_profiles_has_detail_sections` | Port profiles get a summary table plus one sorted detail section per profile |

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
| | `test_site_discovery_returns_id_and_name` | `openapi_discover_site` returns both the site ID and its display name |
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
| | `test_get_switch_port_sheets_lists_switches` | Lists the switches that get a port sheet |
| | `test_get_gateway_port_sheets_lists_gateways` | Lists the gateways that get a port sheet |
| | `test_get_ap_sheets_collects_parts_and_drops_counters` | Per-AP parts are best-effort, live counters are dropped, credentials are redacted |
| | `test_get_switch_security_collects_parts` | Collects 802.1X, MAC auth, DHCP snooping, ARP detection, IP-MAC binding (best-effort) |
| | `test_get_oui_vlans_qos_and_port_labels` | Fetches OUI VLAN rules / profiles, switch QoS, and port labels |
| | `test_get_uplinks_switch_detail_fallback_and_stacks` | Uplinks/downlinks from switch-detail, port-select fallback, stack members |
| | `test_get_uplinks_no_switches` | No switch lookups when the site has no switches |
| | `test_post_returns_result_and_raises_on_error` | Read-only POST helper returns `result` and raises on API errors |
| | `test_get_device_ports_merges_full_config_and_schedules` | Merges full per-port config from `switches/ports/select` and PoE / port schedule membership |
| | `test_get_device_ports_without_full_config` | Falls back to overview data when the full config is unavailable |
| | `test_get_lags_uses_full_lag_config` | LAG name, profile, mode, and members filled from the full LAG config |
| | `test_get_port_schedules` | Fetches PoE and port schedules best-effort |
| | `test_get_switch_settings` | Collects site jumbo/LLDP and per-switch general config, VLAN interfaces, RPVST (best-effort; GPS dropped) |
| | `test_get_lags_rebuilds_groups_from_port_overview` | Rebuilds LAG groups per switch from member `lagSetting`, taking the union of member lists |
| | `test_get_lags_fallback_and_stacks` | Falls back to `lagPort` flags when the overview is unavailable; adds stack LAGs |
| | `test_get_wan_failover_collects_config_and_health` | Combines load-balance, basic-info, and per-gateway WAN health |
| | `test_collect_tolerates_partial_and_raises_on_total_failure` | Multi-endpoint resources tolerate partial failure; DDNS password redacted |
| | `test_get_time_settings_uses_site_info_without_trailing_slash` | Reads time zone / NTP from site info, keeping only time-related fields |
| | `test_get_multicast_services_unwraps_bonjour` | Collects multicast/Bonjour/UPnP settings and unwraps the Bonjour list |
| | `test_get_ssids_merges_detail_and_overrides_and_redacts` | Merges SSID detail and AP overrides; redacts passphrase and override password |
| | `test_get_ssids_detail_falls_back_to_wlan_path` | Falls back to the WLAN-scoped SSID detail endpoint |
| | `test_get_radius_profiles_redacts_all_secrets` | Redacts RADIUS auth, accounting, CoA, and built-in secrets |
| | `test_get_portals_merges_detail_and_redacts` | Merges portal detail; redacts portal password, OAuth secret, and SMS token |
| | `test_get_time_range_and_rate_limit_profiles` | Fetches schedule and rate limit profiles |
| | `test_get_wireless_settings_partial_and_total_failure` | One failing site setting is tolerated; all failing raises |
| | `test_get_ap_radios` | Fetches radio config for APs only, skipping unavailable ones |
| | `test_get_dhcp_reservations` | Fetches DHCP reservations |
| | `test_get_port_forwarding` | Fetches port forwarding rules |
| | `test_get_one_to_one_nat` | Fetches One-to-One NAT rules |
| | `test_get_alg_settings` | Fetches ALG settings |
| | `test_get_alg_settings_non_dict_result` | Returns `{}` when ALG result is not an object |
| | `test_get_static_routes_gateway_and_switch` | Combines gateway and switch static routes, resolving interface names |
| | `test_get_static_routes_tolerates_failures` | Missing gateway/switch routing support does not fail the export |
| | `test_get_policy_routes` | Fetches policy routing rules |
| | `test_get_site_to_site_vpns_redacts_psk` | Fetches site-to-site VPNs with the pre-shared key redacted |
| | `test_get_remote_access_vpns_tags_roles_and_redacts` | Combines VPN servers and clients, tagging roles and redacting secrets |
| | `test_get_remote_access_vpns_partial_and_total_failure` | One failing endpoint is tolerated; both failing raises |
| | `test_get_wireguard_nests_peers_and_redacts` | Nests peers under interfaces and redacts private/preshared keys |
| | `test_get_vpn_users_redacts_passwords` | Fetches VPN users with passwords redacted |
| | `test_get_ssl_vpn_collects_lists_and_redacts` | Gathers SSL VPN setting and lists, tolerating a failing list and redacting passwords |
| | `test_get_ssl_vpn_setting_failure_propagates` | A failing SSL VPN setting call is reported as a fetch failure |
| | `test_get_eogre_tunnel` | Fetches EoGRE tunnel settings |
| | `test_get_ipsec_failover` | Fetches IPsec failover groups |
| | `test_get_dhcp_scopes_extracts_dhcp_fields_and_pool_status` | Extracts DHCP fields per network and adds pool usage for serving networks |
| | `test_get_dhcp_scopes_tolerates_pool_status_failure` | Pool-usage lookup failure does not fail the export |
| | `test_get_dhcp_leases` | Fetches DHCP leases across all servers |
| | `test_get_devices` | Fetches the site device list |
| | `test_get_device_ports_switch_uses_overview` | Switch ports come from the site-wide port overview, sorted, tagged with device name / MAC / type / model |
| | `test_get_device_ports_switch_falls_back_when_overview_fails` | Falls back to the per-switch `portList` when the overview is unavailable |
| | `test_get_device_ports_gateway_merges_sources` | Gateway ports merge `portConfigs`, `osgPortInfos`, and WAN status (`portStatus`) by port number |
| | `test_get_device_ports_gateway_partial_failure` | Gateway ports still export when some gateway endpoints fail |
| | `test_get_device_ports_gateway_all_sources_fail` | Gateway with every port endpoint failing is skipped with a warning |
| | `test_get_device_ports_skips_aps_and_missing_mac` | Access points and devices without a MAC are skipped |
| | `test_get_device_ports_skips_overview_without_switches` | No port-overview call when the site has no switches |
| | `test_get_device_ports_continues_when_device_fails` | A failing switch is logged and the remaining devices still export |
| `TestServiceWithOpenApiClient` | `test_service_accepts_injected_client` | Service uses injected client |
| | `test_service_fetch_all_uses_injected_client` | `fetch_all` calls injected client methods |

---

## test_registry.py

Resource registry and `generate_from_yaml` tests.

| Class | Test | Description |
| --- | --- | --- |
| `TestRegistry` | `test_all_forty_six_resources_defined` | All 46 resource types are registered |
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
| | `test_ssid_rows` | Formats SSID rows with band and security labels (security 3 = WPA-Personal) |
| | `test_ssid_rows_resolve_profiles` | SSID security version, VLAN, portal, rate limit, schedule, and band steering resolved by name |
| | `test_ssid_details_and_ap_overrides` | Full per-SSID settings plus a per-AP override table |
| | `test_radius_profile_rows` | External and built-in RADIUS profiles, showing only secret state |
| | `test_portal_rows_and_details` | Portal auth, SSIDs, timeout, landing page, and per-method details |
| | `test_time_range_rows` | Schedule day modes and time slots |
| | `test_rate_limit_profile_rows` | Rate limit profile download / upload limits |
| | `test_wireless_settings_rows` | Site band steering, roaming, mesh, and multicast rate limit |
| | `test_ap_radio_rows` | Per-AP radio channel, width, Tx power, and wireless mode |
| | `test_dhcp_reservation_rows` | Formats DHCP reservation rows |
| | `test_port_forwarding_rows` | Formats port forwarding rows, resolving WAN port IDs to names |
| | `test_one_to_one_nat_rows` | Formats One-to-One NAT rows |
| | `test_alg_rows` | Formats ALG settings as Setting / Value rows |
| | `test_alg_rows_sip_disabled_hides_sip_options` | SIP sub-options are omitted when SIP ALG is off |
| | `test_static_route_rows` | Formats gateway (next hop / interface) and switch static routes |
| | `test_static_route_rows_prefers_fetched_interface_name` | Uses the interface name fetched from the API |
| | `test_policy_route_rows` | Formats policy routes in index order with resolved sources, destinations, and WAN binding |
| | `test_site_to_site_vpn_rows_and_details` | Site-to-site VPN summary and phase 1/2 + authentication details |
| | `test_remote_access_vpn_rows` | L2TP/PPTP/IPsec/OpenVPN server and client rows, including user references |
| | `test_remote_access_vpn_details_title_includes_role` | Detail sections are titled with the tunnel role |
| | `test_wireguard_rows_and_peer_details` | WireGuard interface rows and per-interface peer tables |
| | `test_vpn_user_rows` | Formats VPN user rows without exposing passwords |
| | `test_ssl_vpn_rows` | SSL VPN server settings, including RADIUS, lockout, and idle logout |
| | `test_ssl_vpn_details` | SSL VPN user group, user, resource, and resource group sections |
| | `test_eogre_rows` | EoGRE tunnel settings as Setting / Value rows |
| | `test_ipsec_failover_rows` | IPsec failover primary, ordered candidates, and failback |
| | `test_dhcp_scope_rows` | DHCP scope summary for gateway, switch relay, disabled, external, and legacy networks |
| | `test_dhcp_scope_details_gateway_options_and_guard` | Gateway scope pools, DNS/domain, options 3/60/66/138/next-server, custom options, and guard |
| | `test_dhcp_scope_details_switch_server_uses_switch_option_types` | Switch DHCP server scope with switch option-type codes |
| | `test_dhcp_scope_details_switch_relay` | Switch DHCP relay interface and target servers |
| | `test_dhcp_lease_rows_sorted_by_network_then_ip` | DHCP leases sorted by network and numeric IP |
| | `test_dhcp_reservation_rows_sorted_with_description_and_options` | Reservations sorted by network and IP, with description and options |
| | `test_wan_failover_rows` | Health-check interval, link backup (primary/backup WAN, trigger, mode), and per-WAN weights |
| | `test_wan_failover_health_snapshot` | WAN health snapshot (link, internet, latency, loss), skipping LAN-mode ports |
| | `test_dns_settings_rows_per_proxy_type` | DNS proxy as DoH, DoT, DNSSEC, and DNS Override, plus DNS cache |
| | `test_dns_settings_details` | LAN DNS records (IP / CNAME / forward, TTL) and Dynamic DNS entries |
| | `test_time_settings_rows` | Time zone, region, NTP servers, and DST |
| | `test_multicast_services_rows_and_details` | IGMP/MLD proxy, IPTV, UPnP, mDNS rules, Bonjour profiles, and snooping |
| | `test_lag_rows_and_details` | LAG summary (mode, members, link, M-LAG), per-LAG member tables, M-LAG groups, hash algorithm |
| | `test_device_port_operation_names_lag` | Device-port Operation column names the LAG an aggregating port belongs to |
| | `test_switch_settings_rows` | Per-switch management VLAN, jumbo frames, STP / loopback coverage, LAG hash, LED |
| | `test_switch_settings_details` | Site switch settings (jumbo, LLDP, IGMP snooping), per-switch detail, VLAN interfaces, RPVST |
| | `test_port_overrides_detects_differences` | Port vs profile: PoE, 802.1X, bandwidth/storm control, isolation, voice VLAN, speed/duplex, schedules, VLAN conflict |
| | `test_port_overrides_matching_port_and_special_cases` | No false positives (set order, PoE "device setting"); mirroring; gateways skipped; unknown profile |
| | `test_device_port_overrides_column_and_section` | Device-port Overrides column and "Ports differing from their profile" table |
| | `test_port_schedule_rows` | PoE and port schedules with time range and switch port membership |
| | `test_uplink_rows` | Per-switch uplink port / LAG, upstream device and port, speed, downlink count, stack unit |
| | `test_uplink_details_and_remapping_checklist` | Downlink tables, stack members, and the model-specific port remapping checklist |
| | `test_switch_port_sheet_rows_summarize_carry_over` | Per-switch summary: ports, connected, custom settings, ports to carry over (SFP / PoE) |
| | `test_switch_port_sheet_details_per_port` | Per-port sheet: VLANs, PoE, speed, LAG, connected device, manual settings, carry-over reason |
| | `test_wan_connection_type_codes_follow_spec` | WAN `protoType` codes: 0 Static, 2 PPPoE |
| | `test_gateway_port_sheet_rows` | Per-gateway summary: ports, WAN ports, connected, port-bound rules, carry over |
| | `test_gateway_port_sheet_details` | Port capability / mode, WAN connection, LAN networks, connected switch, and the port reference checklist |
| | `test_ap_sheet_rows` | Per-AP summary: bands, IP, management VLAN, uplink, LAN ports, SSID overrides |
| | `test_ap_sheet_details` | Radios, SSID overrides, general settings with carry-over flags; LAN ports and port VLANs |
| | `test_ap_sheet_dhcp_reservation_and_mgmt_ssid` | DHCP reservation and management SSID count as carry-over |
| | `test_port_connection_ignores_placeholder_port_status` | No negotiated speed shown when `portStatus` reports link down |
| | `test_port_rule_refs_and_sheet_rules_column` | Port-bound DHCP snooping / ARP detection / OUI / QoS rules (LAGs expanded) appear on the port sheet and force carry-over |
| | `test_switch_security_rows_and_details` | 802.1X, MAC auth, DHCP snooping, ARP detection, IP-MAC binding settings and per-switch tables |
| | `test_oui_vlan_rows_and_profiles` | OUI-based VLAN rules with target ports, VLAN / priority, and OUI profiles |
| | `test_switch_qos_rows_and_details` | QoS rules in index order with match, queue, remark, target ports; mode, DSCP and scheduler mappings |
| | `test_port_label_rows` | Port label definitions |
| | `test_switch_port_profile_rows` | Formats switch port profile rows |
| | `test_switch_port_profile_rows_vlan_columns` | Resolves native, untagged, and tagged networks in the profile summary |
| | `test_switch_port_profile_details_lists_all_properties` | Per-profile detail rows cover every property group, plus unmapped keys |
| | `test_switch_port_profile_details_storm_control` | Storm-control and disabled spanning-tree details |
| | `test_switch_port_profile_details_empty_input` | Detail formatter handles empty list/dict input |
| | `test_device_port_rows_switch` | Formats switch port rows (label, connection, type, operation, profile, native network) |
| | `test_device_port_rows_gateway_er605` | Formats ER605 gateway port rows (WAN / WAN-LAN / LAN type, mode, PVID native network) |
| | `test_switch_port_profile_rows_resolves_tagged_networks` | Resolves tagged network IDs to names |
| | `test_switch_port_profile_rows_no_context_shows_raw_ids` | Shows raw IDs without context |
| | `test_device_rows` | Formats device rows (name, type, model, MAC, IP, status, firmware); no ports column |
| `TestGenerateFromYaml` | `test_generates_markdown_from_yaml_files` | Generates Markdown from YAML files |
| | `test_separate_input_output_dirs` | Supports separate input/output directories |
| | `test_empty_dir_returns_empty_dict` | Returns empty dict for empty directory |
| | `test_empty_yaml_file_handled` | Handles empty YAML files gracefully |
| | `test_creates_output_dir_if_missing` | Creates output directory if it doesn't exist |

---

## test_redaction.py

Credential redaction tests.

| Test | Description |
| --- | --- |
| `test_credential_keys_detected` | Password / secret / token / key field names are treated as credentials |
| `test_non_credential_keys_not_detected` | Public keys, usernames, IDs, and setting objects are not |
| `test_redacts_nested_strings_only` | Only non-empty string values are redacted; flags and empty values are kept; input is not mutated |
| `test_passes_through_scalars` | Non-container values pass through unchanged |
| `test_contains_secrets` | Detects plaintext (non-redacted) credentials anywhere in the data |

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
| `TestVpnSecretsNeverExported` | `test_vpn_and_wireless_secrets_redacted_in_yaml_and_markdown` | No VPN / SSL VPN / WireGuard / Wi-Fi / RADIUS / portal secret appears in any written YAML or Markdown file |
| `TestIncludeSecrets` | `test_default_redacts_and_has_no_warning` | Default run redacts the Wi-Fi passphrase and adds no warning |
| | `test_include_secrets_exports_values_with_warning` | `include_secrets=True` exports the passphrase to YAML and Markdown with a warning banner |
| | `test_regenerate_from_yaml_keeps_warning` | Markdown regenerated from secret-bearing YAML keeps the warning |
| `TestGlobalRedaction` | `test_fetch_all_redacts_every_resource` | `fetch_all` redacts credentials from every resource (e.g. PPPoE password, WPA passphrase), keeping identifiers |

---

## test_web.py

Flask web application tests.

| Class | Test | Description |
| --- | --- | --- |
| `TestIndexRoute` | `test_index_returns_200` | Index page returns HTTP 200 |
| | `test_index_contains_form` | Index page contains the configuration form |
| | `test_index_contains_csrf_token_field` | Form includes a CSRF token field |
| | `test_index_contains_auth_mode_tabs` | Form shows both authentication mode tabs |
| | `test_index_lists_nested_markdown_paths` | Lists Markdown files in site subdirectories as `Site/file.md` |
| `TestRunRoute` | `test_run_missing_client_creds_flashes_error` | Flashes error when client credentials are missing |
| | `test_run_client_credentials_success` | Client Credentials mode succeeds end-to-end |
| | `test_run_include_secrets_checkbox` | Checkbox reaches the service and flashes a warning; never pre-checked afterwards |
| | `test_index_has_include_secrets_checkbox` | Run form includes the Include secrets checkbox |
| | `test_run_auth_code_success` | Authorization Code mode succeeds end-to-end |
| | `test_run_auth_code_missing_username_flashes_error` | Flashes error when username is missing in auth code mode |
| | `test_run_service_error_flashes_error` | Flashes error when service raises an exception |
| | `test_run_csrf_enforced_outside_testing` | CSRF protection is enforced outside test mode |
| | `test_run_invalid_port_flashes_error` | Flashes error for invalid port values |
| `TestRegenerateRoute` | `test_regenerate_no_yaml_files_flashes_warning` | Warns when no YAML files are found |
| | `test_regenerate_with_yaml_files` | Regenerates Markdown from existing YAML |
| | `test_regenerate_missing_output_dir_flashes_warning` | Warns when output directory doesn't exist |
| | `test_regenerate_csrf_enforced_outside_testing` | CSRF protection is enforced outside test mode |
| | `test_regenerate_uses_resolved_site_directory` | Regenerates from the site subdirectory of the last fetch (resolved site name) |
| `TestDocViewPathTraversal` | `test_path_traversal_is_blocked` | Blocks path traversal attempts |
| | `test_view_existing_doc` | Renders an existing Markdown document |
| | `test_view_missing_doc_redirects` | Redirects with warning for missing documents |
| | `test_view_nested_doc` | Renders a Markdown file inside a site subdirectory |
| `TestDownloadDoc` | `test_download_single_file` | Downloads a single file as attachment |
| | `test_download_missing_file_redirects` | Redirects with warning for missing files |
| | `test_download_path_traversal_blocked` | Blocks path traversal in download routes |
| | `test_download_nested_doc_uses_basename` | Downloading `Site/file.md` sends the file with its base name as the attachment name |
| `TestDownloadSelected` | `test_no_files_selected_flashes_warning` | Warns when no files are selected |
| | `test_download_single_selected_file` | Downloads a single selected file |
| | `test_download_multiple_files_as_zip` | Downloads multiple files as a ZIP archive |
| | `test_download_selected_path_traversal_blocked` | Blocks path traversal in selected downloads |
| | `test_download_selected_missing_file_redirects` | Redirects for missing selected files |
| | `test_download_csrf_enforced_outside_testing` | CSRF protection is enforced outside test mode |
