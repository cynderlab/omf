# AGENTS.md

OH MY FIREWALL (`omf`) is a read-only firewall audit tool. This is the working contract for this tree.

## Capabilities

Nine CORE capabilities. `collect(capability)` always returns the same frozen payload type for every vendor.

| Capability | Payload |
|---|---|
| `users` | `UserList` |
| `admin_settings` | `AdminSettings` |
| `services` | `ServiceList` |
| `ntp` | `NtpConfig` |
| `dns` | `DnsConfig` |
| `logging` | `LoggingConfig` |
| `snmp` | `SnmpConfig` |
| `firewall_filter` | `PolicyList` |
| `system_info` | `SystemInfo` |

Four Fortinet-only extras. MikroTik leaves them unimplemented so those checks are SKIPPED.

| Capability | Payload |
|---|---|
| `zones` | `ZoneList` |
| `local_in` | `LocalInPolicyList` |
| `ha` | `HaConfig` |
| `utm` | `UtmConfig` |

`CORE_CAPABILITIES` is the original nine. `ALL_CAPABILITIES` is CORE plus the four extras. Fortinet `implemented()` returns ALL. MikroTik returns CORE.

## Catalog

Forty-two checks (14 MikroTik, 41 Fortinet). `FW-POL-002` is MikroTik-only. IDs are ours, not CIS. Inspired by CIS FortiGate 7.4.x Benchmark v1.0.1 Level 1. Level 2 is out of scope. CIS 2.4.3 is omitted because “correct profile” is org policy.

## Invariants

- Username, password, and API token stay in process RAM. The target URL appears on disk only in the `report.md` header.
- Adapters are read-only (GET, plus FortiOS session login if no token).
- Evaluators are pure: `(evidence_map, params, vendor) -> CheckResult`. They do not import HTTP or secrets.
- Secrets never enter evidence. HA password is stripped before raw and model.
