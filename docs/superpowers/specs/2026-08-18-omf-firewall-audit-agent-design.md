# OMF — Firewall audit agent (MVP)

**Date:** 2026-08-18  
**Status:** Approved  
**Product:** OH MY FIREWALL (`omf`)  
**Repo:** greenfield

## 1. Intent

A CLI/TUI tool for a **consultant auditor**. One session per engagement: connect read-only to a firewall, collect evidence, evaluate a fixed baseline, keep everything on disk, write a Markdown report. Recurring/SOC use is out of MVP but must not be designed out.

The brand is **transparency**. The operator sees every step. The model never sees secrets, IPs, hostnames, URLs, serials, or credentials.

Mitigations appear in the report as **examples**. The tool never changes the device. Responsibility stays with the auditor.

## 2. Goals and non-goals

### Goals (MVP)

- Audit **MikroTik (RouterOS 7+ REST)** and **Fortinet (FortiOS REST)**.
- Run **all** applicable baseline checks every session (completeness, repeatability).
- Encapsulate every network call in a vendor adapter. The LLM has **no** network tools.
- Persist raw evidence, canonical evidence, findings, and a Markdown report under `./audits/`.
- English TUI (Rich + prompts). Report language `ca` | `es` | `en`.
- Cloud LLM via OpenAI-compatible **or** Anthropic-compatible endpoints (OpenRouter, Fireworks, etc.).
- Single operator entry point (`./omf` / `omf`): default TUI, plus `install`, `doctor`, `help`. Tooling is **uv**.

### Non-goals (MVP)

- SSH / RouterOS 6 / vendors other than MikroTik and Fortinet.
- Writing or remediating config on the device.
- PDF, HTML, DOCX.
- Persistent firewall credentials or target URL.
- Recurring scans, scheduling, inventory of many devices.
- RAG over CIS/vendor PDFs.
- Textual multi-pane cockpit.
- A rule DSL in YAML.
- Haystack / LangGraph.

## 3. Constraints (inviolable)

1. Username, password, and API token live in **process memory only**. Never written anywhere on disk or to the LLM. The target URL stays in RAM during the run; the only disk copy allowed is the local header of `report.md`. Never in `config.yaml`, `.env`, `meta.json`, `events.jsonl`, or LLM payloads.
2. LLM payloads contain only **redacted** findings/evidence plus catalog text (check titles, curated mitigations). Never `raw/`, never `token_map.json`, never `.env`.
3. Adapters are read-only. No POST/PUT/PATCH/DELETE that mutates device config. Probe and collect are GET (or vendor-equivalent read). FortiOS login-to-get-a-session-cookie is allowed if token is absent; that session is not a config change.
4. Evaluators are pure functions. They do not import HTTP, adapters, or env secrets.
5. Default TLS certificate verification is **on**. Insecure TLS is an explicit wizard answer, default no.

## 4. Architecture

Two halves. They do not share credentials or raw evidence.

```
TUI (Rich, EN)  →  Session (RAM)  →  Runner (no LLM)  →  Vendor adapter
                         │                  │
                         │                  ▼
                         │           Evidence store (disk)
                         │                  │
                         │                  ▼
                         │              Redactor
                         │                  │
                         └────────►  Analysis agent (Pydantic AI)
                                     tools: read redacted + write report
                                     NO collect / NO network
```

| Unit | Does | Does not |
|---|---|---|
| TUI | Prompt, live log, counters | Own HTTP or LLM calls |
| Session | Hold vendor, URL, creds, TLS flag, report language | Persist firewall secrets |
| Runner | Plan, collect each capability once, evaluate, write store | Talk to the model |
| Adapter | HTTP to one vendor, normalize to frozen models | Decide pass/fail |
| Catalog / profiles | Check metadata, vendor default names, mitigation text | Know URLs |
| Evaluator | Judge canonical evidence + params | Touch the network |
| Redactor | Tokenize identifiers; strip secrets | Call the model |
| Analysis agent | Adapt mitigations, write narrative Markdown | Collect or connect |
| Store | Session directory layout | Interpret findings |

Adding a vendor = one adapter + profile params. Adding a check = YAML entry + one evaluator (if new). TUI and agent stay unchanged.

## 5. Baseline matching

The model does **not** choose checks. Matching is data + pure code.

- **Capability** — a named slice of device state (`users`, `ntp`, …).
- **Adapter** — `collect(capability) -> Evidence[Payload]`. Vendor-specific HTTP and mapping live only here.
- **Check** — YAML: id, title, severity, `applies_to`, `needs`, `evaluator` name, `params`, `mitigation`.
- **Evaluator** — registered Python function `(evidence_map, params, vendor) -> CheckResult`.

`collect("users")` **always** returns the same frozen payload type, regardless of vendor. If the adapter cannot fill that type, the capability is `ERROR`, not a “slightly different JSON”.

Vendor-specific **policy** (default account names, insecure service lists, min firmware) lives in catalog `params` and/or `baseline/profiles/<vendor>.yaml`. Adapters do not decide what a finding is.

If two vendors do not share a judgement (e.g. FortiOS cannot delete `admin`, only rename it), use evaluator `params.mode` or two checks with different `applies_to`. Do not `if vendor` inside an adapter.

**SKIPPED** — check `applies_to` excludes this vendor, or a required capability is not implemented.  
**ERROR** — probe/collect/parse/evaluator exception. Not a security fail.  
**FAIL** — collected successfully; control is not met.  
**PASS** — collected successfully; control is met.

## 6. Canonical models

Pydantic v2, `ConfigDict(frozen=True)`. No `extras` dict on capability payloads. Vendor-only leftovers stay in `raw/` and never enter evaluators.

Envelope:

```python
class Evidence(BaseModel, Generic[T]):
    model_config = ConfigDict(frozen=True)
    capability: str
    vendor: Literal["mikrotik", "fortinet"]
    schema_version: int = 1
    collected_at: datetime
    payload: T
```

MVP payloads (fields may be optional with defaults; names are stable):

| Capability | Payload | Required fields |
|---|---|---|
| `users` | `UserList` | `users: tuple[User, ...]`; `User.name`, `User.enabled`, `User.groups` |
| `admin_settings` | `AdminSettings` | `hostname`, `idle_timeout_seconds` (optional int) |
| `services` | `ServiceList` | `services: tuple[Service, ...]`; `Service.name`, `Service.enabled`, `Service.port`, `Service.listen` (`all` / `restricted` / `unknown`) |
| `ntp` | `NtpConfig` | `enabled`, `servers: tuple[str, ...]` |
| `dns` | `DnsConfig` | `servers: tuple[str, ...]` |
| `logging` | `LoggingConfig` | `local_enabled`, `remote_targets: tuple[str, ...]` |
| `snmp` | `SnmpConfig` | `enabled`, `communities: tuple[SnmpCommunity, ...]`; `SnmpCommunity.name`, `SnmpCommunity.version` |
| `firewall_filter` | `PolicyList` | `policies: tuple[Policy, ...]`; `Policy.id`, `Policy.enabled`, `Policy.action` (`accept` / `deny` / `drop` / `other`), `Policy.src`, `Policy.dst`, `Policy.service` (each `tuple[str, ...]`). Adapters **must** normalize vendor “all”, empty, `*`, `0.0.0.0/0`, `::/0` to the single token `any`. |
| `system_info` | `SystemInfo` | `firmware`, `model` (optional) |

`CheckResult`: `check_id`, `status` (`pass` / `fail` / `error` / `skipped`), `severity`, `diagnostic` (short English sentence for the store; report writer translates), `capability_refs`, `observed` (JSON-serializable scalars/lists only).

## 7. MVP catalog

Fourteen checks. IDs are ours (not CIS). Inspired by common hardening guides. Growing to ~30 later is additive YAML + evaluators only. There is no firmware EOL database; a “minimum version” check is omitted on purpose (it would be SKIPPED unless we invented a floor).

| ID | Title | needs | evaluator | Notes |
|---|---|---|---|---|
| FW-ADM-001 | No generic default admin username | `users` | `no_generic_accounts` | `params.names` per vendor; default `admin`, `administrator`, `root`. Fortinet: `mode: must_be_renamed` (default name still present = fail). MikroTik: `mode: must_not_exist`. |
| FW-ADM-002 | Admin idle timeout is set | `admin_settings` | `idle_timeout_set` | Fail if timeout missing or `0`. Optional `params.max_seconds`. |
| FW-ADM-003 | Device identity is not the factory default | `admin_settings` | `hostname_not_default` | `params.default_hostnames` per vendor (`MikroTik`, `FortiGate`, empty). |
| FW-SVC-001 | Insecure management services are disabled | `services` | `insecure_services_disabled` | `params.forbidden` e.g. `telnet`, `ftp`, `www`, `http`. |
| FW-SVC-002 | Management services are not open to all | `services` | `services_not_unrestricted` | Fail if an enabled mgmt service has `listen=all` or `listen=unknown`. `params.mgmt` list. |
| FW-NTP-001 | NTP is enabled with at least one server | `ntp` | `ntp_configured` | |
| FW-DNS-001 | DNS servers are configured | `dns` | `dns_configured` | |
| FW-LOG-001 | Local logging is enabled | `logging` | `local_logging_enabled` | |
| FW-LOG-002 | Remote syslog is configured | `logging` | `remote_syslog_configured` | |
| FW-SNMP-001 | No default SNMP community | `snmp` | `no_default_snmp_community` | Fail if enabled community name is `public` or `private` (case-insensitive). |
| FW-SNMP-002 | SNMP is disabled or uses v3-only communities | `snmp` | `snmp_not_legacy` | Pass if SNMP disabled **or** all communities are v3. |
| FW-POL-001 | No unrestricted accept policy | `firewall_filter` | `no_any_any_accept` | Fail if enabled policy is accept + src/dst/service all `any`. |
| FW-POL-002 | Explicit deny is present (MikroTik) | `firewall_filter` | `explicit_deny_present` | `applies_to: [mikrotik]`. Fortinet implicit deny → this check skipped. |
| FW-SYS-001 | Firmware version is recorded | `system_info` | `firmware_present` | Pass if `firmware` non-empty. Informational; no EOL DB. |

Each check has `mitigation.generic` plus optional `mitigation.mikrotik` / `mitigation.fortinet`. Text is curated in the catalog. The LLM may rephrase and bind it to redacted evidence. It must not invent CLI/API that is not implied by that text.

## 8. Session, config, and secrets

### 8.1 LLM — `.env` only

Search order: `./.env` then `~/.config/omf/.env`.

```
OMF_LLM_BASE_URL=
OMF_LLM_API_KEY=
OMF_LLM_MODEL=
OMF_LLM_API_STYLE=openai   # openai | anthropic
```

No other keys required. Missing LLM config does **not** block collect/evaluate.

### 8.2 User prefs — `~/.config/omf/config.yaml`

```yaml
disclaimer_accepted: true
disclaimer_version: 1
default_report_language: ca   # ca | es | en
last_vendor: mikrotik         # optional wizard default
```

If the file is missing or broken: warn, use defaults, recreate a valid file.  
If `disclaimer_version` in code is newer than the file: show disclaimer again.

Never store URL, username, password, or token here.

Disclaimer text (English, TUI). Version **1**. Bump the integer when this text changes:

> OMF is a read-only firewall audit tool. It will authenticate to the device you specify and collect configuration evidence. It will not change the device. Suggested mitigations in the report are examples only. You, the auditor, are responsible for any change applied to the system. Review the session folder before sharing it; `raw/` contains unredacted vendor data. Proceed?

### 8.3 Session (RAM)

Wizard fields every run: vendor, base URL, username, password, optional API token, verify TLS (default yes), report language (default from yaml).

Auth selection:

- **MikroTik:** HTTP Basic with username/password. Token field ignored.
- **Fortinet:** if token non-empty, use `Authorization: Bearer <token>`. Else username/password session login.

On process exit, Ctrl+C, or wizard failure: drop all session secret fields.

## 9. Data flow and store

Session directory: `./audits/YYYY-MM-DDTHHMMSS-{vendor}/`

```
meta.json                 # vendor, timestamps, report language, tool version, tls_verify
                          # MUST NOT contain url, username, password, token
raw/<capability>.json     # vendor JSON, local only
evidence/<capability>.json
findings.json
redacted/findings.json
redacted/evidence/<capability>.json
token_map.json            # local only; never sent to the model
events.jsonl             # TUI/runner events, secrets stripped
report.redacted.md        # model output (or omitted if LLM skipped)
report.md                 # final: local header + destokenized body
```

`meta.json` does **not** store the target URL. The URL exists only in RAM. The final `report.md` header includes the target URL because that header is assembled **in process** from the session, after the model has finished, not by writing the URL to `meta.json`. If we need the URL on disk for the auditor, it appears only inside `report.md` (the deliverable they already expect to contain the client device). It still never appears in LLM input.

Pipeline:

1. Disclaimer if needed → wizard → adapter probe. Probe fail → exit, no checks.
2. Load catalog, filter `applies_to`, union `needs` → collection plan. Log the plan.
3. Collect each capability once. Write `raw/` + `evidence/`. Collect fail → capability ERROR; dependent checks ERROR; continue others.
4. Evaluate all checks. Write `findings.json`.
5. Redact findings + canonical evidence → `redacted/` + `token_map.json`.
6. If LLM configured: agent writes `report.redacted.md` from redacted data only. Locally prepend header (vendor, URL from RAM, time, tool) and destokenize body → `report.md`.
7. If LLM missing or failed after one retry: write `report.md` as a **deterministic skeleton** (findings table + catalog mitigations verbatim, banner `Narrative skipped`). No `report.redacted.md`.
8. Print path to `report.md`. Wipe firewall creds from RAM.

## 10. Redaction

Deterministic. No model involved.

**Replace with stable tokens** (`[IP_1]`, `[IP_2]`, `[HOST_1]`, `[USER_1]`, `[URL_1]`, `[SERIAL_1]`, `[SECRET_1]`):

- IPv4 / IPv6
- FQDNs and hostnames (non-allowlisted)
- URLs
- Serial-like strings
- Usernames **not** on the allowlist
- SNMP community names **not** `public` / `private`

**Allowlist (do not tokenize):** `admin`, `administrator`, `root`, `guest`, `public`, `private`, check IDs, capability names, vendor names, actions `accept`/`deny`/`drop`, the word `any`.

**Strip, do not tokenize:** values of keys matching `password`, `passwd`, `passphrase`, `secret`, `psk`, `private_key`, `api_key` (any case, substring `_key` only if listed). Replaced with `[STRIPPED]`.

Same value → same token within a session. `token_map.json` is the reverse map, local only.

After the model returns Markdown, destokenize with that map. The model only ever sees tokens.

## 11. Analysis agent

**Framework:** Pydantic AI.  
**Providers:** OpenAI-compatible (`OMF_LLM_API_STYLE=openai`) and Anthropic-compatible (`anthropic`). Base URL + key + model from env.

The agent is constructed **without** any adapter, session, or `token_map`. Tools:

| Tool | Returns |
|---|---|
| `list_findings` | id, status, severity, title |
| `get_finding` | one redacted finding + diagnostic + observed |
| `get_redacted_evidence` | one redacted capability payload |
| `get_mitigation` | catalog mitigation text for that check + vendor |
| `submit_report` | accepts full Markdown body; persists `report.redacted.md` |

System prompt (normative intent): write the report in the selected language; use only tool data; adapt catalog mitigations to the redacted evidence; do not invent vendor commands beyond that text; state that mitigations are examples and the auditor owns the change; do not mention hidden IPs or ask for credentials.

Report body structure (LLM and skeleton share this outline):

1. Short executive summary (counts + top risks). Skeleton: counts only.
2. Findings table.
3. One subsection per non-PASS check: diagnostic, adapted (or verbatim) mitigation.
4. Closing line: read-only assessment; examples only; auditor is responsible.

Local wrapper then adds the title header (tool name, vendor, target URL from RAM, timestamp).

## 12. CLI and TUI

### 12.1 Single entry point

The operator never learns a second command. From a clone:

```
./omf              # default: TUI
./omf help
./omf install      # install / sync all project deps
./omf doctor       # what is missing
```

After `install`, the same surface is available as the console script `omf` (`uv run omf …`).

**Tooling:** `uv` + `pyproject.toml`. No pip, poetry, or Makefile as the operator interface. Python **3.12+**.

**Bootstrap:** a POSIX shell launcher at the repo root named `omf` (no extension). It exists so `install` / `help` / a useful `doctor` work **before** the venv exists.

| Arg | Behaviour |
|---|---|
| *(none)* | If deps are not synced, print “run `./omf install`” and exit 1. Else `uv run python -m omf` → TUI. |
| `help` or `-h` / `--help` | Print the four commands. Exit 0. Works without a venv. |
| `install` | If `uv` is missing, print the official uv install one-liner and exit 1 (do not curl from the script). Else `uv sync --all-extras --all-groups` from the repo root. Exit with uv’s status. |
| `doctor` | Run the checks in §12.2. Exit 0 only if every **required** check passes. |
| anything else | Print help. Exit 1. |

The Python package (`python -m omf`, console script `omf`) implements the same verbs (`help`, `doctor`, default TUI). `install` in the Python CLI execs `uv sync --all-extras --all-groups` (same as the launcher). No other subcommands in the MVP (no `omf audit`, no `omf report`).

### 12.2 `doctor`

Read-only. Never asks for firewall credentials. Never opens a firewall connection.

| Check | Level | Pass if |
|---|---|---|
| `uv` on `PATH` | required | `uv --version` works |
| Python 3.12+ | required | `uv python` / interpreter ≥ 3.12 |
| Deps synced | required | `import omf` works inside the project environment |
| LLM `.env` file | warn | `./.env` or `~/.config/omf/.env` exists |
| `OMF_LLM_BASE_URL` | warn | set and non-empty |
| `OMF_LLM_API_KEY` | warn | set and non-empty (print only “set” / “missing”, never the value) |
| `OMF_LLM_MODEL` | warn | set and non-empty |
| `OMF_LLM_API_STYLE` | warn | missing (defaults to `openai`) or `openai` / `anthropic` |

Output: one line per check, `OK` / `MISSING` / `WARN`, English. Required failures → exit 1. Warnings only (typical: no LLM yet) → exit 0, because collect/evaluate still work.

### 12.3 TUI (MVP)

English. **Rich + sequential prompts.** Not Textual. This is what `omf` with no args starts.

1. Disclaimer (if needed).
2. Wizard prompts.
3. One `Live` view: phase line, PASS/FAIL/SKIP/ERR counters, checks table, last N log lines.
4. Final: summary + path to `report.md`.

Log line format: `[collect] GET /rest/user 200 84ms` — method, **path only** (no host, no query secrets), status, duration. Also `[eval]`, `[redact]`, `[llm] <tool_name>`.

Never print password, token, API key, or `Authorization`.

`Ctrl+C`: stop HTTP, persist what is already on disk, wipe RAM creds, exit non-zero.

No in-TUI raw viewer, no Markdown preview pane, no per-check confirmation.

## 13. Adapters

Protocol (conceptual):

```python
class VendorAdapter(Protocol):
    vendor: Literal["mikrotik", "fortinet"]
    def probe(self) -> None: ...
    def collect(self, capability: str) -> Evidence: ...
    def implemented(self) -> frozenset[str]: ...
    def close(self) -> None: ...
```

- Base URL from session. Paths are relative (`/rest/user`, `/api/v2/cmdb/system/admin`).
- Timeouts: 15s connect, 30s read. No collect retries (LLM is the only one-retry path).
- `implemented()` drives SKIPPED when a future check needs a capability this adapter lacks. MVP adapters implement all nine capabilities in §6.
- HTTP client is created with session creds inside the adapter. Runner never receives a client or a password.

**Probe**

| Vendor | Method |
|---|---|
| MikroTik | `GET /rest/system/identity` |
| Fortinet | `GET /api/v2/monitor/system/status` |

Fortinet token: send `Authorization: Bearer <token>`. If token is empty, POST vendor session login, then use the cookie for subsequent GETs; `close()` logs out if the vendor provides it.

**Collect endpoints (normative for MVP fixtures)**

| Capability | MikroTik | Fortinet |
|---|---|---|
| `users` | `GET /rest/user` | `GET /api/v2/cmdb/system/admin` |
| `admin_settings` | `GET /rest/system/identity` + `GET /rest/user/settings` (timeout if present) | `GET /api/v2/cmdb/system/global` + `GET /api/v2/cmdb/system/admin` (hostname / `admintimeout`) |
| `services` | `GET /rest/ip/service` | Synthesize from `GET /api/v2/cmdb/system/interface` (`allowaccess`) and admin `trusthost*` |
| `ntp` | `GET /rest/system/ntp/client` | `GET /api/v2/cmdb/system/ntp` |
| `dns` | `GET /rest/ip/dns` | `GET /api/v2/cmdb/system/dns` |
| `logging` | `GET /rest/system/logging` + `GET /rest/system/logging/action` | `GET /api/v2/cmdb/log.syslogd/setting` (and `log.syslogd2` if present) |
| `snmp` | `GET /rest/snmp` + `GET /rest/snmp/community` | `GET /api/v2/cmdb/system/snmp/community` + `GET /api/v2/cmdb/system/snmp/sysinfo` |
| `firewall_filter` | `GET /rest/ip/firewall/filter` | `GET /api/v2/cmdb/firewall/policy` |
| `system_info` | `GET /rest/system/resource` | `GET /api/v2/monitor/system/status` |

**Fortinet `services` synthesis (KISS, conservative):** build one `Service` per management protocol seen in any interface `allowaccess` (`https`, `ssh`, `http`, `telnet`, `ftp`). `enabled=true` if any interface lists it. `listen=restricted` if every admin has at least one `trusthost` set; `listen=all` if any enabled admin has empty trusthosts **or** a trusthost of `0.0.0.0/0`; `listen=unknown` only if trusthost fields are absent from the payload. FW-SVC-002 fails on `all` **and** on `unknown` for names in `params.mgmt`.

MikroTik `services`: `listen=all` when `address` is empty or `0.0.0.0/0`; otherwise `restricted`.

## 14. Errors

| Event | Behaviour |
|---|---|
| Disclaimer refused | Exit 1. No network. |
| LLM env missing | Collect + evaluate + skeleton `report.md`. Warn. |
| Probe fail (network, TLS, 401/403) | Stop. Show status/path. No checks. Wipe creds. |
| One capability fails | That capability ERROR; dependent checks ERROR; continue. |
| Evaluator exception | That check ERROR + traceback in `events.jsonl`. Continue. |
| LLM fail | One retry. Then skeleton `report.md`. Do not reconnect to the firewall. |
| Ctrl+C | Cancel, close HTTP, keep disk, wipe creds. |
| Broken `config.yaml` | Warn, defaults, rewrite file. |
| Insecure TLS | Only if wizard said yes. Log a visible warning. |

## 15. Testing

CI has **no** live firewall.

| Layer | How |
|---|---|
| Evaluators | Unit tests, frozen fixtures, no network. |
| Normalizers | Fixture vendor JSON → canonical model (one fixture set per vendor × capability). |
| Redactor | IPs/users tokenized; allowlist kept; passwords stripped; assert a fake LLM payload builder never includes `token_map` or `raw`. |
| Runner | Fake adapter. Each capability collected once; missing capability → SKIPPED; collect fail → ERROR on dependents; store layout asserted. |
| LLM boundary | Mock model. Assert request bodies contain no URL, password, key, `raw`, or `token_map`. |
| Wizard validation | Pure functions (URL parse, vendor enum, language enum). |
| CLI / doctor | `help` text; doctor required vs warn; API key never printed; unknown arg → exit 1. |
| Live Rich UI | Not tested. |
| Real adapters | `integration` mark, optional, not CI. |

## 16. Package layout

Python 3.12+. `uv` + `pyproject.toml`. Console script: `omf = omf.cli:main`. Root launcher: `./omf`.

```
omf                  # POSIX launcher (install/help/doctor/default)
pyproject.toml
src/omf/
  __init__.py
  __main__.py
  cli.py
  tui.py
  session.py
  config.py          # .env + config.yaml
  runner.py
  redactor.py
  store.py
  baseline/
    catalog.yaml
    profiles/mikrotik.yaml
    profiles/fortinet.yaml
    evaluators/
  schema/
  adapters/
    base.py
    mikrotik.py
    fortinet.py
  agent/
    tools.py
    report.py
tests/
audits/              # gitignored
```

## 17. Success criteria

A developer (or the implementation plan) is done with the MVP when:

1. An operator can run `./omf install`, `./omf doctor`, and `./omf` (TUI), accept the disclaimer once, enter MikroTik or Fortinet details, and get `./audits/.../report.md` without the model ever receiving URL/creds/raw/token_map (enforced by tests in §15).
2. All 14 checks run; SKIPPED/ERROR/FAIL/PASS are distinguishable in the TUI table and `findings.json`.
3. Both adapters fill the nine frozen capability models from the endpoints in §13 (unit-tested via fixtures).
4. With LLM env set, the report is in the chosen language and contains adapted catalog mitigations. Without it, the skeleton report still lists every finding and verbatim mitigations.
5. After a run (including Ctrl+C and probe failure), the session directory contains no password, token, or API key. The target URL appears on disk only in `report.md` (and only if that file was written).

## 18. Decisions log

| Topic | Decision |
|---|---|
| Primary user | Auditor; recurring later |
| Mutation | Never. Mitigations are examples |
| Orchestration | Deterministic runner + Pydantic AI analysis |
| Frameworks rejected | Haystack, LangGraph, Textual (MVP) |
| LLM | Cloud, OpenAI- or Anthropic-compatible |
| Report | Markdown only |
| TUI language | English |
| Report language | `ca` / `es` / `en` |
| Firewall secrets | RAM only |
| LLM secrets | `.env` |
| User prefs | `~/.config/omf/config.yaml` (not TOML) |
| Evidence to model | Redacted fragments + findings |
| Mitigations | Catalog text; LLM adapts, does not invent |
| Connection | Official REST only |
| TUI | Rich + prompts, one live view |
| Tooling | uv only |
| Entry point | `./omf` / `omf`: default TUI; `install`; `doctor`; `help` |
| Matching | Capability × vendor; shared frozen models; params in YAML |
