# AGENTS.md

OH MY FIREWALL (`omf`) is a **read-only** firewall audit tool for a consultant auditor. One session: connect, collect evidence, evaluate a fixed baseline, write Markdown under `./audits/`.

The brand is **transparency**. The operator sees every step. The model never sees secrets or identifiers.

This file is the working contract for agents. Do not copy it into code comments.

## Inviolable

These are product constraints, not style nits. A change that violates any of them is a bug.

1. **Firewall secrets stay in RAM.** Password and API token are never written to disk, logs, `meta.json`, `events.jsonl`, `config.yaml`, `.env`, or LLM payloads. Username may be remembered as `last_username` in prefs only. Wipe password/token/username from the session with `Session.clear_secrets()` on every exit path (success, probe fail, Ctrl+C). Use a `finally`.
2. **Target URL on disk only in `report.md` and optional prefs `last_url`.** The report header is assembled in-process from the session after analysis. Never put the URL in `meta.json`, events, or LLM input.
3. **The model sees only redacted findings/evidence plus catalog text.** Never `raw/`, never `token_map.json`, never `.env`, never credentials, never IPs/hostnames/URLs/serials in the clear. Analysis tools are constructed without adapter, session, or `token_map`.
4. **Adapters are read-only.** GET (and FortiOS session login if no token). No POST/PUT/PATCH/DELETE that mutates device config. Login/logout cookies are not a config change.
5. **Evaluators are pure.** They take `(evidence_map, params, vendor) -> CheckResult`. They do not import HTTP, adapters, env, or secrets. They do not decide what to collect.
6. **The model does not choose checks.** The runner plans from the catalog, collects each needed capability **once**, then evaluates. LLM writes narrative only.
7. **TLS verify is off.** The TUI does not ask. Management certs are typically self-signed. Show a dim notice. `Session.verify_tls` stays so adapters/tests can still set it.
8. **Mitigations are examples.** Catalog text is the source. The LLM may rephrase and bind it to redacted evidence; it must not invent CLI/API beyond that text. The auditor owns any change.
9. **English is the product language.** Source, comments, docstrings, commit messages, catalog titles/mitigations, evaluator diagnostics, TUI, `doctor`, `help`, README, and this file are English. The only exception is what the operator (or an explicit product rule) selects: the **report body** language `ca` | `es` | `en`. Do not add Catalan, Spanish, or any other language to the app unless the user asks for that specific surface.

MVP vendors: `mikrotik` (RouterOS 7+ REST) and `fortinet` (FortiOS REST). No SSH, no RouterOS 6, no other vendors, no PDF/HTML/DOCX, no Textual, no Haystack, no LangGraph, no RAG.

## Architecture

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
                                     tools: redacted read + submit_report
                                     NO collect / NO network
```

| Unit | Owns | Must not |
|---|---|---|
| `cli.py` + `./omf` | `help` / `install` / `doctor` / default TUI; `-v`/`--debug` | Extra verbs (`audit`, `report`, …) |
| `tui.py` + `banner.py` + `menus.py` | English prompts (Rich + questionary), live counters, report path | Own HTTP or LLM calls |
| `connect.py` | Reachability + probe error copy | Authenticate or collect |
| `log.py` | stderr logging; debug URLs without userinfo | Print passwords / tokens / `Authorization` |
| `session.py` | Vendor, URL, creds, TLS, report language | Persist password or token |
| `wizard.py` | Pure validators | I/O |
| `config.py` | `.env` LLM settings + `~/.config/omf/config.yaml` prefs | Persist password or token |
| `runner.py` | Plan, collect once, evaluate, write store | Talk to the model |
| `pipeline.py` | Probe → run → redact → analyze/skeleton → destokenize header | Leak URL into meta |
| `adapters/` | HTTP + normalize to frozen models; `auth.py` schemes | Pass/fail decisions |
| `baseline/` | Catalog, vendor profiles, pure evaluators | Know URLs or secrets |
| `redactor.py` | Tokenize identifiers; strip secrets | Call the model |
| `agent/` | Narrative Markdown from redacted tools | Collect or connect |
| `store.py` | `./audits/YYYY-MM-DDTHHMMSS-{vendor}/` layout | Interpret findings |

`AuditStore.write_meta` and event writers reject secret keys. Keep that guard.

## Commands

Tooling is **uv** only. Python **3.12+**. No pip/poetry/Makefile as the operator interface.

```bash
./omf              # TUI (after install)
./omf install      # uv sync --all-extras --all-groups; create .env from .env.example if missing
./omf doctor       # required vs warn; never talks to a firewall
./omf help
./omf -v           # DEBUG on stderr (HTTP URLs and phases; no secrets)
uv run pytest      # CI suite; no live firewall
```

`doctor` required failures → exit 1. Missing LLM env is a **warn** (exit 0): collect + evaluate + skeleton report still work.

LLM env (search `./.env` then `~/.config/omf/.env`): `OMF_LLM_BASE_URL`, `OMF_LLM_API_KEY`, `OMF_LLM_MODEL`, `OMF_LLM_API_STYLE` (`openai` \| `anthropic`). `is_configured()` requires the first three non-empty.

User prefs (`~/.config/omf/config.yaml`): disclaimer, `default_report_language` (`ca` \| `es` \| `en`), optional `last_vendor`, optional `last_url` and `last_username` as wizard defaults. **Never** password or token. Broken YAML → warn, defaults, rewrite.

`last_url` / `last_username` are the only firewall identifiers allowed in prefs. They still must never appear in `meta.json`, events, or LLM payloads. The session URL in `report.md` remains the only copy in the audit folder.

TUI language is English. The generated report body is `ca` \| `es` \| `en` (operator choice). Everything else in the repo is English — see Inviolable §9.

## Data flow

Session dir (gitignored `./audits/`):

```
meta.json                    # no url / username / password / token
raw/<capability>.json        # vendor JSON, local only
evidence/<capability>.json
findings.json
redacted/findings.json
redacted/evidence/<capability>.json
redacted/transcript.md       # what the model saw; omitted if LLM skipped
token_map.json               # local only
events.jsonl                # path only, no host, no secrets
report.redacted.md           # omitted if LLM skipped
report.md                    # local header (includes URL) + destokenized body
```

Statuses: `pass` / `fail` / `error` / `skipped`. ERROR is a collect/parse/evaluator exception, not a security fail. SKIPPED means `applies_to` excludes the vendor or a needed capability is unimplemented.

LLM fail: **one retry**, then deterministic skeleton (`Narrative skipped` + fail-only table + title / severity / description / evidence / mitigation). Do not reconnect to the firewall.

Log lines: `[collect] GET /rest/user 200 84ms` — method, **path only**, status, duration. Also `[eval]`, `[redact]`, `[llm] <tool_name>`. Never print password, token, API key, or `Authorization`.

## Schema and matching

Pydantic v2, `ConfigDict(frozen=True, extra="forbid")`. No extras dict on capability payloads. Vendor leftovers stay in `raw/` and never enter evaluators.

Nine CORE capabilities (stable names): `users`, `admin_settings`, `services`, `ntp`, `dns`, `logging`, `snmp`, `firewall_filter`, `system_info`. Four Fortinet-only extras: `zones`, `local_in`, `ha`, `utm`. One MikroTik-only extra: `l2_access`. `CORE_CAPABILITIES` is the original nine. `ALL_CAPABILITIES` is CORE plus both extra sets. Fortinet `implemented()` returns CORE plus Fortinet extras. MikroTik returns CORE plus `l2_access`. Unimplemented extras make dependents SKIPPED.

`collect(capability)` **always** returns the same frozen payload type for every vendor. If the adapter cannot fill that type, the capability is ERROR — not a slightly different JSON. Policy “any” tokens (`*`, empty, `0.0.0.0/0`, `::/0`) normalize to the single token `any` via `adapters/normalize.py`.

Vendor-specific **policy** (default account names, insecure service lists, default hostnames) lives in catalog `params` and/or `baseline/profiles/<vendor>.yaml`. `resolve_params` shallow-merges `params.default` → `params[vendor]` → profile keys if unset.

If two vendors do not share a judgement, use evaluator `params.mode` or two checks with different `applies_to`. Do not `if vendor` inside an adapter to decide a finding. Adapter `if vendor` is only for HTTP/normalize.

Forty-eight checks today (24 MikroTik, 41 Fortinet). `FW-POL-002` is MikroTik-only. `FW-POL-005` is Fortinet-only. MikroTik extras include neighbor discovery, MAC access, auxiliary services, SSH strong-crypto, PPTP server, and last RouterOS update status from `GET /rest/system/package/update` (never POST `check-for-updates`). IDs are ours, not CIS. Inspired by CIS FortiGate 7.4.x Benchmark v1.0.1 Level 1. Level 2 is out of scope. CIS 2.4.3 is omitted because “correct profile” is org policy. Growing the catalog is additive YAML + evaluator. There is no firmware EOL database; do not invent a minimum-version floor.

## How to extend

**Add a check** (preferred, cheapest):

1. Entry in `src/omf/baseline/catalog.yaml` (`id`, `title`, `severity`, `applies_to`, `needs`, `evaluator`, `params`, `mitigation.generic` + optional vendor text). `title` is a neutral topic (`Administrative HTTP/HTTPS ports`), never a pass/fail assertion. Status and `diagnostic` carry the judgement.
2. If the evaluator is new: pure function in `baseline/evaluators/`, register in `REGISTRY`.
3. Vendor params or `profiles/<vendor>.yaml` — not adapter branches.
4. Unit test with frozen fixtures. No network.

**Add a capability:**

1. Frozen payload on `schema/capabilities.py` + `ALL_CAPABILITIES` (and `CORE_CAPABILITIES` if only one vendor implements it).
2. Implement `collect` + normalizer on **both** adapters (or leave unimplemented → dependents SKIPPED).
3. Fixture JSON under `tests/adapters/fixtures/{mikrotik,fortinet}/`.
4. TUI and agent stay unchanged.

**Add a vendor:**

1. Adapter implementing `VendorAdapter` (`probe`, `collect -> (Evidence, raw)`, `implemented`, `close`).
2. `profiles/<vendor>.yaml`.
3. Register in `adapters/factory.py`.
4. Fixture set + normalize tests.
5. HTTP client is created **inside** the factory/adapter from the session. Runner never receives a client or a password.
6. Timeouts: 15s connect, 30s read. No collect retries.

REST paths: Probe: MikroTik `GET /rest/system/identity`; Fortinet `GET /api/v2/monitor/system/status`.

Auth: MikroTik HTTP Basic (token field ignored). Fortinet: Bearer token if set, else session login + cookie; `close()` logs out when the vendor provides it.

Fortinet `services` is synthesized: one `Service` per management protocol seen in interface `allowaccess`. `listen=restricted` if every admin has a trusthost; `listen=all` if any enabled admin has empty trusthosts or `0.0.0.0/0`; `listen=unknown` if trusthost keys are **absent**. FW-SVC-002 fails on `all` **and** `unknown` for names in `params.mgmt`.

## Redaction

Deterministic. Same value → same token within a session.

Tokenize: IPv4/IPv6, FQDNs, URLs, serials, non-allowlisted usernames, non-`public`/`private` SNMP communities → `[IP_n]`, `[HOST_n]`, `[URL_n]`, `[SERIAL_n]`, `[USER_n]`, `[SECRET_n]`.

Allowlist (do not tokenize): `admin`, `administrator`, `root`, `guest`, `public`, `private`, check IDs, capability names, vendor names, `accept`/`deny`/`drop`, `any`.

Strip (do not tokenize, do not put in `token_map`): keys `password`, `passwd`, `passphrase`, `secret`, `psk`, `private_key`, `api_key` → `[STRIPPED]`.

After the model returns Markdown, destokenize with the local map. The model only ever sees tokens.

## Analysis agent

Pydantic AI. Tools: `list_findings`, `get_finding`, `get_redacted_evidence`, `get_mitigation`, `submit_report`. No collect, no network, no session, no `token_map`.

`submit_report` accepts the Markdown **body** (no title header): executive summary, fail-only table, then one vulnerability block per fail (`title`, `severity`, `description`, `evidence`, `mitigation`). `finalize_report` prepends localized title plus Author / Date / Firewall (vendor · URL-from-RAM) / Tool, then destokenizes.

Keep `tests/test_llm_boundary.py` true: request/tool payloads contain no URL, password, key, `raw`, or `token_map`. `build_agent` must not hang session or `token_map` on the agent.

## Tests

CI has **no** live firewall. Marker `integration` is optional and not CI.

| Layer | Expectation |
|---|---|
| Evaluators | Frozen fixtures, no network |
| Normalizers | Fixture vendor JSON → canonical model |
| Redactor | Tokens stable; allowlist kept; passwords stripped; IPv6-mapped (`::ffff:x.x.x.x`) not split |
| Runner | Fake adapter; collect-once; missing → SKIPPED; collect fail → ERROR on dependents |
| LLM boundary | Mock model; no secrets/raw/token_map in payloads |
| Store | `assert_no_secrets` after a run; URL only in `report.md` |
| CLI / doctor | Help; required vs warn; API key never printed |
| Live Rich UI | Not tested |
| Real adapters | `@pytest.mark.integration` only |

Ship catalog YAML in the wheel (`[tool.hatch.build] include = ["src/omf/**/*.yaml"]`). Do not break that.

## Style

- KISS. Least code that preserves the invariants.
- Python 3.12+, type hints, frozen models, no extra fields on capabilities.
- English everywhere in the repo (docstrings, comments, strings, docs, commits). Report body language is the only operator-selected exception.
- Comments only for non-obvious constraints (e.g. FortiOS envelope, IPv6-mapped order). Write those comments in English.
- Conventional commits in English: `feat:`, `fix:`, `chore:`, `docs:`.
- Do not add subcommands, frameworks, or vendors “while you’re here”.
- Do not persist firewall credentials “for convenience”.
- Do not send more to the model to make the report “smarter”.

## Implementation landmines (already paid for)

- **`collect` returns `(Evidence, raw)`.** Runner writes both. Do not collapse this.
- **FortiOS envelopes.** Most normalizers unwrap `results` via `forti_unwrap`. `system_info` must read `version` / `serial` / `model` from the **envelope**, not only from `results` (`forti_system`).
- **Missing FortiOS `trusthost*` keys mean `listen=unknown`**, not `restricted`. Empty trusthost or `0.0.0.0/0` is `all`.
- **Redact URLs before hostnames** so the host inside a URL is not double-tokenized. Match IPv4-tail IPv6 forms before dotted quads.
- **TUI events: path only.** Adapter `last_call` must not carry host, query secrets, or `Authorization`.
- **`config.yaml` is YAML, not TOML.** LLM stays in `.env`.
- Bump `DISCLAIMER_VERSION` when `DISCLAIMER_TEXT` changes so the prompt is shown again.
- **HA password** is stripped from Fortinet `raw/` and `HaConfig` before persist. Do not put `password` / `passwd` / `secret` from `system ha` into evidence.
