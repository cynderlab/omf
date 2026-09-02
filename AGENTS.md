# AGENTS.md

OH MY FORTRESS (`omf`) is a **read-only** configuration audit tool for a consultant auditor. One session: connect, collect evidence, evaluate a fixed baseline, write HTML under `./audits/`. Current MVP vendors are network devices (MikroTik, Fortinet). The kernel does not know the technology: a vendor fills catalog, how to connect/read, and which evaluators to call.

The brand is **transparency**. The operator sees every step. The model never sees secrets or identifiers.

This file is the working contract for agents. Do not copy it into code comments.

## Inviolable

These are product constraints, not style nits. A change that violates any of them is a bug.

1. **Secrets stay in RAM.** Password, API token, and any other pack auth fields are never written to disk, logs, `meta.json`, `events.jsonl`, `config.yaml`, `.env`, or LLM payloads. Username may be remembered as `last_username` in prefs only. Wipe secrets from the session with `Session.clear_secrets()` on every exit path (success, probe fail, Ctrl+C). Use a `finally`.
2. **Target identity on disk only in `report.html` and optional prefs (`last_url` for URL targets).** The report header is assembled in-process from the session after analysis. Never put the URL/tenant/host in `meta.json`, events, or LLM input.
3. **The model sees only redacted findings/evidence plus catalog text.** Never `raw/`, never `token_map.json`, never `.env`, never credentials, never IPs/hostnames/URLs/serials in the clear. Analysis tools are constructed without adapter, session, or `token_map`.
4. **Adapters are read-only.** Current packs GET (and FortiOS session login if no token). No POST/PUT/PATCH/DELETE that mutates target config. Login/logout cookies are not a config change.
5. **Evaluators are pure.** They take `(evidence_map, params, vendor) -> CheckResult`. They do not import HTTP, adapters, env, or secrets. They do not decide what to collect.
6. **The model does not choose checks.** The runner plans from the catalog, collects each needed capability **once**, then evaluates. LLM writes narrative only.
7. **TLS policy is pack-owned.** Firewall packs: verify off, TUI does not ask, dim notice (management certs are typically self-signed). SaaS packs must verify. `Session.verify_tls` stays so adapters/tests can still set it.
8. **Mitigations are examples.** Catalog text is the source. The LLM may rephrase and bind it to redacted evidence; it must not invent CLI/API beyond that text. The auditor owns any change.
9. **English is the product language.** Source, comments, docstrings, commit messages, catalog titles/descriptions/mitigations, evaluator diagnostics, TUI, `doctor`, `help`, README, and this file are English. The only exception is what the operator (or an explicit product rule) selects: the **report body** language `ca` | `es` | `en`. Do not add Catalan, Spanish, or any other language to the app unless the user asks for that specific surface.

MVP vendors: `mikrotik` (RouterOS 7+ REST) and `fortinet` (FortiOS REST). No SSH, no RouterOS 6, no PDF/DOCX, no Textual, no Haystack, no LangGraph, no RAG. A new vendor is a registry spec + catalog + adapter, not a kernel branch.

## Architecture

Two halves. They do not share credentials or raw evidence.

```
TUI (Rich, EN)  →  Session (RAM)  →  Runner (no LLM)  →  Vendor adapter
       │                  │                  │
       │                  │                  ▼
       │                  │           Evidence store (disk)
       └─ vendor spec ────┘                  │
          (catalog, connect, TLS)            ▼
                                         Redactor
                                             │
                         └────────►  Analysis agent (one-shot httpx JSON completion)
                                     one-shot fail pack + narrative
                                     NO collect / NO network
```

The four steps the kernel runs, without knowing firewall vs SaaS vs OS:

1. Load that vendor’s catalog of checks.
2. Connect and read the params the catalog `needs`.
3. Evaluate with pure functions.
4. Redact and write the report (LLM narrative or skeleton).

| Unit | Owns | Must not |
|---|---|---|
| `cli.py` + `./omf` | `help` / `install` / `doctor` / default TUI; `-v`/`--debug` | Extra verbs (`audit`, `report`, …) |
| `tui.py` + `banner.py` + `menus.py` | English prompts (Rich + questionary), live counters, report path | Own HTTP or LLM calls; hardcode vendor URL/TLS |
| `vendors.py` | Registry of vendor specs (target kind, TLS, labels, adapter builder) | Evaluate or call the model |
| `connect.py` | Reachability + probe error copy | Authenticate or collect |
| `log.py` | stderr logging; debug URLs without userinfo | Print passwords / tokens / `Authorization` |
| `session.py` | Vendor, target identity, creds, TLS, report language | Persist password or token |
| `wizard.py` | Pure validators | I/O |
| `config.py` | `.env` LLM settings + `~/.config/omf/config.yaml` prefs | Persist password or token |
| `runner.py` | Plan, collect once, evaluate, write store | Talk to the model |
| `pipeline.py` | Probe → run → redact → analyze/skeleton → destokenize header | Leak URL into meta |
| `adapters/` | Collect + normalize to frozen models; `auth.py` schemes | Pass/fail decisions; own the registry |
| `baseline/` | Per-vendor catalogs + profiles, shared pure evaluators | Know URLs or secrets |
| `redactor.py` | Tokenize identifiers; strip secrets | Call the model |
| `agent/` | Narrative Markdown from redacted tools | Collect or connect |
| `store.py` | `./audits/YYYY-MM-DDTHHMMSS-{vendor}/` layout | Interpret findings |

`AuditStore.write_meta` and event writers reject secret keys. Keep that guard.

## Commands

Tooling is **uv** only. Python **3.12+**. No pip/poetry/Makefile as the operator interface.

```bash
./omf              # TUI (after install)
./omf install      # uv sync --all-extras --all-groups; create .env from .env.example if missing
./omf doctor       # required vs warn; never talks to a target
./omf help
./omf -v           # DEBUG on stderr (HTTP URLs and phases; no secrets)
uv run pytest      # CI suite; no live target
```

`doctor` required failures → exit 1. Missing LLM env is a **warn** (exit 0): collect + evaluate + skeleton report still work. TUI **Report** prompt: Evaluation only (no LLM) takes that same path even when LLM env is set (no model call). Evaluation-only reports are English (catalog language); the language prompt is LLM narrative only. LLM narrative is the other choice and still falls back to skeleton if env is missing or the model fails.

LLM env (search `./.env` then `~/.config/omf/.env`): `OMF_LLM_BASE_URL`, `OMF_LLM_API_KEY`, `OMF_LLM_MODEL`, `OMF_LLM_API_STYLE` (`openai` \| `anthropic`). `is_configured()` requires the first three non-empty.

User prefs (`~/.config/omf/config.yaml`): disclaimer, `default_report_language` (`ca` \| `es` \| `en`), optional `last_vendor`, optional `last_url` and `last_username`, optional `last_report_mode` (`eval` \| `llm`) as wizard defaults. **Never** password or token. Broken YAML → warn, defaults, rewrite.

`last_url` / `last_username` are the only target identifiers allowed in prefs today (URL-kind packs). They still must never appear in `meta.json`, events, or LLM payloads. The session target in `report.html` remains the only copy in the audit folder.

TUI language is English. Evaluation-only report chrome is English. LLM narrative report body is `ca` \| `es` \| `en` (operator choice). Everything else in the repo is English — see Inviolable §9.

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
report.html                  # local header (includes URL) + destokenized HTML body
```

Statuses: `pass` / `fail` / `error` / `skipped`. ERROR is a collect/parse/evaluator exception, not a security fail. SKIPPED means the check is absent from the vendor catalog or a needed capability is unimplemented.

LLM fail: **one retry**, then deterministic skeleton (`Narrative skipped` + fail-only table + title / severity / description / evidence / mitigation). Do not reconnect to the target.

Log lines: `[collect] GET /rest/user 200 84ms` — method, **path only**, status, duration. Also `[eval]`, `[redact]`, `[llm]`. Never print password, token, API key, or `Authorization`.

## Schema and matching

Pydantic v2, `ConfigDict(frozen=True, extra="forbid")`. No extras dict on capability payloads. Vendor leftovers stay in `raw/` and never enter evaluators.

Firewall vendors share a capability library (stable names): `users`, `admin_settings`, `services`, `ntp`, `dns`, `logging`, `snmp`, `firewall_filter`, `system_info`. Fortinet extras: `zones`, `local_in`, `ha`, `utm`, `licenses`. MikroTik extra: `l2_access`. `CORE_CAPABILITIES` is that firewall nine — **not** an obligation on future non-firewall vendors. `ALL_CAPABILITIES` is CORE plus both extra sets. Fortinet `implemented()` returns CORE plus Fortinet extras. MikroTik returns CORE plus `l2_access`. A pack implements only what its catalog `needs`. Unimplemented capabilities make dependents SKIPPED.

`collect(capability)` **always** returns the same frozen payload type for a given capability name. If the adapter cannot fill that type, the capability is ERROR — not a slightly different JSON. Policy “any” tokens (`*`, empty, `0.0.0.0/0`, `0.0.0.0`, `::/0`) normalize to the single token `any` via `adapters/normalize.py`.

Vendor-specific **policy** (default account names, insecure service lists, default hostnames) lives in that vendor’s catalog `params` and/or `baseline/vendors/<vendor>/profile.yaml`. `resolve_params` uses the check params, then profile keys if unset.

If two vendors do not share a judgement, they get different catalog rows (and optionally `params.mode`). Do not `if vendor` inside an adapter to decide a finding. Adapter `if vendor` is only for HTTP/normalize. Shared evaluator functions are fine when the payload type matches.

Sixty-three unique checks today (24 MikroTik, 57 Fortinet). `FW-POL-002` is MikroTik-only. `FW-POL-005` is Fortinet-only. MikroTik extras include neighbor discovery, MAC access, auxiliary services, SSH strong-crypto, PPTP server, and last RouterOS update status from `GET /rest/system/package/update` (never POST `check-for-updates`). Fortinet `profile.yaml` holds a static FortiOS EoES/EoS table used by `firmware_supported`; do not invent a version floor for vendors without a table, and do not query Fortinet’s portal. IDs are ours, not CIS. Inspired by CIS FortiGate 7.4.x Benchmark v1.0.1 Level 1. Level 2 is out of scope. CIS 2.4.3 is omitted because “correct profile” is org policy. Growing the catalog is additive YAML + evaluator.

## How to extend

**Add a check** (preferred, cheapest):

1. Entry in `src/omf/baseline/vendors/<vendor>/catalog.yaml` (`id`, `title`, `severity`, `needs`, `evaluator`, `params`, `description`, `mitigation`). `title` is a neutral topic (`Administrative HTTP/HTTPS ports`), never a pass/fail assertion. `description` is English control rationale (not a pass/fail assertion). Status and `diagnostic` carry the judgement. Fortinet description/mitigation text is paraphrased from CIS FortiGate 7.4.x Benchmark v1.0.1 Level 1; it is not CIS-CAT output. MikroTik description/mitigation text is RouterOS 7 plus the evaluators, not CIS.
2. If the evaluator is new: pure function in `baseline/evaluators/`, register in `REGISTRY`. Reuse an existing function when the payload type already matches.
3. Vendor params or `baseline/vendors/<vendor>/profile.yaml` — not adapter branches.
4. Unit test with frozen fixtures. No network.

**Add a capability:**

1. Frozen payload on `schema/capabilities.py` (firewall library) or a vendor-specific schema module. Add the name to `ALL_CAPABILITIES` only if it is part of the firewall set.
2. Implement `collect` + normalizer on the vendor(s) that need it. Other vendors omit it → dependents SKIPPED.
3. Fixture JSON under `tests/adapters/fixtures/<vendor>/`.
4. TUI and agent stay unchanged.

**Add a vendor:**

1. `VendorSpec` in `vendors.py` (id, label, group, target kind/label, TLS policy, target noun, optional TUI hint).
2. Catalog + profile under `baseline/vendors/<id>/`.
3. Adapter implementing `VendorAdapter` (`probe`, `collect -> (Evidence, raw)`, `implemented`, `close`). Register the class in `vendors._ADAPTERS` (that module builds the HTTP client for URL packs).
4. Auth schemes in `adapters/auth.py`.
5. Fixture set + normalize tests.
6. Runner never receives a client or a password.
7. HTTP URL packs: timeouts 15s connect, 30s read. No collect retries. Other transports are pack-owned and still read-only.

REST paths: Probe: MikroTik `GET /rest/system/identity`; Fortinet `GET /api/v2/monitor/system/status`.

Auth: MikroTik HTTP Basic (token field ignored). Fortinet: Bearer token if set, else session login + cookie; `close()` logs out when the vendor provides it.

Fortinet `services` is synthesized: one `Service` per management protocol seen in interface `allowaccess`. `listen=restricted` if every admin has a trusthost; `listen=all` if any enabled admin has empty trusthosts or `0.0.0.0/0`; `listen=unknown` if trusthost keys are **absent**. FW-SVC-002 fails on `all` **and** `unknown` for names in `params.mgmt`.

## Redaction

Deterministic. Same value → same token within a session.

Tokenize: IPv4/IPv6 (including CIDR and hyphen ranges as one `[IP_n]`), FQDNs, unqualified `hostname`/`host` values, URLs (`http`/`https`/`ftp`), emails as `[USER_n]`, serials, non-allowlisted usernames, non-`public`/`private` SNMP communities → `[IP_n]`, `[HOST_n]`, `[URL_n]`, `[SERIAL_n]`, `[USER_n]`, `[SECRET_n]`. After the tree walk, rewrite every already-seen original in remaining strings (diagnostics, other keys) so the same value is always the same token. The redactor is vendor-agnostic and runs once after collect/eval; adapters do not tokenize.

Allowlist (do not tokenize): `admin`, `administrator`, `root`, `guest`, `public`, `private`, check IDs, capability names, vendor names (`mikrotik`, `fortinet`, `fortigate`), `accept`/`deny`/`drop`, `any`, and protocol/service names (`ftp`, `ssh`, `http`, `https`, `www`, `www-ssl`, `winbox`, `api`, …).

Strip (do not tokenize, do not put in `token_map`): keys `password`, `passwd`, `passphrase`, `secret`, `psk`, `private_key`, `api_key` → `[STRIPPED]`.

After the model returns structured narrative, destokenize the stitched Markdown with the local map. The model only ever sees tokens.

## Analysis agent

One-shot httpx JSON completion. No function tools, no collect, no network to the target, no session, no `token_map`. The kernel injects a redacted, list-capped fail pack plus status counts. The model returns structured narrative (executive summary + per-fail title/description). `narrative_body` stitches catalog evidence tables and mitigations locally. After destokenize, `finalize_report` builds HTML (dashboard from findings + escaped Markdown body).

Keep `tests/test_llm_boundary.py` true: one model request; payloads contain no URL, password, key, `raw`, or `token_map`. `run_analysis` must not take session or `token_map`.

## Tests

CI has **no** live target. Marker `integration` is optional and not CI.

| Layer | Expectation |
|---|---|
| Evaluators | Frozen fixtures, no network |
| Normalizers | Fixture vendor JSON → canonical model |
| Redactor | Tokens stable; allowlist kept; passwords stripped; IPv6-mapped (`::ffff:x.x.x.x`) not split |
| Runner | Fake adapter; collect-once; missing → SKIPPED; collect fail → ERROR on dependents |
| LLM boundary | Mock model; no secrets/raw/token_map in payloads |
| Store | `assert_no_secrets` after a run; URL only in `report.html` |
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
- Do not persist target credentials “for convenience”.
- Do not send more to the model to make the report “smarter”.

## Implementation landmines (already paid for)

- **`collect` returns `(Evidence, raw)`.** Runner writes both. Do not collapse this.
- **FortiOS envelopes.** Most normalizers unwrap `results` via `forti_unwrap`. `system_info` must read `version` / `serial` / `model` from the **envelope**, not only from `results` (`forti_system`).
- **Missing FortiOS `trusthost*` keys mean `listen=unknown`**, not `restricted`. Empty trusthost or `0.0.0.0/0` is `all`.
- **Redact URLs before hostnames** so the host inside a URL is not double-tokenized. Match IPv4-tail IPv6 forms before dotted quads.
- **TUI events: path only.** Adapter `last_call` must not carry host, query secrets, or `Authorization`.
- **`leak_hits` skips catalog fields.** `fail_pack` attaches description (not mitigation). Those may contain `0.0.0.0/0`, `::/0`, or FortiGuard anycast. Scan diagnostic/observed only.
- **`config.yaml` is YAML, not TOML.** LLM stays in `.env`.
- Bump `DISCLAIMER_VERSION` when `DISCLAIMER_TEXT` changes so the prompt is shown again.
- **HA password** is stripped from Fortinet `raw/` and `HaConfig` before persist. Do not put `password` / `passwd` / `secret` from `system ha` into evidence.
- **Vendor registry owns connection.** Do not add `if vendor ==` for URL, TLS, or wizard labels in the TUI. Put them on `VendorSpec` in `vendors.py`.
- **Per-vendor catalogs.** Checks live in `baseline/vendors/<id>/catalog.yaml`. Do not revive a global catalog with `applies_to`. Shared evaluator functions are the reuse point, not a shared YAML file.
