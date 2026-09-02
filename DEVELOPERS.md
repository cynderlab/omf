# Developers

OH MY FORTRESS (`omf`) is a **read-only** hardening auditor. One session: connect, collect evidence, evaluate a fixed catalog, write HTML under `./audits/`.

The kernel does **not** know firewall vs SaaS vs OS. A vendor pack fills catalog, how to connect/read, TLS policy, and which evaluators to call. A new vendor is a registry spec + catalog + adapter — not a kernel branch.

Hard product rules live in [AGENTS.md](AGENTS.md). This file is the map of the code and the exact steps to extend it. English is the repo language. The only operator-selected language is the **report body** (`ca` | `es` | `en`).

MVP packs: `mikrotik` (RouterOS 7+ REST) and `fortinet` (FortiOS REST). No SSH, no RouterOS 6.

## How a run works

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

The kernel always runs the same four steps:

1. Load that vendor’s catalog of checks.
2. Connect and read the params the catalog `needs`.
3. Evaluate with pure functions.
4. Redact and write the report (LLM narrative or skeleton).

`pipeline.run_audit` is the orchestration:

1. **Probe** — adapter `probe()`. Reachability + auth. No collect yet.
2. **Plan** — checks from `baseline/vendors/<id>/catalog.yaml`. The model does not choose checks.
3. **Collect once** — runner walks every `needs` capability, calls `adapter.collect` at most once, writes `evidence/` + `raw/`.
4. **Evaluate** — pure functions `(evidence_map, params, vendor) -> CheckResult`. No HTTP.
5. **Redact** — tokenize identifiers, strip secrets. Write `redacted/` + `token_map.json` (local only).
6. **Narrate** — optional LLM writes Markdown from redacted tools. TUI **Evaluation only (no LLM)** skips this even when LLM env is set. Fail → one retry → deterministic skeleton.
7. **Finalize** — destokenize locally, build `report.html` header **in process** from the session (target identity hits the audit folder only here).
8. **`finally`** — `Session.clear_secrets()`.

Statuses: `pass` / `fail` / `error` / `skipped`. ERROR is a collect/parse/evaluator exception, not a security fail. SKIPPED means the check is absent from the vendor catalog or a needed capability is unimplemented.

LLM missing, failed, or skipped: collect + evaluate + skeleton still run. Do not reconnect to the target.

## Layout

| Unit | Owns | Must not |
|---|---|---|
| `cli.py` + `./omf` | `help` / `install` / `doctor` / default TUI; `-v` | Extra verbs (`audit`, `report`, …) |
| `tui.py` + `banner.py` + `menus.py` | English prompts, live counters, report path | HTTP, LLM, or hardcoded vendor URL/TLS |
| `vendors.py` | Registry: `VendorSpec` + adapter class + HTTP client for URL packs | Evaluate or call the model |
| `connect.py` | Reachability + probe error copy | Authenticate or collect |
| `session.py` | Vendor id, target identity, creds, TLS, report language | Persist password or token |
| `wizard.py` | Pure validators (`parse_vendor` reads `vendors.ids()`) | I/O |
| `config.py` | `.env` LLM settings + `~/.config/omf/config.yaml` prefs | Persist password or token |
| `runner.py` | Plan, collect once, evaluate, write store | Talk to the model |
| `pipeline.py` | Probe → run → redact → analyze/skeleton → destokenize header | Leak URL into `meta.json` |
| `adapters/` | Collect + normalize to frozen models; `auth.py` schemes | Pass/fail decisions; own the registry |
| `baseline/` | Per-vendor catalogs + profiles, shared pure evaluators | Know URLs or secrets |
| `redactor.py` | Tokenize identifiers; strip secrets | Call the model |
| `agent/` | Narrative Markdown from redacted tools | Collect or connect |
| `store.py` | `./audits/YYYY-MM-DDTHHMMSS-{vendor}/` layout | Interpret findings |

The HTTP client for URL packs is created in `vendors.build_adapter` (15s connect, 30s read, `verify=session.verify_tls`). The runner never receives a client or a password.

TLS policy is **pack-owned** (`VendorSpec.tls_verify`). Firewall packs: verify off, TUI does not ask, dim notice. SaaS packs must verify. `Session.verify_tls` stays so tests can still set it.

TUI vendor menu and wizard allow-list come from `vendors.py`. Do not add `if vendor ==` for URL, TLS, or wizard labels in the TUI.

## Schema

Pydantic v2, `ConfigDict(frozen=True, extra="forbid")`. No extras dict on capability payloads. Vendor leftovers stay in `raw/` and never enter evaluators.

Firewall packs share a capability library (stable names):

`users`, `admin_settings`, `services`, `ntp`, `dns`, `logging`, `snmp`, `firewall_filter`, `system_info`

Fortinet extras: `zones`, `local_in`, `ha`, `utm`, `licenses`. MikroTik extra: `l2_access`.

`CORE_CAPABILITIES` is that firewall nine — **not** an obligation on future non-firewall vendors. A pack implements only what its catalog `needs`. Unimplemented capabilities make dependents SKIPPED.

`collect(capability)` **always** returns the same frozen payload type for a given capability name. If the adapter cannot fill that type, the capability is ERROR — not a slightly different JSON.

Policy “any” tokens (`*`, empty, `0.0.0.0/0`, `0.0.0.0`, `::/0`) normalize to `any` via `adapters/normalize.py`.

Vendor **policy** (default account names, insecure services, default hostnames) lives in that vendor’s catalog `params` and/or `baseline/vendors/<id>/profile.yaml`. `resolve_params` uses the check params, then profile keys if unset.

If two vendors do not share a judgement, they get **different catalog rows** (and optionally `params.mode`). Do **not** `if vendor` inside an adapter to decide a finding. Adapter `if vendor` is only for HTTP/normalize. Shared evaluator functions are fine when the payload type matches.

Checks live in `baseline/vendors/<id>/catalog.yaml`. There is no global catalog with `applies_to`. Shared evaluator functions are the reuse point, not a shared YAML file.

`collect` returns `(Evidence, raw)`. Runner writes both. Do not collapse this.

## Add a check

Preferred. Cheapest. No adapter change if the capability already exists.

1. Entry in `src/omf/baseline/vendors/<vendor>/catalog.yaml`:

   | Key | Role |
   |---|---|
   | `id` | Stable identifier (ours, not CIS). Findings, report, tests. |
   | `title` | Neutral topic (`Administrative HTTP/HTTPS ports`). Never a pass/fail assertion. |
   | `severity` | `high` / `medium` / `low`. Catalog sets it; the evaluator does not pick it. |
   | `needs` | Capability names the runner collects once. Missing or unimplemented → SKIPPED. |
   | `evaluator` | Name in `REGISTRY` of the pure function. |
   | `params` | Optional. Check knobs; `resolve_params` merges with `profile.yaml` (check wins). |
   | `description` | English control rationale for the report / LLM. Not a pass/fail assertion. Status and `diagnostic` carry the judgement. |
   | `mitigation` | Example remediation. The LLM may rephrase; it must not invent CLI/API beyond this text. |

   Fortinet description/mitigation text is paraphrased from CIS FortiGate 7.4.x Benchmark v1.0.1 Level 1; it is not CIS-CAT output. MikroTik description/mitigation text is RouterOS 7 plus the evaluators, not CIS.

2. If the evaluator is new: pure function in `src/omf/baseline/evaluators/`, register the name in `REGISTRY` in `evaluators/__init__.py`. Signature: `(evidence_map, params, vendor) -> CheckResult`. No HTTP, adapters, env, or secrets. Reuse an existing function when the payload type already matches.

3. Vendor-specific values go in that check’s `params` or `baseline/vendors/<vendor>/profile.yaml`, not adapter branches.

4. Unit test with frozen fixtures. No network.

IDs are ours, not CIS. Growing the catalog is additive YAML + evaluator. Fortinet `profile.yaml` holds a static FortiOS EoES/EoS table used by `firmware_supported`; do not invent a version floor for vendors without a table, and do not query Fortinet’s portal.

## Add a capability

1. Frozen payload on `src/omf/schema/capabilities.py` (firewall library) or a vendor-specific schema module. Add the name to `ALL_CAPABILITIES` only if it is part of the firewall set.
2. Implement `collect` + normalizer on the vendor(s) that need it. Other vendors omit it → dependents SKIPPED.
3. Fixture JSON under `tests/adapters/fixtures/<vendor>/` and a normalize test.
4. TUI and agent stay unchanged.

## Add a vendor

Exact file list. Do them in this order. Do not add SSH, extra CLI verbs, or LLM tools “while you’re here”.

The slug is lowercase ASCII (`pfsense`, not `pfSense`). It must match the `VendorSpec.id`, catalog directory, adapter `vendor` field, auth key, and redactor allowlist.

### 1. Registry spec

`src/omf/vendors.py` — append a `VendorSpec` to `_SPECS` and the class to `_ADAPTERS`.

| Field | Meaning |
|---|---|
| `id` | Slug. Catalog dir, session.vendor, audit folder suffix. |
| `label` | TUI menu text (English). |
| `group` | e.g. `firewall`. Informational. |
| `target_kind` | `url` today. Other transports are pack-owned. |
| `target_label` | Wizard prompt (`Device URL`). |
| `tls_verify` | Firewall packs: `False`. SaaS packs: `True`. |
| `tls_notice` | Dim TUI notice, or `None`. |
| `target_noun` | Copy (`firewall`, later `tenant`, …). |
| `hint` | Optional extra TUI line after vendor select. |

`wizard.parse_vendor` and `menus.VENDOR_OPTIONS` read this registry. You do **not** edit those files for a new pack.

### 2. Auth scheme

`src/omf/adapters/auth.py` — add `VENDOR_AUTH_SCHEMES["<slug>"]`.

The TUI only prompts the fields you list (`username`, `password`, `token`). This is the single source of truth for wizard + adapters.

Adapters are **read-only**. Current packs GET (FortiOS session login/logout cookies are allowed — not a config change). No POST/PUT/PATCH/DELETE that mutates target config.

### 3. Adapter

`src/omf/adapters/<slug>.py` implementing `VendorAdapter`:

| Method | Contract |
|---|---|
| `probe()` | One cheap GET that proves auth. Raise `ProbeError`. |
| `collect(capability)` | Return `(Evidence, raw)`. Raise `CollectError` on HTTP/parse failure. Same frozen payload type as every other pack for that capability name. |
| `implemented()` | Frozenset of capability names this adapter can fill. Unlisted → dependents SKIPPED. |
| `close()` | Logout if the vendor has a session cookie. Always safe to call. |

Register the class in `vendors._ADAPTERS`. For URL packs, `vendors.build_adapter` creates the `httpx.Client`. Other transports: pack-owned, still read-only. Timeouts for HTTP URL packs: 15s connect, 30s read. No collect retries.

Probe paths today: MikroTik `GET /rest/system/identity`; Fortinet `GET /api/v2/monitor/system/status`.

`last_call` (if you expose one) is **path only**: method, path, status, ms. No host, no query secrets, no `Authorization`.

### 4. Catalog + profile

```
src/omf/baseline/vendors/<slug>/catalog.yaml
src/omf/baseline/vendors/<slug>/profile.yaml
```

No `applies_to`. If the check is in this file, it applies. Shared judgement across vendors → same evaluator function, two catalog rows. Different judgement → different rows (and optionally `params.mode`).

Ship YAML in the wheel (`[tool.hatch.build] include = ["src/omf/**/*.yaml"]`). Do not break that.

### 5. Redactor allowlist

`src/omf/redactor.py` — add the slug (and any product name the payload will contain, like `fortigate`) to `ALLOWLIST` so it is not tokenized as `[HOST_n]`.

### 6. Tests (no live target)

CI has **no** live target. Marker `integration` is optional and not CI.

| Layer | What to add |
|---|---|
| Normalize | `tests/adapters/fixtures/<slug>/*.json` → canonical frozen model |
| Auth | `tests/test_auth_schemes.py` for the new schemes |
| Wizard | `parse_vendor` accepts the slug (registry-driven; still worth a line) |
| Evaluators | Frozen evidence fixtures; no network |
| Runner | Fake adapter is enough |
| LLM boundary | Do not regress `tests/test_llm_boundary.py` |

Real adapter calls: `@pytest.mark.integration` only.

### 7. Constraints that fail review

- Secrets stay in RAM. Never write password, token, or other pack auth fields to disk, logs, `meta.json`, `events.jsonl`, `config.yaml`, `.env`, or LLM payloads.
- Target identity on disk only in `report.html` and optional prefs (`last_url` for URL targets).
- Same frozen payload type per capability name. If you cannot fill it, leave it unimplemented (SKIPPED), or ERROR if you claim it and then cannot parse.
- Policy in that vendor’s YAML, not `if vendor` in the adapter.
- Do not hardcode the new vendor’s URL/TLS/labels in the TUI. Put them on `VendorSpec`.
- Mitigations are catalog text. The LLM may rephrase; it must not invent CLI beyond that text.

## Redaction and the model

The redactor is vendor-agnostic and runs **once** after collect/eval. Adapters do not tokenize.

- Tokenize: IPs (CIDR and hyphen ranges as one `[IP_n]`), FQDNs, hostnames, URLs, emails → `[USER_n]`, serials, non-allowlisted usernames, non-`public`/`private` SNMP communities.
- Strip (not in `token_map`): keys `password`, `passwd`, `passphrase`, `secret`, `psk`, `private_key`, `api_key` → `[STRIPPED]`.
- After the tree walk, rewrite every already-seen original in remaining strings so the same value is always the same token.
- Redact URLs **before** hostnames so the host inside a URL is not double-tokenized.

The analysis agent (one-shot httpx JSON completion) has no adapter, no session, no `token_map`, and no function tools. The kernel injects a redacted, list-capped fail pack plus status counts. The model returns structured narrative (executive summary + per-fail title/description). `narrative_body` stitches catalog evidence tables and mitigations locally. `run_analysis` must not take session or `token_map`.

Keep `tests/test_llm_boundary.py` true: one model request; payloads contain no URL, password, key, `raw/`, or `token_map`.

## Tests and commands

```bash
./omf install          # uv sync --all-extras --all-groups; .env from .env.example if missing
./omf doctor           # required vs warn; never talks to a target
./omf -v               # DEBUG on stderr: method + path + status + ms. No secrets.
uv run pytest          # CI suite; no live target
```

TUI **Report** prompt: Evaluation only (no LLM) writes the skeleton even when LLM env is set. LLM narrative is the other choice and still falls back to skeleton if env is missing or the model fails.

Conventional commits in English: `feat:`, `fix:`, `chore:`, `docs:`.
