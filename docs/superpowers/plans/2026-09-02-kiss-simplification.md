# KISS Simplification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove dead shims, collapse local duplication, then split the Fortinet adapter and replace Pydantic AI with one httpx JSON call — without changing audit behavior or violating product invariants.

**Architecture:** Keep the four kernel steps (catalog → collect → evaluate → redact/report). Delete pass-through modules. Evaluators stay pure. Adapters stay read-only. The model still sees only a redacted fail pack. `collect` still returns `(Evidence, raw)`.

**Tech Stack:** Python 3.12+, uv, pytest, Pydantic v2, httpx, Rich, per-vendor YAML catalogs.

**Spec:** Audit in the prior turn (KISS / unused-code review). No separate design doc.

## Global Constraints

- Secrets stay in RAM; `Session.clear_secrets()` in every `finally`; never write password/token to disk, logs, `meta.json`, events, `.env`, or LLM payloads.
- Target URL on disk only in `report.html` and optional prefs `last_url`.
- Model sees only redacted findings/evidence plus catalog text; never `raw/`, `token_map`, session, credentials, or clear IPs/hostnames in LLM input.
- Adapters are GET-only (FortiOS login/logout cookies allowed).
- Evaluators are pure `(evidence, params, vendor) -> CheckResult`; no `if vendor` inside them.
- `collect` returns `(Evidence, raw)`. Same capability name → same frozen payload type.
- English in repo (source, tests, commits, AGENTS.md, DEVELOPERS.md). Report body language `ca`|`es`|`en` is the only operator exception.
- Tooling: `uv` only. Verify with `uv run pytest`. No live target.
- Do not add Markdown libraries, collector plugin frameworks, or a shared VendorHttpAdapter base class.
- Do not split `Policy` / `AdminSettings`. Do not merge MikroTik and Fortinet `_as_bool` token sets.
- Commits on this feature branch are required for SDD review packages. Conventional commits in English (`chore:`, `refactor:`, `fix:`).
- No new code comments unless a non-obvious constraint (English).

---

## File map

| File | Role after this plan |
|---|---|
| `src/omf/adapters/factory.py` | **Delete** |
| `src/omf/baseline/loader.py` | `load_catalog(vendor)` only; string description/mitigation |
| `src/omf/agent/report.py` | One fail-section builder; `finalize_report` calls `render_html_report` |
| `src/omf/agent/tools.py` | `AnalysisContext`, `fail_pack`, `status_counts` — no `get_finding` / `get_mitigation` |
| `src/omf/baseline/evaluators/admin.py` | `flag_enabled` only (no `banner_enabled`) |
| `src/omf/session.py` | Add `report_mode: Literal["eval","llm"] = "llm"` |
| `src/omf/adapters/fortinet/` | Package: `normalize.py` + `adapter.py` + re-export `__init__.py` |
| `src/omf/agent/llm.py` | httpx POST; parse `ReportNarrative`; one retry |
| `src/omf/agent/trace.py` | **Delete** (Phase 3) |
| `docs/superpowers/plans/` | This plan + folder `.gitignore` |

Work from: the git worktree that contains this plan file.

Do not dispatch subagents. Do not start implementation on `main`.

---

### Task 0: Save the plan and gitignore

**Files:**
- Create: `docs/superpowers/plans/2026-09-02-kiss-simplification.md` (this document)
- Create: `docs/superpowers/plans/.gitignore`
- Modify: `.gitignore` (root `docs/` ignore)

- [x] **Step 1: Write folder gitignore**

```
# Keep markdown plans; ignore local scratch
*
!.gitignore
!*.md
```

- [x] **Step 2: Un-ignore the plans path in root `.gitignore`**

Replace the bare `docs/` line with:

```
docs/
!docs/superpowers/
!docs/superpowers/plans/
!docs/superpowers/plans/**
```

- [x] **Step 3: Write this plan file**

- [ ] **Step 4: Confirm git can see the plan**

Run: `git check-ignore -v docs/superpowers/plans/2026-09-02-kiss-simplification.md`
Expected: no ignore (empty output), or a negation rule.

---

## Phase 1 — Dead shims

### Task 1: Delete `adapters/factory.py`

**Files:**
- Delete: `src/omf/adapters/factory.py`
- Modify: `src/omf/tui.py:22`
- Modify: `tests/adapters/test_http_adapters.py:8`
- Modify: `DEVELOPERS.md:70`

**Interfaces:**
- Consumes: `omf.vendors.build_adapter(session: Session, client: httpx.Client | None = None) -> VendorAdapter`
- Produces: no `omf.adapters.factory` module

- [ ] **Step 1: Retarget imports**

`src/omf/tui.py` — change so `build_adapter` comes from `omf.vendors`, merged with the existing vendor import:

```python
from omf.adapters.base import ProbeError, VendorAdapter
from omf.vendors import build_adapter, get as vendor_spec, ids as vendor_ids
```

Remove `from omf.adapters.factory import build_adapter`. Delete the old `from omf.vendors import get as vendor_spec, ids as vendor_ids` duplicate.

`tests/adapters/test_http_adapters.py:8`:

```python
from omf.vendors import build_adapter
```

- [ ] **Step 2: Delete `src/omf/adapters/factory.py`**

- [ ] **Step 3: Fix DEVELOPERS.md:70**

Replace the factory sentence with:

```
The HTTP client for URL packs is created in `vendors.build_adapter` (15s connect, 30s read, `verify=session.verify_tls`). The runner never receives a client or a password.
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/adapters/test_http_adapters.py tests/test_tui_session.py -q`
Expected: PASS

Then: `uv run pytest -q` before commit.

- [ ] **Step 5: Commit**

```bash
git add src/omf/adapters/factory.py src/omf/tui.py tests/adapters/test_http_adapters.py DEVELOPERS.md
git commit -m "chore: drop adapters.factory re-export"
```

---

### Task 2: Drop `checks_for`, `mitigation_for`, and dict catalog text

**Files:**
- Modify: `src/omf/baseline/loader.py`
- Modify: `src/omf/baseline/__init__.py`
- Modify: `src/omf/tui.py` (import `load_catalog` only)
- Modify: `src/omf/pipeline.py:14,61`
- Modify: `src/omf/agent/report.py` (use `check.mitigation`)
- Modify: `src/omf/agent/tools.py` (use `check.mitigation` until Task 7 inlines it)
- Modify: `tests/test_catalog.py`, `tests/test_runner.py`, `tests/test_evaluators_mikrotik_review.py`, `tests/test_evaluators_fortinet_lifecycle.py`

**Interfaces:**
- Consumes: `load_catalog(vendor: str | None = None) -> tuple[CheckDef, ...]`
- Produces: `CheckDef.mitigation: str` and `CheckDef.description: str` always from YAML strings. `load_catalog(None)` merge stays (tests: 63 unique ids).

- [ ] **Step 1: Rewrite description load to strings only**

In `loader.py` replace `_catalog_text` and the mitigation dict branch:

```python
def _one_line(value: object) -> str:
    return " ".join(str(value or "").split())
```

In `load_catalog` for each entry:

```python
checks.append(
    CheckDef(
        id=entry["id"],
        title=entry["title"],
        severity=entry["severity"],
        needs=tuple(entry["needs"]),
        evaluator=entry["evaluator"],
        params=dict(entry.get("params") or {}),
        mitigation=str(entry.get("mitigation") or ""),
        description=_one_line(entry.get("description")),
    )
)
```

Delete `checks_for` and `mitigation_for`. `__all__` becomes `["CheckDef", "load_catalog", "load_profile", "resolve_params"]`.

- [ ] **Step 2: Point production callers at `load_catalog` / `check.mitigation`**

`pipeline.py`:

```python
from omf.baseline.loader import load_catalog
# ...
checks = load_catalog(session.vendor)
```

`tui.py`: drop `checks_for`; `checks = load_catalog(session.vendor)`.

`report.py`: delete `mitigation_for` import. Both call sites:

```python
parts.extend(_format_mitigation(check.mitigation))
```

`tools.py` `get_mitigation` (still present until Task 7):

```python
return check.mitigation
```

- [ ] **Step 3: Retarget tests**

`tests/test_catalog.py`: `from omf.baseline.loader import load_catalog, resolve_params`

Replace every `checks_for("mikrotik")` with `load_catalog("mikrotik")` (same for fortinet).

Replace `mitigation_for(check, "mikrotik")` with `check.mitigation`.

`test_mitigation_falls_back_to_generic`:

```python
def test_mitigation_is_nonempty():
    check = next(c for c in load_catalog("mikrotik") if c.id == "FW-SYS-001")
    assert check.mitigation
```

`test_mikrotik_sys002_mitigation_is_auditor_owned`:

```python
text = next(c for c in load_catalog("mikrotik") if c.id == "FW-SYS-002").mitigation
assert "check-for-updates" not in text
```

The two `assert "set admintimeout" in mitigation_for(ft, "fortinet")` lines become `assert "set admintimeout" in ft.mitigation`.

Same `load_catalog` swap in `test_runner.py`, `test_evaluators_mikrotik_review.py`, `test_evaluators_fortinet_lifecycle.py`.

`baseline/__init__.py`:

```python
from omf.baseline.loader import CheckDef, load_catalog, load_profile, resolve_params

__all__ = ["CheckDef", "load_catalog", "load_profile", "resolve_params"]
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_catalog.py tests/test_runner.py tests/test_pipeline.py tests/test_report.py -q`
Expected: PASS

Then full `uv run pytest -q` before commit.

- [ ] **Step 5: Commit**

```bash
git commit -m "refactor: drop catalog loader aliases and dict catalog text"
```

---

### Task 3: Delete `wrap_report`

**Files:**
- Modify: `src/omf/agent/report.py:315-343`
- Modify: `src/omf/agent/__init__.py`
- Modify: `tests/test_report.py`
- Modify: `tests/test_html_report.py`

**Interfaces:**
- Consumes: `render_html_report(body, *, findings, vendor, url, started_at, version, language) -> str`
- Produces: `finalize_report(body, redactor, *, findings, vendor, url, started_at, version, language) -> str`

- [ ] **Step 1: Point tests at `render_html_report`**

`tests/test_report.py` — import `render_html_report` from `omf.agent.html`. Replace `wrap_report(...)` in `test_wrap_inserts_localized_header_with_author_date_target` and `test_wrap_english_title` with `render_html_report(...)`. Same kwargs (pass `findings=[]`).

`tests/test_html_report.py` helper `_wrap` must call `render_html_report` with the same kwargs `wrap_report` used. Keep `finalize_report` tests unchanged.

- [ ] **Step 2: Run those tests (still pass via wrap_report until deleted)**

Run: `uv run pytest tests/test_report.py tests/test_html_report.py -q`
Expected: PASS

- [ ] **Step 3: Delete `wrap_report`; call HTML from `finalize_report`**

```python
def finalize_report(
    body: str,
    redactor: Redactor,
    *,
    findings: Sequence[CheckResult],
    vendor: str,
    url: str,
    started_at: datetime,
    version: str,
    language: str,
) -> str:
    return render_html_report(
        redactor.destokenize(body),
        findings=findings,
        vendor=vendor,
        url=url,
        started_at=started_at,
        version=version,
        language=language,
    )
```

Delete `**wrap_kwargs`. `pipeline.py` already passes those kwargs by name — no change.

`agent/__init__.py`:

```python
from omf.agent.report import finalize_report, skeleton_body

__all__ = ["finalize_report", "skeleton_body"]
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_report.py tests/test_html_report.py tests/test_pipeline.py -q`
Expected: PASS

Then full `uv run pytest -q` before commit.

- [ ] **Step 5: Commit**

```bash
git commit -m "refactor: finalize_report calls render_html_report directly"
```

---

### Task 4: Delete `banner_enabled`

**Files:**
- Modify: `src/omf/baseline/vendors/fortinet/catalog.yaml` FW-ADM-004 and FW-ADM-005 (`evaluator: flag_enabled`)
- Modify: `src/omf/baseline/evaluators/admin.py` (delete `banner_enabled`)
- Modify: `src/omf/baseline/evaluators/__init__.py` (import + REGISTRY)
- Modify: `tests/test_evaluators_fortinet_l1.py`

**Interfaces:**
- Consumes: `flag_enabled(evidence, params, vendor)` with required `params["field"]`
- Produces: catalogs FW-ADM-004 / FW-ADM-005 use `evaluator: flag_enabled` and keep `params.field`

- [ ] **Step 1: Failing catalog assertion**

Add to `tests/test_catalog.py`:

```python
def test_no_banner_enabled_evaluator():
    from omf.baseline.evaluators import REGISTRY
    assert "banner_enabled" not in REGISTRY
    for check in load_catalog("fortinet"):
        assert check.evaluator != "banner_enabled", check.id
```

Run: `uv run pytest tests/test_catalog.py::test_no_banner_enabled_evaluator -q`
Expected: FAIL (`banner_enabled` still registered)

- [ ] **Step 2: YAML + code**

Fortinet catalog FW-ADM-004 and FW-ADM-005: `evaluator: flag_enabled` (params.field already set).

Delete `banner_enabled` from `admin.py`.

`evaluators/__init__.py`: remove it from the import list and from `REGISTRY`.

`test_evaluators_fortinet_l1.py`: import `flag_enabled` only; `test_pre_login_banner_fail_when_disabled` calls `flag_enabled(...)`.

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/test_catalog.py tests/test_evaluators_fortinet_l1.py tests/test_evaluators.py -q`
Expected: PASS

Then full `uv run pytest -q` before commit.

- [ ] **Step 4: Commit**

```bash
git commit -m "refactor: use flag_enabled for Fortinet login banners"
```

---

### Task 5: Empty unused barrels and drop the TUI `tool` event

**Files:**
- Modify: `src/omf/adapters/__init__.py`
- Modify: `src/omf/agent/__init__.py` (already slimmed in Task 3)
- Modify: `src/omf/tui.py` `_handle_llm`
- Delete test: `tests/test_live_state.py::test_llm_tool_event_does_not_change_narrative`

**Interfaces:**
- Produces: `_LiveState._handle_llm` ignores unknown statuses by falling through to the status map; no special `tool` branch.

- [ ] **Step 1: Barrels**

`adapters/__init__.py`:

```python
"""Vendor HTTP adapters. Normalize to frozen capability models. Read-only."""
```

Keep `agent/__init__.py` as after Task 3. Keep `baseline/__init__.py` as after Task 2. Do **not** slim `schema/__init__.py` (`loader.py` imports `Severity` from `omf.schema`).

- [ ] **Step 2: TUI**

In `_handle_llm`, delete:

```python
        if status == "tool":
            return
```

Delete `test_llm_tool_event_does_not_change_narrative` entirely.

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/test_live_state.py tests/test_llm_boundary.py -q`
Expected: PASS (`test_run_analysis_one_request_no_tool_events` still asserts no `status=="tool"` events)

Then full `uv run pytest -q` before commit.

- [ ] **Step 4: Commit**

```bash
git commit -m "chore: drop unused package barrels and LLM tool-event branch"
```

---

### Checkpoint: Phase 1

- [ ] `uv run pytest -q` — all green
- [ ] `rg -n "factory|checks_for|mitigation_for|wrap_report|banner_enabled" src tests DEVELOPERS.md AGENTS.md` — no production hits (test names mentioning tools in `test_no_function_tool_helpers` may remain until Task 7)

---

## Phase 2 — Local duplicates

### Task 6: One fail-section builder for skeleton and narrative

**Files:**
- Modify: `src/omf/agent/report.py`

**Interfaces:**
- Consumes: `list[CheckResult]`, `tuple[CheckDef, ...]`, optional title/description overlays
- Produces: `skeleton_body` and `narrative_body` still return the same Markdown. `narrative_body` still accepts `Sequence[CheckResult] | Sequence[dict]` (keep `_to_result`). Evidence tables still built from the findings passed in (redacted dicts on the LLM path). `report.redacted.md` stays tokenized.

- [ ] **Step 1: Extract helper (behavior-identical)**

Replace the duplicated loop in `skeleton_body` / `narrative_body` with:

```python
def _fail_sections(
    fails: list[CheckResult],
    by_id: dict[str, CheckDef],
    *,
    titles: dict[str, str] | None = None,
    descriptions: dict[str, str] | None = None,
) -> list[str]:
    title_overlay = titles or {}
    desc_overlay = descriptions or {}
    parts: list[str] = []
    for finding in fails:
        check = by_id.get(finding.check_id)
        title = title_overlay.get(finding.check_id) or (check.title if check else "")
        desc = desc_overlay.get(finding.check_id) or (
            check.description.strip()
            if check is not None and check.description.strip()
            else finding.diagnostic
        )
        parts.append(f"### {finding.check_id} — {title}")
        parts.append("")
        parts.append(f"- **Severity:** {finding.severity}")
        parts.append(f"- **Description:** {desc}")
        parts.extend(_format_evidence(finding.observed))
        if check is not None:
            parts.extend(_format_mitigation(check.mitigation))
        parts.append("")
    return parts
```

`skeleton_body` after the fail table uses `*_fail_sections(fails, by_id)`.

`narrative_body` builds overlays then uses `*_fail_sections(fails, by_id, titles=titles, descriptions=descriptions)`.

Keep `_vuln_title` / `_vuln_description` / `_to_result`.

- [ ] **Step 2: Run tests**

Run: `uv run pytest tests/test_report.py tests/test_html_report.py -q`
Expected: PASS with **no assertion changes**

Then full `uv run pytest -q` before commit.

- [ ] **Step 3: Commit**

```bash
git commit -m "refactor: share fail-section Markdown between skeleton and narrative"
```

---

### Task 7: Inline `fail_pack`; drop tool-era helpers

**Files:**
- Modify: `src/omf/agent/tools.py`
- Modify: `tests/test_llm_boundary.py`
- Modify: `src/omf/agent/llm.py` (`_CATALOG_FIELDS` — keep `description` skip; drop `mitigation` from pack)

**Interfaces:**
- Consumes: `AnalysisContext(findings, checks, vendor, language, transcript="")`
- Produces: `fail_pack(ctx) -> list[dict]` (fails only, severity-sorted, lists capped at 12, `description` from catalog, **no** `mitigation` key). `status_counts(ctx) -> dict[str, int]`. No `get_finding` / `get_mitigation`.

- [ ] **Step 1: Rewrite `test_fail_pack_*` and drop helper tests**

Replace `test_get_finding_caps_long_observed_lists`, `test_tools_return_redacted_only`, `test_get_finding_includes_catalog_description`, `test_get_mitigation_returns_catalog_text` with pack-level tests. Cap stays 12. `mitigation` must not be in pack rows. Keep `description`.

Keep `test_fail_pack_is_fails_only_and_capped` but assert `"mitigation" not in pack[0]`.

Keep `test_no_function_tool_helpers`; add:

```python
    assert not hasattr(tools, "get_finding")
    assert not hasattr(tools, "get_mitigation")
```

- [ ] **Step 2: Implement `tools.py`**

```python
def fail_pack(ctx: AnalysisContext) -> list[dict]:
    by_id = {check.id: check for check in ctx.checks}
    fails = [finding for finding in ctx.findings if finding.get("status") == "fail"]
    fails.sort(
        key=lambda finding: (
            _SEV_ORDER.get(str(finding.get("severity")), 9),
            str(finding.get("check_id")),
        )
    )
    pack: list[dict] = []
    for finding in fails:
        check_id = finding.get("check_id")
        if not isinstance(check_id, str):
            continue
        row = _cap_for_model(finding)
        if not isinstance(row, dict):
            continue
        check = by_id.get(check_id)
        if check is not None and check.description.strip():
            row["description"] = check.description
        pack.append(row)
    return pack
```

Delete `get_finding` and `get_mitigation`. Keep `_cap_for_model` and `status_counts`.

`llm.py`: `_CATALOG_FIELDS = frozenset({"description"})`

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/test_llm_boundary.py tests/test_report.py -q`
Expected: PASS. Catalog policy tokens (`0.0.0.0/0`) and FortiGuard anycast still appear via **description**.

Then full `uv run pytest -q` before commit.

- [ ] **Step 4: Commit**

```bash
git commit -m "refactor: inline fail_pack and stop sending mitigations to the model"
```

---

### Task 8: Single walk in `forti_ha`

**Files:**
- Modify: `src/omf/adapters/fortinet.py` function `forti_ha` (or `src/omf/adapters/fortinet/normalize.py` after Task 10 — this task runs before Task 10, so edit `fortinet.py`)
- Test: `tests/adapters/test_fortinet_normalize.py` (existing HA tests)

**Interfaces:**
- Consumes: FortiOS HA raw (dict or list `ha-mgmt-interfaces`)
- Produces: `HaConfig` with de-duplicated `ha_mgmt_interfaces`; secrets still dropped via `_drop_secrets`

- [ ] **Step 1: Run existing HA tests (baseline)**

Run: `uv run pytest tests/adapters/test_fortinet_normalize.py -q -k ha`
Expected: PASS

- [ ] **Step 2: Replace the double loop**

```python
def forti_ha(raw: object) -> HaConfig:
    item = _as_record(_drop_secrets(raw))
    monitors = _tokens(item.get("monitor"))
    mgmt = item.get("ha-mgmt-interfaces")
    entries = _as_records(mgmt if not isinstance(mgmt, dict) else [mgmt])
    ifaces: list[str] = []
    for entry in entries:
        name = entry.get("interface") or entry.get("name")
        if name not in (None, ""):
            ifaces.append(str(name))
    mode = str(item.get("mode") or "standalone").strip().lower()
    return HaConfig(
        mode=mode,
        monitor_interfaces=monitors,
        ha_mgmt_status=_as_bool(item.get("ha-mgmt-status"), default=False),
        ha_mgmt_interfaces=tuple(dict.fromkeys(ifaces)),
    )
```

- [ ] **Step 3: Re-run HA + HTTP adapter tests**

Run: `uv run pytest tests/adapters/test_fortinet_normalize.py tests/adapters/test_http_adapters.py -q`
Expected: PASS

Then full `uv run pytest -q` before commit.

- [ ] **Step 4: Commit**

```bash
git commit -m "fix: walk FortiOS ha-mgmt-interfaces once"
```

---

### Task 9: `Session.report_mode` instead of inverted `skip_llm`

**Files:**
- Modify: `src/omf/session.py`
- Modify: `src/omf/tui.py` (`_prompt_session`, `_remember_target`, `_connect_with_retry`, `run`)
- Modify: `src/omf/pipeline.py` (`skip_llm` kwarg → `session.report_mode == "eval"`)
- Modify: `tests/test_session.py`, `tests/test_tui_session.py`, `tests/test_pipeline.py`, `tests/test_config.py`

**Interfaces:**
- Consumes: prefs `last_report_mode: Literal["eval","llm"] | None`
- Produces: `Session.report_mode: Literal["eval","llm"] = "llm"` (default keeps current `skip_llm=False`). `run_audit(..., skip_llm=)` **removed**. Evaluation-only still forces `report_language = "en"`.

- [ ] **Step 1: Extend Session (default keeps old tests compiling)**

```python
@dataclass
class Session:
    vendor: str
    url: str
    username: str
    password: str
    token: str
    verify_tls: bool
    report_language: Literal["ca", "es", "en"]
    report_mode: Literal["eval", "llm"] = "llm"
```

Add to `tests/test_session.py`:

```python
def test_default_report_mode_is_llm():
    s = Session("mikrotik", "https://x", "", "", "", True, "en")
    assert s.report_mode == "llm"
```

- [ ] **Step 2: Pipeline**

Remove `skip_llm` parameter. Inside `run_audit` / `_analysis_body`:

```python
skip_llm = session.report_mode == "eval"
report_language = "en" if skip_llm else session.report_language
```

Keep the same skeleton vs LLM branch and event `detail`: `"evaluation only"` vs `"LLM not configured"`.

- [ ] **Step 3: TUI**

`_prompt_report_mode` returns `"eval"` | `"llm"` (not bool).

`_prompt_session` returns `Session` only (drop the bool). Set `report_mode` on the Session. Language still `"en"` when mode is `"eval"`.

`_remember_target(prefs, session)` — no `skip_llm`:

```python
    if session.report_mode == "llm":
        prefs.default_report_language = session.report_language
    prefs.last_report_mode = session.report_mode
```

`run_audit(..., skip_probe=True)` only.

- [ ] **Step 4: Tests**

`test_tui_session.py`: unpack `session = _prompt_session(...)`; assert `session.report_mode`. `_prompt_report_mode(...)` now returns `"eval"` / `"llm"`.

`test_pipeline.py`: replace `skip_llm=True` with `report_mode="eval"` on the Session.

`test_config.py` `_remember_target(prefs, session)` with `session.report_mode = "eval"`.

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/test_session.py tests/test_tui_session.py tests/test_pipeline.py tests/test_config.py -q`
Expected: PASS

Then full `uv run pytest -q` before commit.

- [ ] **Step 6: Commit**

```bash
git commit -m "refactor: store report_mode on Session instead of skip_llm"
```

---

### Checkpoint: Phase 2

- [ ] `uv run pytest -q`
- [ ] Confirm LLM payload in `test_llm_boundary.py` still has no URL/password/`raw`/`token_map`
- [ ] Confirm `meta.json` tests still forbid `url`

---

## Phase 3 — Structure and LLM stack

### Task 10: Split Fortinet adapter into a package (move-only)

**Files:**
- Create: `src/omf/adapters/fortinet/normalize.py` (everything currently above `class FortinetAdapter`: helpers + `forti_*`, including Task 8 `forti_ha`)
- Create: `src/omf/adapters/fortinet/adapter.py` (`FortinetAdapter` + HTTP: `_get`, `_request`, login/logout, `last_call`)
- Create: `src/omf/adapters/fortinet/__init__.py` re-exports
- Delete: `src/omf/adapters/fortinet.py`
- No change: `src/omf/vendors.py` import path `from omf.adapters.fortinet import FortinetAdapter`
- No change: `tests/adapters/test_fortinet_normalize.py` imports

**Interfaces:**
- Consumes: same `FortinetAdapter(session, client)` and same `forti_*` signatures
- Produces: `collect` still returns `(Evidence, raw)`. `last_call` still `{method, path, status, ms}` path-only. HA password still stripped before persist. Do **not** add a capability plugin registry; keep the `if capability ==` ladder in `adapter.py`.

- [ ] **Step 1: Run Fortinet tests (baseline)**

Run: `uv run pytest tests/adapters/test_fortinet_normalize.py tests/adapters/test_http_adapters.py -q`
Expected: PASS

- [ ] **Step 2: Create package without changing logic**

`__init__.py` re-exports `FortinetAdapter` and every `forti_*` name tests import today: `forti_admin_settings`, `forti_dns`, `forti_filter`, `forti_ha`, `forti_licenses`, `forti_local_in`, `forti_logging`, `forti_ntp`, `forti_object_usage`, `forti_services`, `forti_snmp`, `forti_system`, `forti_unwrap`, `forti_users`, `forti_utm`, `forti_zones`.

Move functions by cut-paste. `adapter.py` imports normalizers from `.normalize`. Shared private helpers (`_as_bool`, `_as_records`, `_drop_secrets`, `_TRUE`/`_FALSE`, `_ACTION_MAP`, …) live in `normalize.py` if only normalizers need them; HTTP helpers (`_decode_json`, `_raise_http`, `_normalize_failed`) stay on `adapter.py`. If a helper is used by both, put it in `normalize.py` and import it — do not duplicate.

Delete `src/omf/adapters/fortinet.py` in the same change (cannot coexist with the package).

- [ ] **Step 3: Run tests — no assertion edits**

Run: `uv run pytest tests/adapters/test_fortinet_normalize.py tests/adapters/test_http_adapters.py tests/test_vendors.py -q`
Expected: PASS

Then full `uv run pytest -q` before commit.

- [ ] **Step 4: Commit**

```bash
git commit -m "refactor: split Fortinet adapter into normalize and HTTP modules"
```

---

### Task 11: Replace Pydantic AI with one httpx JSON call

**Files:**
- Modify: `src/omf/agent/llm.py` (rewrite)
- Delete: `src/omf/agent/trace.py`
- Modify: `src/omf/tui.py` `_LiveState` — drop span merge (`_push_span`, `llm_spans`, `status=="span"`)
- Modify: `pyproject.toml` — remove `pydantic-ai` (keep `pydantic>=2.13` and `httpx`)
- Modify: `tests/test_llm_boundary.py` — mock httpx, not `FunctionModel`
- Delete or rewrite: `tests/test_llm_trace.py` (keep secret-strip transcript coverage in `test_llm_boundary.py`)
- Modify: `AGENTS.md` analysis-agent section; `DEVELOPERS.md` “Pydantic AI” sentences
- Run: `uv lock` after pyproject change

**Interfaces:**
- Consumes: `LlmSettings(base_url, api_key, model, api_style)`, `AnalysisContext`, `fail_pack`, `status_counts`, `leak_hits`
- Produces:
  - `run_analysis(ctx, settings, on_event=None) -> str` (Markdown from `narrative_body`)
  - One retry then raise (pipeline already falls back to skeleton)
  - Events: `{phase:"llm", status:"start"|"done"|"fallback"}` — **no** `span`, **no** `tool`
  - `ctx.transcript` = system + user + raw response text with API key stripped
  - **No** `build_agent`. **No** session/`token_map` on any object
  - Timeouts: connect 15s, read 120s (`httpx.Timeout(120.0, connect=15.0)`)

HTTP (OpenAI style, `api_style=="openai"`):

```
POST {base_url}/chat/completions
Authorization: Bearer {api_key}
{"model": ..., "messages": [{"role":"system","content":...},{"role":"user","content":...}],
 "response_format": {"type": "json_object"}}
```

Parse `choices[0].message.content` as JSON → `ReportNarrative.model_validate`.

HTTP (Anthropic style):

```
POST {base_url}/v1/messages
x-api-key: {api_key}
anthropic-version: 2023-06-01
{"model": ..., "max_tokens": 8192, "system": ..., "messages": [{"role":"user","content":...}]}
```

Parse `content[0].text` as JSON → `ReportNarrative`.

If `base_url` already ends with `/chat/completions` or `/v1/messages`, do not append the path twice. Prefer: `url = settings.base_url.rstrip("/")` and if it does not end with the expected suffix, append it.

- [ ] **Step 1: Write failing tests that talk to a fake `_complete`**

Replace FunctionModel helpers. `run_analysis` must call `_complete(settings, system, user)` once on success. Rewrite retry/leak/secret tests against captured `user`/`system` strings. Delete `test_build_agent_has_no_session_attr`; replace with signature check that `run_analysis` has no `session` or `token_map` parameters.

Delete `tests/test_llm_trace.py`. Move transcript API-key strip into `test_llm_boundary.py`.

- [ ] **Step 2: Implement `llm.py`**

Keep `_SYSTEM_PROMPT`, `_prompt_for`, `_user_prompt`, `_noun_line`, `_target_noun` (eager `from omf.vendors import get`). Keep `LlmNotConfigured`, `LlmPayloadLeak`, leak check **before** any HTTP.

`_complete` uses `httpx.Client(timeout=_LLM_TIMEOUT, trust_env=False)` (sync). Never log `Authorization` or the API key. Strip the API key from `ctx.transcript`.

Do not import pydantic-ai or opentelemetry.

- [ ] **Step 3: TUI spans**

Delete `_push_span`, `llm_spans`, `_SPAN_KEEP`. Ignore `status == "span"` with a simple return.

`_llm_panel` body: spinner, model label, elapsed, `no secrets on the wire`. No span lines.

- [ ] **Step 4: Drop dependency**

`pyproject.toml` dependencies: remove `"pydantic-ai>=2.31.1"`. Keep pydantic and httpx.

Run: `uv lock`

AGENTS.md: replace “Pydantic AI” with “one-shot httpx JSON completion”. Same in DEVELOPERS.md. Keep: no function tools, no collect, no session, no `token_map`, one request, `tests/test_llm_boundary.py` still the boundary.

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/test_llm_boundary.py tests/test_live_state.py tests/test_pipeline.py tests/test_report.py -q`
Expected: PASS

Then: `uv run pytest -q`
Expected: PASS (no leftover `pydantic_ai` imports)

- [ ] **Step 6: Commit**

```bash
git commit -m "refactor: replace pydantic-ai with one httpx JSON completion"
```

---

### Checkpoint: Complete

- [ ] `uv run pytest -q`
- [ ] `rg -n "pydantic_ai|opentelemetry|factory|wrap_report|banner_enabled|get_finding|skip_llm" src tests` — empty (except historical comments in this plan)
- [ ] Wheel still ships YAML: `include = ["src/omf/**/*.yaml"]` untouched
- [ ] Invariants: secrets RAM-only; URL only in `report.html`; model sees tokens; adapters GET-only; evaluators pure

---

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Dropping mitigation from the LLM pack changes model prose | Med | Evidence/CLI still stitched locally from catalog; tests keep description in pack |
| Anthropic/OpenAI URL joining wrong | Med | Unit-test `_complete` URL with a fake client; do not hit network |
| Fortinet package split breaks imports | Low | Re-export every `forti_*` tests import today |
| `Session.report_mode` default wrong | Low | Default `"llm"` matches old `skip_llm=False` |
| Root `docs/` gitignore hides the plan | Low | Task 0 negation rules |

## Out of scope

- Shared MikroTik/Fortinet HTTP helper module
- Evaluator dummy-`CheckResult` contract change
- Merging `insecure_services_disabled` / `named_services_disabled`
- Custom HTML/SVG dashboard rewrite
- Splitting `Policy` / `AdminSettings`
- Deleting wizard `parse_vendor` / `parse_language` / `parse_yes_no`
