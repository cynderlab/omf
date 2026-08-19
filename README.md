```
  ██████╗ ███╗   ███╗███████╗
 ██╔═══██╗████╗ ████║██╔════╝
 ██║   ██║██╔████╔██║█████╗
 ██║   ██║██║╚██╔╝██║██╔══╝
 ╚██████╔╝██║ ╚═╝ ██║██║
  ╚═════╝ ╚═╝     ╚═╝╚═╝
```

# OH MY FIREWALL

**Beta.** Read-only multi-vendor firewall audit for a consultant auditor.

Connect once. Collect evidence. Evaluate a fixed baseline. Write Markdown under `./audits/`.

The brand is transparency: you see every step. The model never sees secrets or identifiers.

| | |
|---|---|
| **Version** | 0.1.0 **beta** |
| **Author** | [Pere Casas](mailto:pcasas@cynderlab.com) · [Cynderlab](https://cynderlab.com) |
| **Contact** | pcasas@cynderlab.com |
| **License** | [PolyForm Noncommercial 1.0.0](LICENSE) — free to use, no commercial benefit, credit the original |
| **Stack** | Python 3.12+ · [uv](https://docs.astral.sh/uv/) only |

## What it does

OMF is a **read-only** REST auditor. It does **not** SSH, does not change device config, and does not pick checks with an LLM. The runner plans from a YAML catalog, collects each capability once, evaluates pure functions, then (optionally) asks a model to write the narrative from **redacted** findings only.

If the LLM is missing or fails, you still get collect + evaluate + a deterministic skeleton report.

This is **beta** software. Treat findings as a starting point for the auditor, not a finished certification.

## Supported vendors

| Vendor | Status | Access |
|---|---|---|
| MikroTik RouterOS 7+ | Supported | REST (`/rest/...`, HTTP Basic) |
| Fortinet FortiOS | Partial | REST (`/api/v2/...`, token or session login) |
| pfSense | Coming soon | |
| SonicWall | Coming soon | |

**Supported** means the catalog has been exercised against a live device. **Partial** means the adapter and checks exist but are not at the same confidence. **Coming soon** is not in this release.

## Getting started

You need [uv](https://docs.astral.sh/uv/) and Python 3.12+.

```bash
# 1. Install uv if you do not have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Clone and enter the repo
git clone <this-repo> omf
cd omf

# 3. Sync dependencies (and create .env from .env.example if missing)
./omf install

# 4. Optional: sanity check. Never talks to a firewall.
./omf doctor

# 5. Run the TUI (English prompts; report body ca | es | en)
./omf
```

The wizard asks vendor, URL, username, password (Fortinet: token or password), and report language. TLS verification is off — management certs are usually self-signed. A dim notice is shown.

**Firewall password and API token stay in RAM.** They are wiped on every exit path (`finally`). Username may be remembered as a wizard default. The target URL is written only in `report.md` and optional prefs `last_url`.

## Commands

| Command | Purpose |
|---|---|
| `./omf` | Audit TUI |
| `./omf install` | `uv sync --all-extras --all-groups`; create `.env` from `.env.example` if missing |
| `./omf doctor` | Required vs warn. Exit 1 only on required failures. Never talks to a firewall. |
| `./omf help` | Help |
| `./omf -v` / `--debug` | DEBUG on stderr: HTTP **paths** and phases. No passwords, tokens, or `Authorization`. |

There is no `audit` / `report` subcommand. The TUI is the product.

Tests (no live firewall):

```bash
uv run pytest
```

## Optional LLM (narrative)

Collect and evaluate work without a model. For a written report, set these in `./.env` or `~/.config/omf/.env`:

```bash
OMF_LLM_BASE_URL=
OMF_LLM_API_KEY=
OMF_LLM_MODEL=
OMF_LLM_API_STYLE=openai    # or anthropic
```

`./omf doctor` **warns** (exit 0) if LLM env is missing. One LLM retry, then the skeleton report.

The model sees only redacted findings, redacted evidence, and catalog mitigations. It never sees `raw/`, `token_map.json`, credentials, or the target URL.

## What you get

Each run writes `./audits/YYYY-MM-DDTHHMMSS-{vendor}/` (gitignored):

| File | Contents |
|---|---|
| `report.md` | Header (vendor, **URL from RAM**, date) + destokenized narrative |
| `findings.json` | Pass / fail / error / skipped + diagnostics |
| `evidence/` | Normalized payloads |
| `raw/` | Vendor JSON — **local only, unredacted** |
| `redacted/` | What the model is allowed to read |
| `token_map.json` | Local destokenize map — **never sent to the model** |
| `events.jsonl` | Paths and phases, no host, no secrets |
| `meta.json` | Session meta — no URL, no credentials |

Review the folder before you share it. Mitigations in the report are **examples**. You own any change on the device.

## Privacy (non-negotiable)

- Password and API token are never written to disk, logs, `meta.json`, events, `config.yaml`, `.env`, or LLM payloads.
- Adapters are GET only (plus FortiOS login/logout cookies when there is no token).
- Evaluators are pure: `(evidence, params, vendor) → result`. No HTTP, no env, no secrets.
- Identifiers in model input are tokens (`[IP_n]`, `[USER_n]`, …). Destokenize happens locally after the model returns.

## Scope

In: REST collection, Markdown reports, English TUI.

Out: SSH, RouterOS 6, PDF/HTML/DOCX, mutating the firewall. Vendors not marked **Supported** or **Partial** above are not collected.

## License

**[PolyForm Noncommercial License 1.0.0](LICENSE)**

You may use, study, and share OMF for **non-commercial** purposes (personal study, research, education, public-interest work). You may **not** sell it, run it as a paid service, or otherwise profit from it.

If you publish a fork or other derivative work, you **must credit the original**:

> OH MY FIREWALL (omf) — Copyright 2026 Pere Casas (pcasas@cynderlab.com)

Keep this README notice and the `LICENSE` file with any copy you distribute.

Commercial use requires a separate permission from the author.

## Author

**Pere Casas**  
pcasas@cynderlab.com  
Cynderlab
