# omf

OH MY FIREWALL — read-only firewall audit agent (MikroTik RouterOS 7+ and Fortinet FortiOS).

## Setup

```bash
# requires https://docs.astral.sh/uv/
./omf install
./omf doctor
cp .env.example .env   # optional; without it you still get findings + a skeleton report
./omf
```

## Commands

| Command | Purpose |
|---|---|
| `./omf` | Audit TUI (English) |
| `./omf install` | `uv sync --all-extras --all-groups` |
| `./omf doctor` | What is missing (never talks to a firewall) |
| `./omf help` | Help |

Firewall credentials are never stored. The model never receives URLs, credentials, raw dumps, or the token map.

See `docs/superpowers/specs/2026-08-18-omf-firewall-audit-agent-design.md`.
