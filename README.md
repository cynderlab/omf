# omf

OH MY FIREWALL — read-only firewall audit agent (MikroTik RouterOS 7+ and Fortinet FortiOS).

Author: Pere Casas · pcasas@cynderlab.com

## Setup

```bash
# requires https://docs.astral.sh/uv/
./omf install          # also creates .env from .env.example if missing
./omf doctor
./omf
```

## Commands

| Command | Purpose |
|---|---|
| `./omf` | Audit TUI (English) |
| `./omf install` | `uv sync` and create `.env` from `.env.example` if missing |
| `./omf doctor` | What is missing (never talks to a firewall) |
| `./omf help` | Help |
| `./omf -v` / `--debug` | DEBUG logs on stderr (no secrets) |

Firewall credentials are never stored. The model never receives URLs, credentials, raw dumps, or the token map.
