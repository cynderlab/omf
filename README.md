<p align="center">
  <img src="assets/banner.jpg" alt="OH MY FORTRESS — read-only perimeter security audit" width="100%">
</p>

<p align="center">
  <img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12+-22d3ee?labelColor=0b1020">
  <img alt="Version 1.0.1" src="https://img.shields.io/badge/version-1.0.1-22d3ee?labelColor=0b1020">
  <img alt="License Elastic-2.0" src="https://img.shields.io/badge/license-Elastic--2.0-22d3ee?labelColor=0b1020">
  <img alt="uv" src="https://img.shields.io/badge/tooling-uv-e879f9?labelColor=0b1020">
</p>

# OH MY FORTRESS

Read-only hardening audit of **perimeter security products** (firewalls and UTM) for a consultant auditor.

Connect once to the management plane. Collect evidence. Evaluate a **published baseline**. An optional AI agent writes the narrative from **redacted** findings only. Output lands under `./audits/`.

It does not change the target, does not SSH, and does not let the model pick checks. If the agent is missing or fails, you still get collect + evaluate + a skeleton report. The TUI also offers **Evaluation only (no LLM)**.

Treat findings as a starting point for the auditor, not a finished certification.

How the code works, and how to add a vendor: **[DEVELOPERS.md](DEVELOPERS.md)**.

| | |
|---|---|
| **Version** | 1.0.1 |
| **Author** | [Pere Casas](mailto:pcasas@cynderlab.com) · [Cynderlab](https://cynderlab.com) |
| **License** | [Elastic License 2.0](LICENSE) — use, copy, modify; no hosted or managed service |
| **Stack** | Python 3.12+ · [uv](https://docs.astral.sh/uv/) only |

## Supported products

Perimeter firewalls and UTM only. Not servers, not SaaS, not endpoints.

| Product | Status | Access |
|---|---|---|
| MikroTik RouterOS 7+ | Supported | REST (`/rest/...`, HTTP Basic) |
| Fortinet FortiOS | Partial | REST (`/api/v2/...`, token or session login) |
| pfSense | Coming soon | |
| SonicWall | Coming soon | |

**Supported** means the catalog has been exercised against a live firewall. **Partial** means the adapter and checks exist but are not at the same confidence. **Coming soon** is a perimeter product planned for a later release, not in this tree.

## Getting started

You need [uv](https://docs.astral.sh/uv/) and Python 3.12+.

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
git clone <this-repo> omf
cd omf
./omf install
./omf doctor    # optional; never talks to a target
./omf
```

The wizard asks vendor, URL, and credentials. Evaluation-only reports are English. LLM narrative also asks report language (`ca` | `es` | `en`). TLS verification is off for firewall packs — management certs are usually self-signed. Create a dedicated read-only collector first ([Audit account](#audit-account)).

**Password and API token stay in RAM.** They are wiped on every exit. The target URL is written only in `report.html` and optional prefs `last_url`.

Optional written narrative — set in `./.env` or `~/.config/omf/.env`:

```bash
OMF_LLM_BASE_URL=
OMF_LLM_API_KEY=
OMF_LLM_MODEL=
OMF_LLM_API_STYLE=openai    # or anthropic
```

`./omf doctor` **warns** (exit 0) if LLM env is missing. Collect and evaluate still work. Choose **Evaluation only (no LLM)** in the TUI to skip the model even when env is set.

## Audit account

OMF only `GET`s. It does not create users and does not change device config. Have a privileged admin create a **dedicated collector** before you run the TUI. Do not use `admin` / `full` / `super_admin`.

### MikroTik RouterOS 7+

REST is HTTP Basic on `www-ssl` (`https://<ip>/rest/...`). Enable [`www-ssl`](https://help.mikrotik.com/docs/display/ROS/REST+API). Make a custom group; include `sensitive` so SNMP communities are visible.

```
/ip service set www-ssl disabled=no
/user group add name=omf policy=read,rest-api,sensitive
/user add name=omf group=omf password=<password> address=<auditor-ipv4>/32
```

TUI: vendor MikroTik, URL `https://<ip>`, username `omf`, password.

### Fortinet FortiOS

Prefer an [API token](https://docs.fortinet.com/document/fortigate/7.4.8/administration-guide/399023/rest-api-administrator). Session login is a normal admin user. The interface OMF reaches must allow HTTPS. Create a [read-only access profile](https://docs.fortinet.com/document/fortigate/7.4.8/cli-reference/309990135/config-system-accprofile). `scope global` is required. Do not use `super_admin` or `prof_admin`.

```
config system accprofile
    edit "omf-readonly"
        set comments "OMF GET-only collector"
        set scope global
        set sysgrp read
        set netgrp read
        set fwgrp read
        set loggrp read
        set utmgrp read
        set ftviewgrp read
        set secfabgrp none
        set authgrp none
        set vpngrp none
        set wanoptgrp none
        set wifi none
    next
end
```

**API token** (TUI: Authentication → API token):

```
config system api-user
    edit "omf"
        set comments "OMF GET-only collector"
        set accprofile "omf-readonly"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost <auditor-ipv4> 255.255.255.255
            next
        end
    next
end
execute api-user generate-key omf
```

**Username and password** (TUI: Authentication → Username and password):

```
config system admin
    edit "omf"
        set comments "OMF GET-only collector"
        set accprofile "omf-readonly"
        set vdom "root"
        set trusthost1 <auditor-ipv4> 255.255.255.255
        set password <password>
    next
end
```

You own this change on the device. Restrict the source IP. Delete the collector when the engagement ends.

## Commands

| Command | Purpose |
|---|---|
| `./omf` | Audit TUI |
| `./omf install` | Sync deps; create `.env` from `.env.example` if missing |
| `./omf doctor` | Required vs warn. Never talks to a target. |
| `./omf help` | Help |
| `./omf -v` | DEBUG on stderr: HTTP **paths** and phases. No secrets. |

There is no `audit` / `report` subcommand. The TUI is the product.

Each run writes `./audits/YYYY-MM-DDTHHMMSS-{vendor}/` (gitignored). Review the folder before you share it. Mitigations in the report are **examples**. You own any change on the target.

## Privacy

- Password and API token are never written to disk, logs, or LLM payloads.
- Adapters are GET only (plus FortiOS login/logout cookies when there is no token).
- The model sees only redacted findings. Identifiers become tokens (`[IP_n]`, `[USER_n]`, …). Destokenize happens locally.

## License

**[Elastic License 2.0](LICENSE)** — use, copy, modify, including commercially. You may **not** provide OMF as a hosted or managed service.

See [LICENSE](LICENSE) for the full terms.

## Author

**Pere Casas** · pcasas@cynderlab.com · Cynderlab
