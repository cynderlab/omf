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

Read-only hardening audit of **perimeter security products** (firewalls and UTM). Connect to the management plane, collect evidence, evaluate a published baseline. Optional AI narrative from **redacted** findings only. Reports land in `./audits/`.

It does not change the target. Findings are a starting point for the auditor, not a certification.

How the code works, and how to add a vendor: **[DEVELOPERS.md](DEVELOPERS.md)**.

| | |
|---|---|
| **Author** | [Pere Casas](mailto:pcasas@cynderlab.com) · [Cynderlab](https://cynderlab.com) |
| **Tested on** | Linux, macOS |

## Supported products

| Product | Status | Access |
|---|---|---|
| MikroTik RouterOS 7+ | Supported | REST, HTTP Basic |
| Fortinet FortiOS | Partial | REST, token or session login |
| pfSense | Coming soon | |
| SonicWall | Coming soon | |

**Supported** — exercised on a live device. **Partial** — adapter and checks exist, less field confidence.

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

The wizard asks vendor, URL, and credentials. Create a dedicated read-only collector first ([Audit account](#audit-account)). TLS verification is off — management certs are usually self-signed. Password and API token stay in RAM and are wiped on exit.

Optional LLM narrative (`ca` | `es` | `en`) — `./.env` or `~/.config/omf/.env`:

```bash
OMF_LLM_BASE_URL=
OMF_LLM_API_KEY=
OMF_LLM_MODEL=
OMF_LLM_API_STYLE=openai    # or anthropic
```

Without LLM env, or if you pick **Evaluation only (no LLM)** in the TUI, you still get collect + evaluate + a skeleton report (English).

Each run writes `./audits/YYYY-MM-DDTHHMMSS-{vendor}/`. Review the folder before you share it. Mitigations in the report are **examples**.

`./omf -v` logs HTTP paths and phases on stderr. No secrets.

## Audit account

Have a privileged admin create a **dedicated collector**. Do not use `admin` / `full` / `super_admin`. Restrict the source IP. Delete the account when the engagement ends.

### MikroTik RouterOS 7+

Enable [`www-ssl`](https://help.mikrotik.com/docs/display/ROS/REST+API). Include `sensitive` so SNMP communities are visible.

```
/ip service set www-ssl disabled=no
/user group add name=omf policy=read,rest-api,sensitive
/user add name=omf group=omf password=<password> address=<auditor-ipv4>/32
```

### Fortinet FortiOS

Prefer an [API token](https://docs.fortinet.com/document/fortigate/7.4.8/administration-guide/399023/rest-api-administrator). The interface OMF reaches must allow HTTPS. Create a [read-only access profile](https://docs.fortinet.com/document/fortigate/7.4.8/cli-reference/309990135/config-system-accprofile) with `scope global`. Do not use `super_admin` or `prof_admin`.

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

## License

**[Elastic License 2.0](LICENSE)** — use, copy, modify, including commercially. You may **not** provide OMF as a hosted or managed service.
