import json
from pathlib import Path
import httpx
from omf.session import Session
from omf.adapters.mikrotik import MikrotikAdapter
from omf.adapters.fortinet import FortinetAdapter
from omf.adapters.base import ProbeError, CollectError
from omf.adapters.factory import build_adapter
from omf.schema.capabilities import CORE_CAPABILITIES, FORTINET_EXTRAS, MIKROTIK_EXTRAS

MT = Path(__file__).parent / "fixtures" / "mikrotik"
FT = Path(__file__).parent / "fixtures" / "fortinet"


def mt_session() -> Session:
    return Session("mikrotik", "https://192.0.2.1", "u", "p", "", True, "en")


def ft_session(token: str = "tok") -> Session:
    return Session("fortinet", "https://192.0.2.2", "u", "p", token, True, "en")


def load_mt(name: str):
    return json.loads((MT / name).read_text())


def load_ft(name: str):
    return json.loads((FT / name).read_text())


def test_mikrotik_probe_ok_and_collect_users():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization", "").lower().startswith("basic")
        assert request.url.host == "192.0.2.1"
        if request.url.path == "/rest/system/identity":
            return httpx.Response(200, json={"name": "fw"})
        if request.url.path == "/rest/user":
            return httpx.Response(200, json=json.loads((MT / "user.json").read_text()))
        return httpx.Response(404, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.1")
    ad = MikrotikAdapter(mt_session(), client)
    ad.probe()
    ev, raw = ad.collect("users")
    assert ev.payload.users[0].name == "admin"
    assert isinstance(raw, list)
    client.close()


def test_mikrotik_probe_401():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": 401})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.1")
    ad = MikrotikAdapter(mt_session(), client)
    try:
        ad.probe()
        raise AssertionError("should have failed")
    except ProbeError as exc:
        assert exc.status == 401
        assert exc.path == "/rest/system/identity"
    client.close()


def test_fortinet_bearer_no_logincheck():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        assert request.headers.get("authorization") == "Bearer tok"
        if request.url.path == "/api/v2/monitor/system/status":
            return httpx.Response(200, json={"version": "v7.4.4"})
        return httpx.Response(404)

    session = Session("fortinet", "https://192.0.2.2", "u", "p", "tok", True, "en")
    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.2")
    ad = FortinetAdapter(session, client)
    ad.probe()
    assert "/logincheck" not in seen
    client.close()


def test_last_call_path_only_after_each_http():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/rest/system/identity":
            return httpx.Response(200, json={"name": "fw"})
        if request.url.path == "/rest/user":
            return httpx.Response(200, json=load_mt("user.json"))
        return httpx.Response(404, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.1")
    ad = MikrotikAdapter(mt_session(), client)
    ad.probe()
    assert ad.last_call["method"] == "GET"
    assert ad.last_call["path"] == "/rest/system/identity"
    assert ad.last_call["status"] == 200
    assert isinstance(ad.last_call["ms"], int)
    assert ad.last_call["ms"] >= 0
    assert "url" not in ad.last_call
    assert "host" not in ad.last_call
    ad.collect("users")
    assert ad.last_call["method"] == "GET"
    assert ad.last_call["path"] == "/rest/user"
    assert ad.last_call["status"] == 200
    client.close()


def test_mikrotik_ignores_token():
    session = Session("mikrotik", "https://192.0.2.1", "u", "p", "tok", True, "en")

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        assert auth.lower().startswith("basic")
        assert "bearer" not in auth.lower()
        return httpx.Response(200, json={"name": "fw"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.1")
    ad = MikrotikAdapter(session, client)
    ad.probe()
    client.close()


def test_mikrotik_collect_users_html_is_collect_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="<html><body>login</body></html>",
            headers={"content-type": "text/html"},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.1")
    ad = MikrotikAdapter(mt_session(), client)
    try:
        ad.collect("users")
        raise AssertionError("should have failed")
    except CollectError as exc:
        assert exc.capability == "users"
        assert exc.path == "/rest/user"
        assert exc.status == 200
        assert "invalid JSON" in exc.message
    except json.JSONDecodeError as exc:
        raise AssertionError(f"raw JSONDecodeError leaked: {exc}") from exc
    client.close()


def test_mikrotik_collect_non_2xx():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": 500})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.1")
    ad = MikrotikAdapter(mt_session(), client)
    try:
        ad.collect("users")
        raise AssertionError("should have failed")
    except CollectError as exc:
        assert exc.capability == "users"
        assert exc.path == "/rest/user"
        assert exc.status == 500
    assert ad.last_call["path"] == "/rest/user"
    assert ad.last_call["status"] == 500
    client.close()


def test_mikrotik_collect_all_capabilities():
    fixtures = {
        "/rest/user": "user.json",
        "/rest/system/identity": "system_identity.json",
        "/rest/user/settings": "user_settings.json",
        "/rest/system/clock": "system_clock.json",
        "/rest/ip/service": "ip_service.json",
        "/rest/system/ntp/client": "ntp_client.json",
        "/rest/system/ntp/client/servers": "ntp_client_servers.json",
        "/rest/ip/dns": "ip_dns.json",
        "/rest/system/logging": "system_logging.json",
        "/rest/system/logging/action": "system_logging_action.json",
        "/rest/snmp": "snmp.json",
        "/rest/snmp/community": "snmp_community.json",
        "/rest/ip/firewall/filter": "ip_firewall_filter.json",
        "/rest/system/resource": "system_resource.json",
        "/rest/system/routerboard": "system_routerboard.json",
        "/rest/system/package/update": "package_update.json",
        "/rest/ip/neighbor/discovery-settings": "neighbor_discovery.json",
        "/rest/tool/mac-server": "mac_server.json",
        "/rest/tool/mac-server/mac-winbox": "mac_winbox.json",
        "/rest/tool/mac-server/ping": "mac_ping.json",
        "/rest/ip/ssh": "ip_ssh.json",
        "/rest/tool/bandwidth-server": "bandwidth_server.json",
        "/rest/ip/proxy": "ip_proxy.json",
        "/rest/ip/socks": "ip_socks.json",
        "/rest/ip/upnp": "ip_upnp.json",
        "/rest/ip/cloud": "ip_cloud.json",
        "/rest/interface/pptp-server/server": "pptp_server.json",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        name = fixtures.get(request.url.path)
        if name is None:
            return httpx.Response(404, json={})
        return httpx.Response(200, json=load_mt(name))

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.1")
    ad = MikrotikAdapter(mt_session(), client)
    users, raw_users = ad.collect("users")
    assert users.payload.users[0].name == "admin"
    assert isinstance(raw_users, list)
    admin, _ = ad.collect("admin_settings")
    assert admin.payload.hostname == "MikroTik"
    assert admin.payload.idle_timeout_seconds == 600
    assert admin.payload.ssh_strong_crypto is True
    services, _ = ad.collect("services")
    names = {s.name for s in services.payload.services}
    assert names >= {"www", "www-ssl", "bandwidth-server", "pptp", "cloud-ddns"}
    by_name = {s.name: s for s in services.payload.services}
    assert by_name["bandwidth-server"].enabled is False
    assert by_name["pptp"].enabled is False
    ntp, _ = ad.collect("ntp")
    assert ntp.payload.servers == ("1.1.1.1", "2.pool.ntp.org")
    dns, _ = ad.collect("dns")
    assert dns.payload.servers == ("8.8.8.8", "1.1.1.1")
    logging, _ = ad.collect("logging")
    assert logging.payload.local_enabled is True
    snmp, _ = ad.collect("snmp")
    assert snmp.payload.communities[0].name == "public"
    policies, _ = ad.collect("firewall_filter")
    assert policies.payload.policies[0].action == "accept"
    system, _ = ad.collect("system_info")
    assert system.payload.firmware.startswith("7.16")
    assert system.payload.current_firmware == "7.16.1"
    assert system.payload.update_status == "System is already up to date"
    assert system.vendor == "mikrotik"
    assert system.capability == "system_info"
    l2, _ = ad.collect("l2_access")
    assert l2.payload.discover_interface_list == "none"
    assert l2.payload.mac_ping_enabled is False
    client.close()


def test_fortinet_logincheck_then_logout():
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        assert request.headers.get("authorization") is None
        if request.url.path == "/logincheck":
            assert request.method == "POST"
            body = request.content.decode()
            assert "username=u" in body
            assert "secretkey=p" in body
            return httpx.Response(200, text="1")
        if request.url.path == "/api/v2/monitor/system/status":
            return httpx.Response(200, json={"version": "v7.4.4"})
        if request.url.path == "/logout":
            assert request.method == "GET"
            return httpx.Response(200)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.2")
    ad = FortinetAdapter(ft_session(""), client)
    ad.probe()
    assert seen[0] == ("POST", "/logincheck")
    assert ("GET", "/api/v2/monitor/system/status") in seen
    ad.close()
    assert seen[-1] == ("GET", "/logout")
    client.close()


def test_fortinet_bearer_close_skips_logout():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/api/v2/monitor/system/status":
            return httpx.Response(200, json={"version": "v7.4.4"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.2")
    ad = FortinetAdapter(ft_session("tok"), client)
    ad.probe()
    ad.close()
    assert "/logincheck" not in seen
    assert "/logout" not in seen
    client.close()


def test_fortinet_collect_capabilities():
    fixtures = {
        "/api/v2/cmdb/system/admin": "admin.json",
        "/api/v2/cmdb/system/global": "global.json",
        "/api/v2/cmdb/system/password-policy": "password_policy.json",
        "/api/v2/cmdb/system/interface": "interface.json",
        "/api/v2/cmdb/system/ntp": "ntp.json",
        "/api/v2/cmdb/system/dns": "dns.json",
        "/api/v2/cmdb/log.syslogd/setting": "syslogd.json",
        "/api/v2/cmdb/log.fortianalyzer/setting": "fortianalyzer.json",
        "/api/v2/cmdb/log/setting": "log_setting.json",
        "/api/v2/cmdb/system.snmp/community": "snmp_community.json",
        "/api/v2/cmdb/system.snmp/sysinfo": "snmp_sysinfo.json",
        "/api/v2/cmdb/system.snmp/user": "snmp_user.json",
        "/api/v2/cmdb/firewall/policy": "policy.json",
        "/api/v2/cmdb/system/zone": "zone.json",
        "/api/v2/cmdb/firewall/local-in-policy": "local_in_policy.json",
        "/api/v2/cmdb/system/ha": "ha.json",
        "/api/v2/cmdb/dnsfilter/profile": "dnsfilter.json",
        "/api/v2/cmdb/webfilter/profile": "webfilter.json",
        "/api/v2/cmdb/application/list": "application_list.json",
        "/api/v2/cmdb/system/automation-stitch": "automation_stitch.json",
        "/api/v2/monitor/system/status": "status.json",
        "/api/v2/monitor/license/status": "license_status.json",
        "/api/v2/monitor/firewall/policy": "policy_stats.json",
        "/api/v2/cmdb/firewall/address": "address.json",
        "/api/v2/cmdb/firewall/addrgrp": "addrgrp.json",
        "/api/v2/cmdb/firewall.service/custom": "service_custom.json",
        "/api/v2/cmdb/firewall.service/group": "service_group.json",
        "/api/v2/cmdb/firewall/vip": "vip.json",
        "/api/v2/cmdb/firewall/ippool": "ippool.json",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.headers.get("authorization") == "Bearer tok"
        name = fixtures.get(request.url.path)
        if name is None:
            return httpx.Response(404, json={})
        return httpx.Response(200, json=load_ft(name))

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.2")
    ad = FortinetAdapter(ft_session("tok"), client)
    users, raw_users = ad.collect("users")
    assert users.payload.users[0].name == "admin"
    assert users.vendor == "fortinet"
    assert isinstance(raw_users, dict)
    admin, _ = ad.collect("admin_settings")
    assert admin.payload.hostname == "FortiGate"
    assert admin.payload.idle_timeout_seconds == 300
    services, _ = ad.collect("services")
    by_name = {s.name: s for s in services.payload.services}
    assert by_name["https"].enabled is True
    assert by_name["https"].listen == "unknown"
    assert by_name["https"].on_wan is True
    assert by_name["http"].interfaces == ("wan1",)
    assert by_name["https"].interfaces == ("wan1", "lan")
    assert ad.last_call["path"] == "/api/v2/cmdb/system/admin"
    assert "exclude-default-values" not in str(ad.last_call["path"])
    ntp, _ = ad.collect("ntp")
    assert ntp.payload.enabled is True
    dns, _ = ad.collect("dns")
    assert dns.payload.servers[0] == "1.1.1.1"
    logging, _ = ad.collect("logging")
    assert logging.payload.remote_targets
    snmp, _ = ad.collect("snmp")
    assert snmp.payload.communities[0].name == "public"
    policies, _ = ad.collect("firewall_filter")
    assert policies.payload.policies[0].src == ("any",)
    zones, _ = ad.collect("zones")
    assert zones.payload.zones[0].name == "DMZ"
    assert zones.payload.zones[0].intrazone == "allow"
    local_in, _ = ad.collect("local_in")
    assert local_in.payload.policies[0].virtual_patch is False
    ha, raw_ha = ad.collect("ha")
    assert ha.payload.mode == "a-p"
    assert ha.payload.monitor_interfaces == ("port6", "port7")
    assert "super-secret" not in str(raw_ha)
    assert "super-secret" not in str(ha.payload.model_dump())
    utm, _ = ad.collect("utm")
    assert utm.payload.stitches[0].name.lower().startswith("compromised")
    system, _ = ad.collect("system_info")
    assert system.payload.firmware.startswith("v7.4")
    assert system.payload.model == "FortiGate"
    licenses, raw_licenses = ad.collect("licenses")
    by_key = {item.key: item for item in licenses.payload.entitlements}
    assert by_key["forticare"].status == "licensed"
    assert by_key["firmware_updates"].status == "expired"
    assert "ops@example.com" not in str(licenses.payload.model_dump())
    assert "ops@example.com" in str(raw_licenses)
    usage, _ = ad.collect("object_usage")
    by_usage = {(item.kind, item.name): item for item in usage.payload.items}
    assert by_usage[("address", "HOST_OLD")].refs == 0
    assert by_usage[("policy", "2")].hit_count == 0
    client.close()


def test_fortinet_object_usage_optional_vip_404():
    queries: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        queries.append((request.url.path, request.url.params.get("with_meta")))
        if request.url.path == "/api/v2/monitor/firewall/policy":
            return httpx.Response(200, json=load_ft("policy_stats.json"))
        if request.url.path == "/api/v2/cmdb/firewall/address":
            return httpx.Response(200, json=load_ft("address.json"))
        if request.url.path == "/api/v2/cmdb/firewall/vip":
            return httpx.Response(404, json={})
        if request.url.path.startswith("/api/v2/cmdb/"):
            return httpx.Response(200, json={"results": []})
        return httpx.Response(404, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.2")
    ad = FortinetAdapter(ft_session("tok"), client)
    usage, _ = ad.collect("object_usage")
    kinds = {item.kind for item in usage.payload.items}
    assert "vip" not in kinds
    assert "address" in kinds
    assert ("/api/v2/cmdb/firewall/address", "1") in queries
    assert ("/api/v2/monitor/firewall/policy", None) in queries
    client.close()


def test_fortinet_object_usage_truncated_address_is_collect_error():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2/monitor/firewall/policy":
            return httpx.Response(200, json=load_ft("policy_stats.json"))
        if request.url.path == "/api/v2/cmdb/firewall/address":
            return httpx.Response(200, json={"limit_reached": True, "results": []})
        return httpx.Response(404, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.2")
    ad = FortinetAdapter(ft_session("tok"), client)
    try:
        ad.collect("object_usage")
        raise AssertionError("should have failed")
    except CollectError as exc:
        assert exc.capability == "object_usage"
        assert exc.path == "/api/v2/cmdb/firewall/address"
        assert "limit_reached" in exc.message
    client.close()


def test_fortinet_logging_syslogd2_optional():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2/cmdb/log.syslogd/setting":
            return httpx.Response(200, json=load_ft("syslogd.json"))
        if request.url.path == "/api/v2/cmdb/log.syslogd2/setting":
            return httpx.Response(404, json={})
        return httpx.Response(404, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.2")
    ad = FortinetAdapter(ft_session("tok"), client)
    ev, _ = ad.collect("logging")
    assert ev.payload.remote_targets == ("10.0.0.9",)
    client.close()


def test_fortinet_logging_optional_log_setting_405():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2/cmdb/log.syslogd/setting":
            return httpx.Response(200, json=load_ft("syslogd.json"))
        if request.url.path == "/api/v2/cmdb/log/setting":
            return httpx.Response(405, json={"http_status": 405})
        return httpx.Response(404, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.2")
    ad = FortinetAdapter(ft_session("tok"), client)
    ev, _ = ad.collect("logging")
    assert ev.payload.remote_targets == ("10.0.0.9",)
    assert ev.payload.implicit_policy_logged is None
    client.close()


def test_fortinet_snmp_community_400_is_collect_error():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2/cmdb/system.snmp/community":
            return httpx.Response(400, json={"http_status": 400})
        return httpx.Response(200, json={"results": {}})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.2")
    ad = FortinetAdapter(ft_session("tok"), client)
    try:
        ad.collect("snmp")
        raise AssertionError("should have failed")
    except CollectError as exc:
        assert exc.capability == "snmp"
        assert exc.path == "/api/v2/cmdb/system.snmp/community"
        assert exc.status == 400
    client.close()


def test_fortinet_collect_non_2xx():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": 403})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.2")
    ad = FortinetAdapter(ft_session("tok"), client)
    try:
        ad.collect("users")
        raise AssertionError("should have failed")
    except CollectError as exc:
        assert exc.capability == "users"
        assert exc.path == "/api/v2/cmdb/system/admin"
        assert exc.status == 403
    client.close()


def test_build_adapter_dispatch_and_implemented():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    mt_client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.1")
    mt = build_adapter(mt_session(), mt_client)
    assert isinstance(mt, MikrotikAdapter)
    assert mt.implemented() == frozenset(CORE_CAPABILITIES + MIKROTIK_EXTRAS)
    ft_client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.2")
    ft = build_adapter(ft_session("tok"), ft_client)
    assert isinstance(ft, FortinetAdapter)
    assert ft.implemented() == frozenset(CORE_CAPABILITIES + FORTINET_EXTRAS)
    mt_client.close()
    ft_client.close()


def test_build_adapter_default_client():
    ad = build_adapter(mt_session())
    try:
        assert isinstance(ad, MikrotikAdapter)
        timeout = ad._client.timeout
        assert timeout.connect == 15.0
        assert timeout.read == 30.0
        assert str(ad._client.base_url).rstrip("/") == "https://192.0.2.1"
    finally:
        ad.close()
