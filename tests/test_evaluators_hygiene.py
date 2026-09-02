from datetime import datetime, timezone

from omf.baseline.evaluators.hygiene import (
    disabled_policies,
    unref_objects,
    zero_hit_policies,
)
from omf.schema.capabilities import Policy, PolicyList, UsageItem, UsageList
from omf.schema.evidence import Evidence

_UNREF_PARAMS = {
    "kinds": ["address", "addrgrp", "service", "service_group", "vip", "ippool"],
    "skip_static": True,
    "skip_names": [
        "all",
        "none",
        "FABRIC_DEVICE",
        "FIREWALL_AUTH_PORTAL_ADDRESS",
        "SSLVPN_TUNNEL_ADDR1",
        "ALL",
        "ALL_TCP",
        "ALL_UDP",
        "ALL_ICMP",
    ],
}


def ev(capability, payload):
    return Evidence(
        capability=capability,
        vendor="fortinet",
        collected_at=datetime.now(timezone.utc),
        payload=payload,
    )


def _policy(**kwargs):
    base = {
        "id": "1",
        "enabled": True,
        "action": "accept",
        "src": ("lan",),
        "dst": ("wan",),
        "service": ("HTTPS",),
    }
    base.update(kwargs)
    return Policy(**base)


def test_disabled_policies_fail_lists_ids():
    payload = PolicyList(
        policies=(
            _policy(id="1", enabled=True),
            _policy(id="9", enabled=False),
        )
    )
    result = disabled_policies({"firewall_filter": ev("firewall_filter", payload)}, {}, "fortinet")
    assert result.status == "fail"
    assert "9" in result.diagnostic
    assert result.observed["policies"][0]["id"] == "9"


def test_disabled_policies_pass_when_all_enabled():
    payload = PolicyList(policies=(_policy(id="1", enabled=True),))
    result = disabled_policies({"firewall_filter": ev("firewall_filter", payload)}, {}, "fortinet")
    assert result.status == "pass"
    assert result.observed["policies"] == []


def test_zero_hit_skips_disabled_and_fails_enabled():
    usage = UsageList(
        items=(
            UsageItem(kind="policy", name="1", hit_count=0),
            UsageItem(kind="policy", name="2", hit_count=0),
            UsageItem(kind="policy", name="3", hit_count=12),
        )
    )
    policies = PolicyList(
        policies=(
            _policy(id="1", enabled=True),
            _policy(id="2", enabled=False),
            _policy(id="3", enabled=True),
        )
    )
    result = zero_hit_policies(
        {
            "object_usage": ev("object_usage", usage),
            "firewall_filter": ev("firewall_filter", policies),
        },
        {},
        "fortinet",
    )
    assert result.status == "fail"
    ids = [row["id"] for row in result.observed["policies"]]
    assert ids == ["1"]
    assert "1" in result.diagnostic
    assert "2" not in ids


def test_zero_hit_pass_when_every_enabled_policy_has_hits():
    usage = UsageList(items=(UsageItem(kind="policy", name="1", hit_count=4),))
    policies = PolicyList(policies=(_policy(id="1", enabled=True),))
    result = zero_hit_policies(
        {
            "object_usage": ev("object_usage", usage),
            "firewall_filter": ev("firewall_filter", policies),
        },
        {},
        "fortinet",
    )
    assert result.status == "pass"


def test_unref_objects_skips_static_and_builtin_names():
    usage = UsageList(
        items=(
            UsageItem(kind="address", name="all", refs=0, static=True),
            UsageItem(kind="address", name="FABRIC_DEVICE", refs=0, static=False),
            UsageItem(kind="address", name="HOST_OLD", refs=0, static=False),
            UsageItem(kind="address", name="LAN", refs=3, static=False),
            UsageItem(kind="service", name="TCP_DEAD", refs=0, static=False),
            UsageItem(kind="policy", name="1", hit_count=0),
        )
    )
    result = unref_objects({"object_usage": ev("object_usage", usage)}, _UNREF_PARAMS, "fortinet")
    assert result.status == "fail"
    names = {(row["kind"], row["name"]) for row in result.observed["objects"]}
    assert names == {("address", "HOST_OLD"), ("service", "TCP_DEAD")}
    assert "HOST_OLD" in result.diagnostic


def test_unref_objects_pass_when_only_used_or_skipped():
    usage = UsageList(
        items=(
            UsageItem(kind="address", name="all", refs=0, static=True),
            UsageItem(kind="address", name="LAN", refs=1, static=False),
        )
    )
    result = unref_objects({"object_usage": ev("object_usage", usage)}, _UNREF_PARAMS, "fortinet")
    assert result.status == "pass"
    assert result.observed["objects"] == []
