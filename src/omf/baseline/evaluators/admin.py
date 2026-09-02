from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import AdminSettings
from omf.schema.evidence import CheckResult, Evidence


def idle_timeout_set(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    if params.get("mode") == "per_user":
        allowed = {str(p).strip().lower() for p in params.get("policies", ("logout", "lockscreen", "lock"))}
        hits = [
            u.name
            for u in evidence["users"].payload.users
            if u.enabled
            and (
                (u.inactivity_policy or "") not in allowed
                or u.inactivity_timeout_seconds is None
                or u.inactivity_timeout_seconds <= 0
            )
        ]
        return CheckResult(
            check_id="",
            status="fail" if hits else "pass",
            severity="medium",
            diagnostic=(
                f"users missing inactivity logout/lock {hits!r}"
                if hits
                else "enabled users have inactivity timeout and policy"
            ),
            capability_refs=("users",),
            observed={"names": hits},
        )
    payload: AdminSettings = evidence["admin_settings"].payload
    timeout = payload.idle_timeout_seconds
    failed = timeout is None or timeout <= 0
    max_seconds = params.get("max_seconds")
    if not failed and max_seconds is not None:
        failed = timeout > max_seconds
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=(
            f"idle timeout is {timeout!r}" if failed else f"idle timeout is {timeout}s"
        ),
        capability_refs=("admin_settings",),
        observed={"idle_timeout_seconds": timeout},
    )


def hostname_not_default(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: AdminSettings = evidence["admin_settings"].payload
    defaults = {str(h).strip().lower() for h in params.get("default_hostnames", ())}
    host = payload.hostname.strip()
    failed = (not host) or host.lower() in defaults
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="low",
        diagnostic=(
            f"hostname {payload.hostname!r} is empty or a vendor default"
            if failed
            else f"hostname {payload.hostname!r} is not a vendor default"
        ),
        capability_refs=("admin_settings",),
        observed={"hostname": payload.hostname},
    )


def timezone_set(evidence, params, vendor) -> CheckResult:
    payload = evidence["admin_settings"].payload
    zone = (payload.timezone or "").strip()
    failed = not zone
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="low",
        diagnostic="timezone is empty" if failed else f"timezone is {zone}",
        capability_refs=("admin_settings",),
        observed={"timezone": payload.timezone},
    )


def tls_versions_allowed(evidence, params, vendor) -> CheckResult:
    allowed = {str(v).strip().lower() for v in params.get("allowed", ("tlsv1-3",))}
    versions = tuple(str(v).strip().lower() for v in evidence["admin_settings"].payload.admin_https_ssl_versions)
    extra = [v for v in versions if v not in allowed]
    failed = (not versions) or bool(extra)
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="high",
        diagnostic=f"TLS versions {list(versions)}",
        capability_refs=("admin_settings",),
        observed={"versions": list(versions), "extra": extra},
    )


def flag_enabled(evidence, params, vendor) -> CheckResult:
    field = str(params.get("field"))
    value = getattr(evidence["admin_settings"].payload, field)
    failed = value is not True
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=f"{field} is {value!r}",
        capability_refs=("admin_settings",),
        observed={field: value},
    )


def password_policy_strong(evidence, params, vendor) -> CheckResult:
    payload = evidence["admin_settings"].payload
    min_length = int(params.get("min_length", 14))
    required = {str(x).lower() for x in params.get("apply_to", ("admin-password",))}
    have = {str(x).lower() for x in payload.password_apply_to}
    length = payload.password_min_length
    failed = (
        payload.password_policy_enabled is not True
        or length is None
        or length < min_length
        or not required.issubset(have)
    )
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="high",
        diagnostic="password policy is weak or disabled" if failed else "password policy meets minimums",
        capability_refs=("admin_settings",),
        observed={
            "enabled": payload.password_policy_enabled,
            "min_length": length,
            "apply_to": list(payload.password_apply_to),
        },
    )


def lockout_configured(evidence, params, vendor) -> CheckResult:
    payload = evidence["admin_settings"].payload
    max_threshold = int(params.get("max_threshold", 3))
    max_duration = int(params.get("max_duration", 900))
    threshold = payload.admin_lockout_threshold
    duration = payload.admin_lockout_duration
    failed = (
        threshold is None
        or duration is None
        or threshold < 1
        or threshold > max_threshold
        or duration < 1
        or duration > max_duration
    )
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=f"lockout threshold={threshold!r} duration={duration!r}",
        capability_refs=("admin_settings",),
        observed={"threshold": threshold, "duration": duration},
    )


def admin_ports_changed(evidence, params, vendor) -> CheckResult:
    payload = evidence["admin_settings"].payload
    http_bad = int(params.get("forbidden_http", 80))
    https_bad = int(params.get("forbidden_https", 443))
    http_live = payload.admin_http_enabled is not False
    https_live = payload.admin_https_enabled is not False
    failed = (
        (http_live and payload.admin_http_port == http_bad)
        or (https_live and payload.admin_https_port == https_bad)
        or payload.admin_https_redirect is not False
    )
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=(
            f"admin ports http={payload.admin_http_port!r} https={payload.admin_https_port!r} "
            f"redirect={payload.admin_https_redirect!r}"
        ),
        capability_refs=("admin_settings",),
        observed={
            "admin_http_port": payload.admin_http_port,
            "admin_https_port": payload.admin_https_port,
            "admin_http_enabled": payload.admin_http_enabled,
            "admin_https_enabled": payload.admin_https_enabled,
            "admin_https_redirect": payload.admin_https_redirect,
        },
    )
