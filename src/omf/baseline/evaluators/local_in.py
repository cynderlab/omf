from __future__ import annotations

from omf.schema.evidence import CheckResult


def local_in_present(evidence, params, vendor) -> CheckResult:
    hits = [p.id for p in evidence["local_in"].payload.policies if p.enabled]
    return CheckResult(
        check_id="",
        status="fail" if not hits else "pass",
        severity="medium",
        diagnostic="no enabled local-in policy" if not hits else "local-in policies are present",
        capability_refs=("local_in",),
        observed={"policy_ids": hits},
    )


def virtual_patch_on_accept(evidence, params, vendor) -> CheckResult:
    accepts = [p for p in evidence["local_in"].payload.policies if p.enabled and p.action == "accept"]
    missing = [p.id for p in accepts if not p.virtual_patch]
    failed = bool(missing)
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="high",
        diagnostic=(
            "accept local-in policies lack virtual-patch"
            if failed
            else "virtual-patch is enabled on accept local-in policies"
        ),
        capability_refs=("local_in",),
        observed={"missing": missing, "accepts": [p.id for p in accepts]},
    )
