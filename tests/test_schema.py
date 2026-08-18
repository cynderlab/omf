from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from omf.schema.capabilities import User, UserList
from omf.schema.evidence import CheckResult, Evidence


def test_userlist_frozen():
    users = UserList(users=(User(name="admin", enabled=True, groups=("full",)),))
    with pytest.raises(Exception):
        users.users[0].name = "x"  # type: ignore[misc]


def test_evidence_wraps_payload():
    payload = UserList(users=())
    ev = Evidence(
        capability="users",
        vendor="mikrotik",
        collected_at=datetime.now(timezone.utc),
        payload=payload,
    )
    assert ev.schema_version == 1
    assert ev.payload is payload


def test_user_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        User(name="a", enabled=True, groups=(), password="nope")


def test_check_result_status_enum():
    CheckResult(
        check_id="FW-ADM-001",
        status="fail",
        severity="high",
        diagnostic="default admin present",
        capability_refs=("users",),
        observed={"names": ["admin"]},
    )
    with pytest.raises(ValidationError):
        CheckResult(
            check_id="x",
            status="warn",
            severity="high",
            diagnostic="",
            capability_refs=(),
            observed={},
        )
