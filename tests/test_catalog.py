from omf.baseline.loader import load_catalog, checks_for, resolve_params, mitigation_for


def test_catalog_has_unique_ids():
    checks = load_catalog()
    ids = [c.id for c in checks]
    assert len(ids) == len(set(ids))
    assert "FW-POL-002" in ids
    assert "FW-ADM-011" in ids


def test_pol002_only_mikrotik():
    mt = {c.id for c in checks_for("mikrotik")}
    ft = {c.id for c in checks_for("fortinet")}
    assert "FW-POL-002" in mt
    assert "FW-POL-002" not in ft
    assert len(mt) == 14
    assert len(ft) == 31


def test_resolve_admin_mode_differs_by_vendor():
    check = next(c for c in load_catalog() if c.id == "FW-ADM-001")
    assert resolve_params(check, "mikrotik")["mode"] == "must_not_exist"
    assert resolve_params(check, "fortinet")["mode"] == "must_be_renamed"


def test_mitigation_falls_back_to_generic():
    check = next(c for c in load_catalog() if c.id == "FW-SYS-001")
    text = mitigation_for(check, "mikrotik")
    assert text


def test_new_admin_l1_checks_are_fortinet_only():
    from omf.baseline.loader import load_catalog, checks_for
    ids = {c.id for c in load_catalog()}
    assert "FW-ADM-004" in ids
    assert "FW-ADM-004" not in {c.id for c in checks_for("mikrotik")}
    assert "FW-ADM-004" in {c.id for c in checks_for("fortinet")}
