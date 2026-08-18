from omf.redactor import Redactor


def test_ip_and_stability():
    r = Redactor()
    out = r.redact_text("peer 10.0.0.5 and again 10.0.0.5")
    assert "10.0.0.5" not in out
    assert out.count("[IP_1]") == 2
    assert r.destokenize(out) == "peer 10.0.0.5 and again 10.0.0.5"


def test_allowlist_admin_stays():
    r = Redactor()
    assert r.redact_obj({"name": "admin"})["name"] == "admin"
    assert r.redact_obj({"name": "jcasas"})["name"] == "[USER_1]"


def test_url_and_hostname():
    r = Redactor()
    out = r.redact_text("see https://fw.client.tld/login on fw.client.tld")
    assert "client.tld" not in out
    assert "[URL_1]" in out


def test_password_stripped_not_in_map():
    r = Redactor()
    out = r.redact_obj({"password": "s3cret", "name": "alice"})
    assert out["password"] == "[STRIPPED]"
    assert "s3cret" not in r.token_map().values()
    assert out["name"] == "[USER_1]"


def test_public_community_kept_custom_secret():
    r = Redactor()
    obj = r.redact_obj({"communities": [{"name": "public"}, {"name": "s3cr3tcomm"}]})
    assert obj["communities"][0]["name"] == "public"
    assert obj["communities"][1]["name"] == "[SECRET_1]"


def test_llm_payload_builder_excludes_map_and_raw():
    r = Redactor()
    r.redact_text("10.1.2.3")
    payload = {
        "findings": r.redact_obj([{"diagnostic": "host 10.1.2.3"}]),
        "vendor": "mikrotik",
    }
    blob = str(payload)
    assert "token_map" not in blob
    assert "10.1.2.3" not in blob
    assert "raw" not in payload


def test_ipv6_mapped_and_embedded_not_leaked():
    r = Redactor()
    for addr in ("::ffff:10.0.0.1", "2001:db8::10.0.0.1"):
        out = r.redact_text(f"peer {addr}")
        assert addr not in out
        assert "10.0.0.1" not in out
        assert "::ffff:" not in out
        assert "2001:db8::" not in out
        assert r.destokenize(out) == f"peer {addr}"


def test_same_value_same_token_across_kinds():
    r = Redactor()
    user = r.redact_obj({"name": "shared"})
    comm = r.redact_obj({"communities": [{"name": "shared"}]})
    assert user["name"] == "[USER_1]"
    assert comm["communities"][0]["name"] == "[USER_1]"

    r2 = Redactor()
    ip_out = r2.redact_text("10.0.0.9")
    name_out = r2.redact_obj({"name": "10.0.0.9"})
    assert ip_out == "[IP_1]"
    assert name_out["name"] == "[IP_1]"
    assert r2.destokenize(name_out["name"]) == "10.0.0.9"
