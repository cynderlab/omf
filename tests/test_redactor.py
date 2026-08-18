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
