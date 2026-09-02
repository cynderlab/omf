import json

from omf.redactor import Redactor, leak_hits


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


def test_unqualified_hostname_is_tokenized():
    r = Redactor()
    out = r.redact_obj({"hostname": "home-fw"})
    assert out["hostname"] == "[HOST_1]"
    assert r.destokenize(out["hostname"]) == "home-fw"
    assert r.redact_obj({"hostname": "MikroTik"})["hostname"] == "MikroTik"
    assert r.redact_obj({"hostname": "FortiGate"})["hostname"] == "FortiGate"


def test_username_copied_into_diagnostic_is_tokenized():
    r = Redactor()
    users = r.redact_obj({"users": [{"name": "reader"}]})
    assert users["users"][0]["name"] == "[USER_1]"
    finding = r.redact_obj({
        "diagnostic": "users missing inactivity logout/lock ['admin', 'reader']",
        "observed": {"names": ["admin", "reader"]},
    })
    finding = r.apply_known(finding)
    blob = json.dumps(finding)
    assert "reader" not in blob
    assert "[USER_1]" in finding["diagnostic"]
    assert finding["observed"]["names"] == ["admin", "[USER_1]"]
    assert "admin" in finding["diagnostic"]


def test_profile_name_rewritten_on_other_fields():
    r = Redactor()
    r.redact_obj({"profiles": [{"name": "DOSL-DNS"}]})
    fw = r.redact_obj({"dnsfilter_profile": "DOSL-DNS"})
    fw = r.apply_known(fw)
    assert fw["dnsfilter_profile"] == "[USER_1]"
    assert "DOSL-DNS" not in json.dumps(fw)


def test_protocol_service_names_stay_clear():
    r = Redactor()
    for name in ("ftp", "ssh", "http", "https", "www", "www-ssl", "winbox", "api", "telnet", "ping"):
        assert r.redact_obj({"name": name})["name"] == name


def test_apply_known_longest_original_first():
    r = Redactor()
    r.redact_obj({"name": "foobarbaz"})
    r.redact_obj({"name": "foobar"})
    out = r.apply_known("see foobarbaz and foobar")
    assert out == "see [USER_1] and [USER_2]"
    assert r.destokenize(out) == "see foobarbaz and foobar"


def test_leak_hits_finds_raw_ip_not_tokens():
    assert leak_hits({"peer": "10.0.0.5"}) == ["10.0.0.5"]
    assert leak_hits({"peer": "[IP_1]"}) == []
    assert leak_hits({"url": "https://fw.example"}) == ["https://fw.example"]
    assert leak_hits({"name": "ftp"}) == []


def _assert_tokenized(text: str, *, kind: str) -> None:
    r = Redactor()
    out = r.redact_text(f"see {text} and {text}")
    token = f"[{kind}_1]"
    assert out == f"see {token} and {token}"
    assert r.token_map()[token] == text
    assert r.destokenize(out) == f"see {text} and {text}"
    assert leak_hits(out) == []


def test_ipv4_and_ranges_are_single_ip_tokens():
    _assert_tokenized("10.0.0.5", kind="IP")
    _assert_tokenized("10.0.0.0/24", kind="IP")
    _assert_tokenized("10.0.0.1-10.0.0.50", kind="IP")
    r = Redactor()
    out = r.redact_text("10.0.0.0/255.255.255.0")
    assert "10.0.0.0" not in out
    assert "255.255.255.0" not in out
    assert r.destokenize(out) == "10.0.0.0/255.255.255.0"


def test_ipv6_and_ranges_are_single_ip_tokens():
    _assert_tokenized("2001:db8::1", kind="IP")
    _assert_tokenized("2001:db8::/32", kind="IP")
    _assert_tokenized("2001:db8::1-2001:db8::ff", kind="IP")
    _assert_tokenized("::ffff:10.0.0.1", kind="IP")
    r = Redactor()
    out = r.redact_text("to [2001:db8::1]:443")
    assert "2001:db8::1" not in out
    assert r.destokenize(out) == "to [2001:db8::1]:443"


def test_email_is_whole_user_token():
    _assert_tokenized("alice@client.example", kind="USER")
    _assert_tokenized("alice+fw@sub.client.example", kind="USER")
    r = Redactor()
    out = r.redact_obj({"email": "alice@client.example"})
    assert out["email"] == "[USER_1]"
    assert "alice" not in out["email"]


def test_domains_subdomains_and_urls():
    _assert_tokenized("client.example", kind="HOST")
    _assert_tokenized("fw.client.example", kind="HOST")
    _assert_tokenized("https://fw.client.example/login?x=1", kind="URL")
    _assert_tokenized("http://10.0.0.5:443/api", kind="URL")
    _assert_tokenized("ftp://files.client.example/x", kind="URL")


def test_password_and_username_keys():
    r = Redactor()
    out = r.redact_obj({"password": "hunter2", "username": "alice"})
    assert out["password"] == "[STRIPPED]"
    assert out["username"] == "[USER_1]"
    assert "hunter2" not in r.token_map().values()


def test_leak_hits_covers_cidr_and_email():
    assert leak_hits({"src": "10.0.0.0/24"}) == ["10.0.0.0/24"]
    assert leak_hits({"src": "2001:db8::/32"}) == ["2001:db8::/32"]
    assert leak_hits({"e": "alice@client.example"}) == ["alice@client.example"]
    r = Redactor()
    redacted = r.redact_obj({
        "src": "10.0.0.0/24",
        "dst": "2001:db8::/32",
        "email": "alice@client.example",
        "url": "https://fw.client.example/",
    })
    assert leak_hits(redacted) == []
