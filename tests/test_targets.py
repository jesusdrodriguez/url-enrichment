from urlenrich.normalize import normalize
from urlenrich.targets import REGISTRATION, REPUTATION, TLS, derive


def targets(raw):
    d = derive(normalize(raw))
    return {t.lookup_type: t for t in d.targets}, d


def test_three_targets_from_one_url():
    t, _ = targets("https://Shop.Example.co.uk:443/cart?id=5#top")
    assert t[REGISTRATION].key == "example.co.uk"          # multi-label suffix
    assert t[TLS].key == "shop.example.co.uk:443"
    assert t[REPUTATION].key == "https://shop.example.co.uk/cart?id=5"


def test_registration_uses_icann_suffixes_only():
    t, d = targets("https://alice.github.io/blog/")
    assert t[REGISTRATION].key == "github.io"               # WHOIS knows github.io
    assert d.site == "alice.github.io"                      # owner view kept as metadata
    t, _ = targets("https://storage.googleapis.com/x")
    assert t[REGISTRATION].key == "googleapis.com"


def test_unknown_suffix_uses_default_rule():
    t, _ = targets("https://münchen.example/")
    assert t[REGISTRATION].key == "xn--mnchen-3ya.example"
    assert t[REGISTRATION].attrs == {"suffix_rule": "psl_default_rule"}


def test_ip_has_no_registration_target():
    t, d = targets("http://45.33.32.156/bins/mirai.sh")
    assert REGISTRATION not in t
    assert d.skipped[REGISTRATION] == "ipv4_literal_has_no_domain"
    assert t[TLS].key == "45.33.32.156:443"


def test_tls_port_rules():
    assert targets("https://portal.hsbc-security.co.uk:8443/x")[0][TLS].key == \
        "portal.hsbc-security.co.uk:8443"
    http = targets("http://192.0.2.10:8080/")[0][TLS]
    assert http.key == "192.0.2.10:443" and http.derivation == "inferred_from_http"
    assert targets("http://[2001:db8::1]/")[0][TLS].key == "[2001:db8::1]:443"


def test_ftp_has_no_tls_target():
    t, d = targets("ftp://files.example.com/pub/readme.txt")
    assert TLS not in t and d.skipped[TLS] == "scheme_ftp_not_tls"
    assert t[REGISTRATION].key == "example.com"


def test_http_and_https_share_tls_target():
    a = targets("http://www.example.com/")[0][TLS].key
    b = targets("https://www.example.com/")[0][TLS].key
    assert a == b == "www.example.com:443"
