import pytest

from urlenrich.normalize import Reject, Skip, normalize


def url(raw):
    return normalize(raw).url


# Groups of inputs that must collapse to one canonical URL.
EQUIVALENT = {
    "https://www.example.com/": [
        "https://www.example.com", "HTTPS://WWW.EXAMPLE.COM/", "https://www.example.com:443/",
        "https://www.example.com/#top", "  https://www.example.com/   \r\n",
        '"https://www.example.com/"', "<https://www.example.com/>",
        "https://www.example.com/?utm_source=newsletter&utm_medium=email",
        "https://www.example.com/?fbclid=IwAR0abc123",
    ],
    "http://www.example.com/": ["www.example.com", "//www.example.com/", "http://www.example.com:80/"],
    "https://login.paypal-update.com/account/unlock": [
        "hxxps://login[.]paypal-update[.]com/account/unlock",
        "hxxps://LOGIN.paypal-update.com:443/account/unlock#urgent",
    ],
    "https://login.paypal-update.com/verify?session=123&user=alice": [
        "HTTPS://Login.PayPal-Update.com:443/verify?user=alice&session=123#top",
    ],
    "https://bad-example.net/login": ["hxxps[:]//bad-example[.]net/login"],
    "https://example.com/": ["https://example.com.", "https://example.com", "https://example.com:443/#x"],
    "https://example.com/about": ["https://example.com/a/../about", "https://Example.Com/about"],
    "https://example.com/~user/profile": ["https://example.com/%7Euser/profile"],
    "https://example.com/search?a=1&b=2": ["https://example.com/search?b=2&a=1",
                                           "https://example.com/search?a=1&b=2#results"],
    "https://example.com/search": ["https://example.com/search?"],
    "https://example.com/path%2Fencoded": ["https://example.com/path%2fencoded"],
    "https://example.com/login": ["https://user:secret@example.com/login"],
    "https://xn--mnchen-3ya.example/": ["https://münchen.example/"],
    "http://192.0.2.10/": ["http://3221225994/"],
    "https://example.org/docs?page=2": ["https://example.org/docs?utm_campaign=spring&page=2"],
}


@pytest.mark.parametrize("expected,raw", [(k, r) for k, v in EQUIVALENT.items() for r in v])
def test_variants_collapse(expected, raw):
    assert url(raw) == expected


# Pairs that look similar but must stay DIFFERENT.
@pytest.mark.parametrize("a,b", [
    ("https://storage.googleapis.com/invoice-bucket/DocA.html",
     "https://storage.googleapis.com/invoice-bucket/doca.html"),   # path case matters
    ("https://example.com/about", "https://example.com/about/"),    # trailing slash kept
    ("https://example.com/About", "https://example.com/about"),
    ("https://www.example.com/", "http://www.example.com/"),        # scheme matters
    ("https://www.example.com/", "https://example.com/"),           # www is a different host
    ("https://cdn.example.com:8443/a.js", "https://cdn.example.com/a.js"),  # non-default port
    ("https://example.com/path%2Fencoded", "https://example.com/path/encoded"),  # %2F != /
])
def test_distinct_urls_stay_distinct(a, b):
    assert url(a) != url(b)


def test_flags_record_what_happened():
    n = normalize("hxxps://LOGIN.paypal-update.com:443/account/unlock#urgent")
    assert {"refanged", "host_lowercased", "default_port_removed", "fragment_removed"} <= set(n.flags)


def test_blank_query_value_kept():
    assert url("https://example.com/truncated?id=") == "https://example.com/truncated?id="


def test_repeated_query_keys_keep_order():
    assert url("https://e.com/?z=1&tag=b&tag=a") == "https://e.com/?tag=b&tag=a&z=1"


def test_unsafe_path_chars_are_encoded():
    assert url("https://example.com/<script>") == "https://example.com/%3Cscript%3E"


def test_ipv6_and_idn():
    assert normalize("http://[2001:DB8:0::1]/status").url == "http://[2001:db8::1]/status"
    assert url("https://例え.jp/") == "https://xn--r8jz45g.jp/"


@pytest.mark.parametrize("raw,reason", [
    ("", "blank_line"), ("\r\n", "blank_line"), ("# malformed lines below", "comment_line"),
])
def test_skipped(raw, reason):
    with pytest.raises(Skip) as e:
        normalize(raw)
    assert e.value.reason == reason


@pytest.mark.parametrize("raw,reason", [
    ("mailto:support@paypal-update.com", "unsupported_scheme"),
    ("javascript:alert(1)", "unsupported_scheme"),
    ("data:text/html,hello", "unsupported_scheme"),
    ("http://", "missing_host"),
    ("https://exa mple.com/broken", "invalid_host"),
    ("not a url at all", "invalid_host"),
    ("not-a-valid-url-at-all", "single_label_host"),
    ("example", "single_label_host"),
    ("https://example.com:99999/", "invalid_port"),
    ("gopher://example.com/", "unsupported_scheme"),
])
def test_rejected(raw, reason):
    with pytest.raises(Reject) as e:
        normalize(raw)
    assert e.value.reason == reason
