"""Turn one raw input line into a canonical URL, or explain why it can't be one.

The pipeline is deliberately split into small, ordered steps so every decision
can be tested on its own and is recorded as a *flag* on the result. Flags are
stored next to the raw input, so it is always possible to see *why* two
different-looking lines ended up as the same URL.

Order of steps:
    1. clean      - whitespace / CRLF, blank and comment lines, wrapper chars
    2. refang     - hxxp://, [.], [:]   (threat-intel "defanged" notation)
    3. scheme     - explicit, scheme-relative (//host), missing, or unsupported
    4. authority  - drop credentials, parse host + port
    5. host       - lowercase, trailing dot, IPv4/IPv6/decimal IP, IDN -> punycode
    6. port       - drop the scheme's default port
    7. path       - percent-encoding normalization, dot-segment removal
    8. query      - drop empty / tracking params, sort by key
    9. fragment   - dropped (never sent to a server)
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import quote

import idna

# Schemes we can enrich. ftp is accepted (it has a host and a path worth a
# reputation check) but it gets no TLS lookup; see targets.py.
SUPPORTED_SCHEMES = {"http": 80, "https": 443, "ftp": 21}

# Schemes that look like URLs but have no host to look up.
NON_HIERARCHICAL_SCHEMES = {"mailto", "javascript", "data", "tel", "sms", "about", "blob", "file"}

# Well-known analytics / click-tracking parameters. They don't change which
# page is served, so keeping them would create a separate reputation lookup
# for every marketing email. Anything not on this list is kept.
TRACKING_PARAMS = {
    "fbclid", "gclid", "dclid", "gbraid", "wbraid", "msclkid", "yclid",
    "igshid", "mc_cid", "mc_eid", "_ga", "_gl",
}
TRACKING_PREFIXES = ("utm_",)

_UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_PCT = re.compile(r"%([0-9A-Fa-f]{2})")
_SCHEME_WITH_SLASHES = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")
_SCHEME_COLON = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")
_ASCII_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?$")
# Brackets are deliberately not in this list: "[2001:db8::1]" must keep them.
_WRAPPERS = [('"', '"'), ("'", "'"), ("<", ">")]

# Characters allowed to stay literal in a path / query. Everything else
# (spaces, <, >, quotes, non-ASCII) is percent-encoded, as a browser would.
_PATH_SAFE = "/:@!$&'()*+,;=-._~%"
_QUERY_SAFE = _PATH_SAFE + "?"


class Skip(Exception):
    """Line is intentionally not a URL (blank line, comment)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Reject(Exception):
    """Line was meant to be a URL but can't be used for lookups."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass
class NormalizedURL:
    url: str            # canonical form, used as the reputation lookup key
    scheme: str
    host: str           # lowercase ASCII (punycode); IPv6 without brackets
    port: int           # effective port (default filled in)
    host_type: str      # "domain" | "ipv4" | "ipv6"
    path: str
    query: str
    flags: list[str] = field(default_factory=list)

    @property
    def host_for_url(self) -> str:
        return f"[{self.host}]" if self.host_type == "ipv6" else self.host


# --------------------------------------------------------------------------- #
# Step 1-2: clean and refang
# --------------------------------------------------------------------------- #

def clean(raw: str, flags: list[str]) -> str:
    line = raw.rstrip("\r\n")   # the input file uses CRLF line endings
    text = line.strip()
    if text != line:
        flags.append("whitespace_stripped")
    if not text:
        raise Skip("blank_line")
    if text.startswith("#"):
        raise Skip("comment_line")

    # Strip wrapper characters often left over from CSV, emails and markdown.
    changed = True
    while changed and len(text) >= 2:
        changed = False
        for left, right in _WRAPPERS:
            if text.startswith(left) and text.endswith(right):
                text = text[1:-1].strip()
                flags.append("wrapper_stripped")
                changed = True
    if not text:
        raise Skip("blank_line")
    return text


def refang(text: str, flags: list[str]) -> str:
    """Undo common defanging so 'hxxps://evil[.]com' == 'https://evil.com'."""
    original = text
    text = re.sub(r"^hxxps", "https", text, flags=re.IGNORECASE)
    text = re.sub(r"^hxxp", "http", text, flags=re.IGNORECASE)
    for fanged, plain in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[:]", ":"), ("[://]", "://")):
        text = text.replace(fanged, plain)
    if text != original:
        flags.append("refanged")
    return text


# --------------------------------------------------------------------------- #
# Step 3: scheme
# --------------------------------------------------------------------------- #

def split_scheme(text: str, flags: list[str]) -> tuple[str, str]:
    """Return (scheme, rest-after-//)."""
    m = _SCHEME_WITH_SLASHES.match(text)
    if m:
        scheme = m.group(1).lower()
        if scheme not in SUPPORTED_SCHEMES:
            raise Reject("unsupported_scheme", scheme)
        return scheme, text[m.end():]

    m = _SCHEME_COLON.match(text)
    if m and m.group(1).lower() in NON_HIERARCHICAL_SCHEMES:
        raise Reject("unsupported_scheme", m.group(1).lower())

    if text.startswith("//"):
        flags.append("scheme_inferred")
        return "http", text[2:]

    # No scheme at all ("www.example.com"). Assume http, the same default a
    # browser address bar historically used. Flagged so it can be reviewed.
    flags.append("scheme_inferred")
    return "http", text

def backslashes_to_slashes(rest: str, flags: list[str]) -> str:
    """Browsers treat '\\' as '/' in http, https and ftp URLs (WHATWG URL
    standard), but only before the query and fragment."""
    cut = min((i for i in (rest.find("?"), rest.find("#")) if i != -1), default=len(rest))
    head, tail = rest[:cut], rest[cut:]
    if "\\" in head:
        flags.append("backslash_converted")
        head = head.replace("\\", "/")
    return head + tail

# --------------------------------------------------------------------------- #
# Step 4-6: authority, host, port
# --------------------------------------------------------------------------- #

def split_authority(rest: str) -> tuple[str, str]:
    """Split 'host:port/path?q#f' into (authority, 'path?q#f')."""
    for i, ch in enumerate(rest):
        if ch in "/?#":
            return rest[:i], rest[i:]
    return rest, ""


def parse_host_port(authority: str, flags: list[str]) -> tuple[str, str | None]:
    if "@" in authority:
        # Credentials never reach the lookup services and don't change the host.
        authority = authority.rpartition("@")[2]
        flags.append("userinfo_removed")

    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            raise Reject("invalid_host", "unclosed IPv6 bracket")
        host, after = authority[1:end], authority[end + 1:]
        if after and not after.startswith(":"):
            raise Reject("invalid_host", authority)
        port = after[1:] if after else None
        return "[" + host + "]", port

    if ":" in authority:
        host, _, port = authority.rpartition(":")
        return host, port
    return authority, None


def normalize_host(host: str, flags: list[str]) -> tuple[str, str]:
    """Return (canonical_host, host_type)."""
    if not host:
        raise Reject("missing_host")

    if host.startswith("[") and host.endswith("]"):
        try:
            return ipaddress.IPv6Address(host[1:-1]).compressed, "ipv6"
        except ValueError:
            raise Reject("invalid_host", host)

    if any(ch.isspace() for ch in host) or "%" in host:
        raise Reject("invalid_host", host)

    if host.endswith("."):
        host = host[:-1]          # "example.com." is the same FQDN
        flags.append("trailing_dot_removed")
    if host != host.lower():
        flags.append("host_lowercased")
    host = host.lower()

    # Integer IPv4 ("http://3221225994/") is accepted by browsers.
    if host.isdigit():
        value = int(host)
        if value >= 2 ** 32:
            raise Reject("invalid_host", host)
        flags.append("ip_integer_converted")
        return str(ipaddress.IPv4Address(value)), "ipv4"
    try:
        return str(ipaddress.IPv4Address(host)), "ipv4"
    except ValueError:
        pass

    # Domain name: convert non-ASCII labels to punycode (IDNA 2008 / UTS-46).
    labels = host.split(".")
    if any(not label for label in labels):
        raise Reject("invalid_host", host)
    ascii_labels = []
    for label in labels:
        if label.isascii():
            ascii_labels.append(label)
            continue
        try:
            ascii_labels.append(idna.encode(label, uts46=True).decode("ascii"))
        except idna.IDNAError as exc:
            raise Reject("invalid_host", f"{host} ({exc})")
        if "idn_converted" not in flags:
            flags.append("idn_converted")
    host = ".".join(ascii_labels)

    if len(host) > 253 or not all(_ASCII_LABEL.match(lbl) for lbl in ascii_labels):
        raise Reject("invalid_host", host)
    if len(ascii_labels) < 2:
        # "example" / "not-a-valid-url-at-all": no TLD, can't be looked up.
        raise Reject("single_label_host", host)
    if ascii_labels[-1].isdigit():
        raise Reject("invalid_host", host)   # numeric TLD, e.g. a broken IP
    return host, "domain"


def normalize_port(port: str | None, scheme: str, flags: list[str]) -> int:
    default = SUPPORTED_SCHEMES[scheme]
    if port is None or port == "":
        return default
    if not port.isdigit() or not (0 < int(port) < 65536):
        # Unusable port, but the host is fine. Never lose a host over it:
        # fall back to the scheme's default port and record what happened.
        flags.append("invalid_port_ignored")
        return default
    if int(port) == default:
        flags.append("default_port_removed")
    return int(port)


# --------------------------------------------------------------------------- #
# Step 7-8: path and query
# --------------------------------------------------------------------------- #

def normalize_percent_encoding(text: str, safe: str) -> str:
    """Make equivalent encodings identical.

    - a malformed escape ('%ZZ', a lone '%') is left exactly as written,
      the way a browser sends it; it never causes a rejection
    - characters that must be encoded are encoded (space, <, >, non-ASCII...)
    - '%7E' (unreserved char) is decoded to '~'
    - remaining escapes use uppercase hex: '%2f' -> '%2F'
      (%2F is NOT decoded to '/': an encoded slash is a different path)
    """
    text = quote(text, safe=safe)

    def fix(m: re.Match) -> str:
        ch = chr(int(m.group(1), 16))
        return ch if ch in _UNRESERVED else "%" + m.group(1).upper()

    return _PCT.sub(fix, text)


def remove_dot_segments(path: str) -> str:
    """RFC 3986 section 5.2.4 ('/a/../about' -> '/about')."""
    output: list[str] = []
    segments = path.split("/")
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        if seg == ".":
            if last:
                output.append("")
        elif seg == "..":
            if len(output) > 1:
                output.pop()
            if last:
                output.append("")
        else:
            output.append(seg)
    result = "/".join(output)
    return result if result.startswith("/") else "/" + result


def normalize_path(path: str, flags: list[str]) -> str:
    if not path:
        flags.append("empty_path_set_to_root")   # "https://a.com" == "https://a.com/"
        return "/"
    new = remove_dot_segments(normalize_percent_encoding(path, _PATH_SAFE))
    if new != path:
        flags.append("path_normalized")
    # Case is preserved: paths are case-sensitive (DocA.html != doca.html).
    # Trailing slash is preserved: /about and /about/ can be different pages.
    return new


def is_tracking_param(key: str) -> bool:
    k = key.lower()
    return k in TRACKING_PARAMS or k.startswith(TRACKING_PREFIXES)


def normalize_query(query: str, flags: list[str]) -> str:
    if not query:
        return ""
    pairs = [p for p in query.split("&") if p]   # drops empty "?" and "&&"
    kept = []
    for pair in pairs:
        key = pair.split("=", 1)[0]
        if is_tracking_param(key):
            if "tracking_params_removed" not in flags:
                flags.append("tracking_params_removed")
            continue
        kept.append(normalize_percent_encoding(pair, _QUERY_SAFE))
    # Sort by key only. The sort is stable, so repeated keys
    # (?tag=a&tag=b) keep their relative order, which can be meaningful.
    ordered = sorted(kept, key=lambda p: p.split("=", 1)[0])
    if ordered != kept:
        flags.append("query_sorted")
    return "&".join(ordered)


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def normalize(raw: str) -> NormalizedURL:
    """Normalize one raw line. Raises Skip or Reject when it isn't usable."""
    flags: list[str] = []
    text = refang(clean(raw, flags), flags)
    scheme, rest = split_scheme(text, flags)
    rest = backslashes_to_slashes(rest, flags)

    authority, remainder = split_authority(rest)
    if not authority:
        raise Reject("missing_host")
    host_raw, port_raw = parse_host_port(authority, flags)
    host, host_type = normalize_host(host_raw, flags)
    port = normalize_port(port_raw, scheme, flags)

    remainder, hash_, fragment = remainder.partition("#")
    if hash_:
        flags.append("fragment_removed")
    path, q_mark, query = remainder.partition("?")
    path = normalize_path(path, flags)
    query = normalize_query(query, flags)
    if q_mark and not query and "tracking_params_removed" not in flags:
        flags.append("empty_query_removed")

    n = NormalizedURL(url="", scheme=scheme, host=host, port=port, host_type=host_type,
                      path=path, query=query, flags=flags)
    port_part = "" if port == SUPPORTED_SCHEMES[scheme] else f":{port}"
    n.url = f"{scheme}://{n.host_for_url}{port_part}{path}" + (f"?{query}" if query else "")
    return n
