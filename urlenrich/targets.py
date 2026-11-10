"""Derive the lookup target for each enrichment type from a normalized URL.

The same URL produces three different targets, because each service answers a
different question:

    registration  "who owns this domain?"      -> registrable domain (eTLD+1)
    tls           "what cert does this serve?" -> host:port
    reputation    "is this exact URL bad?"     -> full normalized URL

Coarser targets are shared by more URLs, which is where most of the request
savings come from (many URLs -> fewer hosts -> fewer domains).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import tldextract

from .normalize import NormalizedURL

REGISTRATION = "registration"
TLS = "tls"
REPUTATION = "reputation"
LOOKUP_TYPES = (REGISTRATION, TLS, REPUTATION)

# suffix_list_urls=() -> use the Public Suffix List snapshot bundled with
# tldextract instead of downloading it: offline, fast, and reproducible.
# include_psl_private_domains=False -> ICANN suffixes only. With private
# suffixes, "alice.github.io" would be its own "domain", but WHOIS only knows
# "github.io". The private-suffix view is kept separately as `site` metadata.
_ICANN = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)
_WITH_PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


@dataclass(frozen=True)
class Target:
    lookup_type: str
    key: str
    derivation: str                     # why/how this target was derived
    attrs: dict = field(default_factory=dict, compare=False, hash=False)


@dataclass
class Derived:
    targets: list[Target]
    skipped: dict[str, str]             # lookup_type -> reason it doesn't apply
    registrable_domain: str | None
    site: str | None                    # private-suffix aware eTLD+1 (e.g. alice.github.io)


def registrable_domain(host: str) -> tuple[str | None, bool]:
    """Return (eTLD+1, suffix_known)."""
    ext = _ICANN(host)
    if ext.suffix and ext.domain:
        return f"{ext.domain}.{ext.suffix}", True
    if not ext.suffix:
        # Suffix not in the list (e.g. reserved ".example", or a TLD newer than
        # the bundled snapshot). Apply the PSL default rule "*": the last label
        # is the suffix, so the registrable domain is the last two labels.
        labels = host.split(".")
        return ".".join(labels[-2:]), False
    return None, True   # host *is* a public suffix, e.g. "co.uk"


def site_domain(host: str) -> str | None:
    ext = _WITH_PRIVATE(host)
    if ext.suffix and ext.domain:
        return f"{ext.domain}.{ext.suffix}"
    return None


def derive(n: NormalizedURL) -> Derived:
    targets: list[Target] = []
    skipped: dict[str, str] = {}
    reg_domain = site = None

    # Registration: domains only. An IP literal has no domain registration
    # (IP ownership lives in RIR/ASN data, a different lookup type).
    if n.host_type == "domain":
        reg_domain, suffix_known = registrable_domain(n.host)
        site = site_domain(n.host) or reg_domain
        if reg_domain:
            attrs = {} if suffix_known else {"suffix_rule": "psl_default_rule"}
            targets.append(Target(REGISTRATION, reg_domain, "registrable_domain", attrs))
        else:
            skipped[REGISTRATION] = "host_is_public_suffix"
    else:
        skipped[REGISTRATION] = f"{n.host_type}_literal_has_no_domain"

    # TLS: a certificate belongs to a host:port endpoint, not to a path.
    #   https  -> the port in the URL
    #   http   -> host:443 (inferred). The cert lookup doesn't follow the URL or
    #            its redirects; it only asks "does this host serve TLS on 443,
    #            and with which cert?". Usually dedupes with an https target.
    #   ftp    -> skipped (FTPS is out of scope for this lookup type)
    endpoint_host = n.host_for_url
    sni = n.host if n.host_type == "domain" else None
    if n.scheme == "https":
        targets.append(Target(TLS, f"{endpoint_host}:{n.port}", "explicit_https",
                              {"host": n.host, "port": n.port, "sni": sni}))
    elif n.scheme == "http":
        targets.append(Target(TLS, f"{endpoint_host}:443", "inferred_from_http",
                              {"host": n.host, "port": 443, "sni": sni}))
    else:
        skipped[TLS] = f"scheme_{n.scheme}_not_tls"

    # Reputation: the whole normalized URL. Path and query matter here,
    # because one host can serve both a clean page and a phishing kit.
    targets.append(Target(REPUTATION, n.url, "normalized_url"))

    return Derived(targets=targets, skipped=skipped, registrable_domain=reg_domain, site=site)
