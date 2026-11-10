"""Lookup provider interface, a rate limiter, and deterministic mock providers.

A real provider (WHOIS/RDAP client, TLS handshake, reputation API) only has to
implement `LookupProvider`. Nothing else in the pipeline changes.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Callable, Protocol

from .targets import REGISTRATION, REPUTATION, TLS


@dataclass
class LookupResult:
    status: str                 # "ok" | "not_found" | "error"
    payload: dict = field(default_factory=dict)
    error: str | None = None


class LookupProvider(Protocol):
    name: str
    lookup_type: str

    def lookup(self, target_key: str, attrs: dict) -> LookupResult: ...


class RateLimiter:
    """Simple per-provider rate limit: at most `per_second` calls per second.

    `clock` and `sleep` are injectable so tests don't actually wait.
    per_second <= 0 disables limiting.
    """

    def __init__(self, per_second: float, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.interval = 1.0 / per_second if per_second > 0 else 0.0
        self.clock, self.sleep = clock, sleep
        self._next = 0.0

    def acquire(self) -> None:
        if not self.interval:
            return
        now = self.clock()
        if now < self._next:
            self.sleep(self._next - now)
            now = self._next
        self._next = now + self.interval


# --------------------------------------------------------------------------- #
# Mocks: deterministic (same key -> same answer) so example output is stable.
# --------------------------------------------------------------------------- #

def _h(key: str) -> int:
    return int(hashlib.sha256(key.encode()).hexdigest(), 16)


SUSPICIOUS_MARKERS = ("paypal-update", "hsbc-security", "chase-verify", "bad-example",
                      "45.33.32.156", "mirai", "payload.exe")


class MockRegistrationProvider:
    """Treats every domain as registered, including reserved TLDs such as
    .test and .example, so exercise data behaves like real sites.
    A real RDAP service would return "not found" for reserved TLDs; see README."""

    name, lookup_type = "mock-rdap", REGISTRATION

    def __init__(self):
        self.calls = 0

    def lookup(self, target_key: str, attrs: dict) -> LookupResult:
        self.calls += 1
        h = _h(target_key)
        young = any(m in target_key for m in SUSPICIOUS_MARKERS)
        created = date(2026, 10, 1) - timedelta(days=h % 20 if young else 1000 + h % 6000)
        return LookupResult("ok", {
            "domain": target_key,
            "registrar": ["Example Registrar Inc.", "NameCheap-ish LLC", "MarkMonitor-ish"][h % 3],
            "created": created.isoformat(),
            "privacy_protected": bool(h % 2),
        })


class MockTLSProvider:
    name, lookup_type = "mock-tls", TLS

    def __init__(self):
        self.calls = 0

    def lookup(self, target_key: str, attrs: dict) -> LookupResult:
        self.calls += 1
        h = _h(target_key)
        if h % 7 == 0:
            return LookupResult("not_found", {"note": "no TLS listener on this port"})
        host = attrs.get("sni") or attrs.get("host")
        return LookupResult("ok", {
            "subject_cn": host,
            "issuer": ["Let's Encrypt R11", "DigiCert TLS RSA", "Self-signed"][h % 3],
            "not_after": (date(2027, 1, 1) + timedelta(days=h % 300)).isoformat(),
            "sha256": hashlib.sha256(target_key.encode()).hexdigest()[:16],
        })


class MockReputationProvider:
    name, lookup_type = "mock-reputation", REPUTATION

    def __init__(self):
        self.calls = 0

    def lookup(self, target_key: str, attrs: dict) -> LookupResult:
        self.calls += 1
        if any(m in target_key for m in SUSPICIOUS_MARKERS):
            verdict, score = "malicious", 85 + _h(target_key) % 15
        else:
            verdict, score = ("clean", _h(target_key) % 10) if _h(target_key) % 4 else ("unknown", 50)
        return LookupResult("ok", {"verdict": verdict, "score": score})


def default_providers() -> dict[str, LookupProvider]:
    return {p.lookup_type: p for p in (MockRegistrationProvider(), MockTLSProvider(),
                                        MockReputationProvider())}
