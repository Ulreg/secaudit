"""Shared helpers: scan context (rate limit, cancel, timeouts), profiles and result builder."""
import socket
import ssl
import threading
import time
from urllib.parse import urlparse

import httpx

import knowledge

UA = "SecAuditTool/1.0"

PROFILES = {
    "quick": dict(max_pages=1, paths=0, ciphers=False, dkim=False, probes=False, takeover=False, max_products=3),
    "standard": dict(max_pages=15, paths=1, ciphers=True, dkim=False, probes=False, takeover=True, max_products=6),
    "thorough": dict(max_pages=30, paths=2, ciphers=True, dkim=True, probes=True, takeover=True, max_products=10),
}


class Cancelled(Exception):
    """Raised inside a check when the user cancels the scan."""


class Ctx:
    """Passed to every check. Callable: ctx("message") writes to the scan log."""

    def __init__(self, profile="standard", rate=5.0, log=print, cancel=None, nvd_key=None, cache=None):
        self.profile = profile
        self.cfg = PROFILES[profile]
        self.rate = max(rate, 0.1)
        self._log = log
        self.cancel = cancel or threading.Event()
        self.deadline = None
        self.verify = True
        self.nvd_key = nvd_key
        self.cache = cache
        self.pages = {}      # url -> Page (crawl results)
        self.home = None     # Page of the start URL
        self.base = None     # scheme://host of the final start URL
        self.state = {}      # cross-module data (tech list, hosts, ...)
        self._lock = threading.Lock()
        self._next = 0.0

    def __call__(self, msg):
        self._log(msg)

    def stop(self):
        if self.cancel.is_set():
            raise Cancelled()
        if self.deadline and time.monotonic() > self.deadline:
            raise TimeoutError("check timed out")

    def _hook(self, request):
        self.stop()
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            self._next = max(now, self._next) + 1.0 / self.rate
        if wait > 0:
            time.sleep(wait)

    def client(self, follow=True, headers=None, **kw):
        h = {"User-Agent": UA, **(headers or {})}
        return httpx.Client(follow_redirects=follow, timeout=10, verify=self.verify, headers=h,
                            event_hooks={"request": [self._hook]}, **kw)

    def probe(self, url, maxbytes=2048, headers=None):
        """GET but read at most `maxbytes` of the body. Returns (status, headers, bytes) or None."""
        try:
            with self.client(follow=False, headers=headers) as c:
                with c.stream("GET", url) as r:
                    data = b""
                    for chunk in r.iter_bytes(1024):
                        data += chunk
                        if len(data) >= maxbytes:
                            break
                    return r.status_code, {k.lower(): v for k, v in r.headers.items()}, data[:maxbytes]
        except (Cancelled, TimeoutError):
            raise
        except httpx.HTTPError:
            return None


def host_of(target: str) -> str:
    return urlparse(target).hostname


def https_port(target: str):
    """TLS port to test, or None if the target is plain HTTP on a custom port."""
    p = urlparse(target)
    if p.scheme == "https":
        return p.port or 443
    return None if p.port else 443


def add(out, ok, key, evidence="", severity=None, confidence="high", optional=False, **params):
    """Append a result. ok=True -> Pass; ok=False -> severity from YAML (or override); ok=None -> Info."""
    if ok is False and optional:
        ok = None
    e = knowledge.entry(key)
    default = (e or {}).get("sev", "Medium")
    sev = "Pass" if ok else ("Info" if ok is None else (severity or default))
    out.append(dict(key=key, category=(e or {}).get("cat", "Other"), severity=sev, confidence=confidence,
                    evidence=str(evidence), params=params))


def fetch_der(host, port, timeout=8) -> bytes:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            return ss.getpeercert(binary_form=True)
