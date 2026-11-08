"""HTTPS redirect, HSTS, security headers, security.txt, cookies, version disclosure."""
import re
from urllib.parse import urlparse

import httpx

from .common import add, host_of, https_port


def _redirect(host, out, ctx):
    ctx(f"GET http://{host}/ (redirect test)")
    try:
        with ctx.client(follow=False) as c:
            r = c.get(f"http://{host}/")
    except httpx.HTTPError:
        add(out, True, "http_redirect", "Port 80 closed or unreachable")
        return
    loc = r.headers.get("location", "")
    ok = r.status_code in (301, 302, 303, 307, 308) and loc.startswith("https://")
    add(out, ok, "http_redirect", f"HTTP {r.status_code} Location: {loc or '-'}")


def evaluate_hsts(value: str) -> dict:
    m = re.search(r"max-age=(\d+)", value, re.I)
    return dict(max_age=int(m.group(1)) if m else 0, subdomains="includesubdomains" in value.lower(),
                preload="preload" in value.lower())


def run(target, ctx):
    out = []
    p = urlparse(target)
    host = host_of(target)
    if p.scheme == "https" and https_port(target) == 443:
        _redirect(host, out, ctx)
    home = ctx.home
    if home is None:
        add(out, False, "https_available", "The start page could not be fetched")
        return out
    h = home.headers
    https = home.url.startswith("https://")
    add(out, https, "https_available", home.url)

    if https:
        hsts = h.get("strict-transport-security")
        add(out, bool(hsts), "hsts_present", hsts or "No Strict-Transport-Security header")
        if hsts:
            ev = evaluate_hsts(hsts)
            add(out, ev["max_age"] >= 31536000, "hsts_maxage", hsts)
            add(out, ev["subdomains"], "hsts_subdomains", hsts, optional=True)
            add(out, ev["preload"], "hsts_preload", hsts, optional=True)

    csp = h.get("content-security-policy")
    add(out, bool(csp), "csp_present", csp or "No CSP header")
    if csp:
        add(out, not ("unsafe-inline" in csp or "unsafe-eval" in csp), "csp_weak", csp)
    framed = "x-frame-options" in h or "frame-ancestors" in (csp or "")
    add(out, framed, "frame_protection", h.get("x-frame-options", "none"))
    add(out, h.get("x-content-type-options", "").lower() == "nosniff", "nosniff", h.get("x-content-type-options", "none"))
    add(out, "referrer-policy" in h, "referrer_policy", h.get("referrer-policy", "none"))
    add(out, "permissions-policy" in h, "permissions_policy", h.get("permissions-policy", "none"), optional=True)

    try:
        with ctx.client() as c:
            s = c.get(ctx.base + "/.well-known/security.txt")
        ok = s.status_code == 200 and "contact:" in s.text.lower()
    except httpx.HTTPError:
        ok = False
    add(out, ok, "security_txt", ctx.base + "/.well-known/security.txt", optional=True)

    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if hdr in h and any(ch.isdigit() for ch in h[hdr]):
            add(out, False, "version_disclosure", f"{hdr}: {h[hdr]}", confidence="medium", header=hdr)

    seen = set()
    for page in ctx.pages.values():
        for sc in page.cookies:
            name = sc.split("=", 1)[0]
            if name in seen:
                continue
            seen.add(name)
            low = sc.lower()
            missing = [f for f, good in (("Secure", "secure" in low), ("HttpOnly", "httponly" in low),
                                         ("SameSite", "samesite" in low)) if not good]
            sev = "Medium" if ("HttpOnly" in missing or "Secure" in missing) else "Low"
            add(out, not missing, "cookie_flags", sc[:200] + (f"  [missing: {', '.join(missing)}]" if missing else ""),
                severity=sev, name=name)
    return out
