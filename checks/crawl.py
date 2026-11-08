"""Fetch the start page and crawl same-origin pages (shared by all other checks via ctx.pages)."""
import ssl
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".css", ".js", ".pdf", ".zip", ".gz",
            ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".xml", ".json", ".txt", ".exe", ".dmg")


@dataclass
class Page:
    url: str
    status: int
    headers: dict
    text: str
    cookies: list = field(default_factory=list)
    _soup: object = None

    @property
    def soup(self):
        if self._soup is None:
            self._soup = BeautifulSoup(self.text, "html.parser")
        return self._soup


def _fetch(ctx, url) -> Page:
    with ctx.client() as c:
        r = c.get(url)
    ctype = r.headers.get("content-type", "")
    text = r.text[:400_000] if ("html" in ctype or "text" in ctype or not ctype) else ""
    return Page(str(r.url), r.status_code, {k.lower(): v for k, v in r.headers.items()}, text,
                r.headers.get_list("set-cookie"))


def _is_ssl_error(e) -> bool:
    s = str(e).upper()
    return isinstance(e, ssl.SSLError) or "CERTIFICATE" in s or "SSL" in s


def run(target, ctx):
    try:
        ctx(f"GET {target}")
        try:
            home = _fetch(ctx, target)
        except httpx.ConnectError as e:
            if not _is_ssl_error(e):
                raise
            ctx("Certificate not trusted - continuing without verification")
            ctx.verify = False
            home = _fetch(ctx, target)
    except httpx.HTTPError as e:
        ctx(f"Could not fetch {target}: {e}")
        return []
    ctx.home = home
    ctx.pages[home.url] = home
    p = urlparse(home.url)
    ctx.base = f"{p.scheme}://{p.netloc}"
    ctx(f"Final URL {home.url} -> HTTP {home.status}")

    hosts, queue, seen = set(), [home.url], {home.url}
    limit = ctx.cfg["max_pages"]
    while queue:
        ctx.stop()
        url = queue.pop(0)
        page = ctx.pages.get(url)
        if page is None and len(ctx.pages) < limit:
            try:
                page = _fetch(ctx, url)
                ctx.pages[page.url] = page
            except httpx.HTTPError:
                continue
        if page is None:
            continue
        for tag in page.soup.find_all(["a", "link", "script", "img", "iframe"]):
            ref = tag.get("href") or tag.get("src")
            if not ref or ref.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
                continue
            absu = urldefrag(urljoin(page.url, ref))[0]
            u = urlparse(absu)
            if u.scheme not in ("http", "https") or not u.hostname:
                continue
            hosts.add(u.hostname.lower())
            if tag.name == "a" and u.netloc == p.netloc and absu not in seen \
                    and not u.path.lower().endswith(SKIP_EXT) and len(seen) < limit * 3:
                seen.add(absu)
                queue.append(absu)
    ctx.state["hosts"] = sorted(hosts)
    ctx(f"Crawled {len(ctx.pages)} page(s), {len(hosts)} distinct host(s) referenced")
    return []
