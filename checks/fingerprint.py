"""Technology fingerprinting: web server, language, CMS, frameworks, JS libraries, CDN/WAF, with versions."""
import re
import uuid

from .common import add
from .crawl import Page

# id -> (display name, kind, CPE (vendor, product) pairs used for the NVD lookup)
PRODUCTS = {
    "nginx": ("nginx", "web server", [("f5", "nginx"), ("nginx", "nginx")]),
    "apache": ("Apache HTTP Server", "web server", [("apache", "http_server")]),
    "iis": ("Microsoft IIS", "web server", [("microsoft", "internet_information_services")]),
    "openresty": ("OpenResty", "web server", []),
    "litespeed": ("LiteSpeed", "web server", [("litespeedtech", "litespeed_web_server")]),
    "lighttpd": ("lighttpd", "web server", [("lighttpd", "lighttpd")]),
    "tomcat": ("Apache Tomcat", "application server", [("apache", "tomcat")]),
    "jetty": ("Eclipse Jetty", "application server", [("eclipse", "jetty")]),
    "gunicorn": ("gunicorn", "application server", []),
    "php": ("PHP", "language", [("php", "php")]),
    "openssl": ("OpenSSL", "library", [("openssl", "openssl")]),
    "aspnet": ("ASP.NET", "framework", []),
    "wordpress": ("WordPress", "CMS", [("wordpress", "wordpress")]),
    "drupal": ("Drupal", "CMS", [("drupal", "drupal")]),
    "joomla": ("Joomla", "CMS", [("joomla", "joomla\\!")]),
    "typo3": ("TYPO3", "CMS", [("typo3", "typo3")]),
    "laravel": ("Laravel", "framework", []),
    "django": ("Django", "framework", []),
    "rails": ("Ruby on Rails", "framework", []),
    "express": ("Express", "framework", []),
    "nextjs": ("Next.js", "framework", []),
    "codeigniter": ("CodeIgniter", "framework", []),
    "java": ("Java (servlet)", "language", []),
    "cloudflare": ("Cloudflare", "CDN/WAF", []),
    "cloudfront": ("Amazon CloudFront", "CDN/WAF", []),
    "fastly": ("Fastly", "CDN/WAF", []),
    "akamai": ("Akamai", "CDN/WAF", []),
    "sucuri": ("Sucuri", "CDN/WAF", []),
    "vercel": ("Vercel", "hosting", []),
}
SERVER_NAMES = {"nginx": "nginx", "apache": "apache", "microsoft-iis": "iis", "openresty": "openresty",
                "litespeed": "litespeed", "lighttpd": "lighttpd", "gunicorn": "gunicorn", "jetty": "jetty",
                "php": "php", "openssl": "openssl", "apache-coyote": "tomcat"}
DISTRO = re.compile(r"\((Ubuntu|Debian|CentOS|Red Hat|RHEL|Fedora|Amazon|SUSE|Alpine|Unix)[^)]*\)", re.I)
JS_LIB = re.compile(r"(?i)(jquery-ui|jquery|bootstrap|angular(?:js)?|lodash|moment|vue|react|handlebars|"
                    r"underscore|backbone|select2|chart\.js|dompurify)[-./@_](?:dist/|js/|min/)?v?(\d+\.\d+(?:\.\d+)?)")
JS_BANNERS = [("jquery", r"jQuery(?: JavaScript Library)? v?(\d+\.\d+(?:\.\d+)?)"),
              ("bootstrap", r"Bootstrap(?: v|\s)v?(\d+\.\d+(?:\.\d+)?)")]
COOKIES = {"PHPSESSID": "php", "JSESSIONID": "java", "ASP.NET_SessionId": "aspnet", "laravel_session": "laravel",
           "csrftoken": "django", "connect.sid": "express", "ci_session": "codeigniter"}


def parse_server(value: str):
    """'Apache/2.4.52 (Ubuntu)' -> [('apache', '2.4.52', backport=True)]"""
    res = []
    backport = bool(DISTRO.search(value))
    for m in re.finditer(r"([A-Za-z][\w\-]*)/(\d[\w.\-]*)", value):
        pid = SERVER_NAMES.get(m.group(1).lower())
        if pid:
            res.append((pid, m.group(2), backport))
    return res


def js_from_url(url: str):
    m = JS_LIB.search(url)
    if not m:
        return None
    name = m.group(1).lower()
    return ("angular" if name.startswith("angular") else name, m.group(2))


class Found:
    def __init__(self):
        self.items = {}

    def add(self, pid, version, source, confidence, backport=False):
        cur = self.items.get(pid)
        rank = {"low": 0, "medium": 1, "high": 2}
        if cur is None or (version and not cur["version"]) or (version and rank[confidence] > rank[cur["confidence"]]):
            self.items[pid] = dict(id=pid, version=version, source=source, confidence=confidence, backport=backport)


def detect(page: Page, found: Found):
    h = page.headers
    if "server" in h:
        for pid, ver, bp in parse_server(h["server"]):
            found.add(pid, ver, f"Server: {h['server']}", "high", bp)
        low = h["server"].lower()
        for needle, pid in (("cloudflare", "cloudflare"), ("akamai", "akamai"), ("sucuri", "sucuri")):
            if needle in low:
                found.add(pid, None, f"Server: {h['server']}", "high")
    if "x-powered-by" in h:
        xp = h["x-powered-by"]
        for pid, ver, bp in parse_server(xp):
            found.add(pid, ver, f"X-Powered-By: {xp}", "high", bp)
        for needle, pid in (("asp.net", "aspnet"), ("express", "express"), ("next.js", "nextjs")):
            if needle in xp.lower():
                found.add(pid, None, f"X-Powered-By: {xp}", "high")
    if h.get("x-aspnet-version"):
        found.add("aspnet", h["x-aspnet-version"], f"X-AspNet-Version: {h['x-aspnet-version']}", "high")
    if "x-pingback" in h:
        found.add("wordpress", None, "X-Pingback header", "medium")
    if "x-drupal-cache" in h or "x-drupal-dynamic-cache" in h:
        found.add("drupal", None, "X-Drupal-Cache header", "high")
    gen = h.get("x-generator", "")
    m = re.match(r"(WordPress|Drupal|Joomla)[!\s]*v?(\d+(?:\.\d+)*)?", gen, re.I)
    if m:
        found.add(m.group(1).lower(), m.group(2), f"X-Generator: {gen}", "high")
    if "cf-ray" in h:
        found.add("cloudflare", None, "cf-ray header", "high")
    if "x-amz-cf-id" in h:
        found.add("cloudfront", None, "x-amz-cf-id header", "high")
    if "x-vercel-id" in h:
        found.add("vercel", None, "x-vercel-id header", "high")
    if "x-sucuri-id" in h:
        found.add("sucuri", None, "x-sucuri-id header", "high")
    if "fastly" in h.get("x-served-by", "").lower() or "x-fastly-request-id" in h:
        found.add("fastly", None, "Fastly headers", "medium")
    for sc in page.cookies:
        name = sc.split("=", 1)[0]
        if name in COOKIES:
            found.add(COOKIES[name], None, f"Cookie {name}", "medium")


def detect_html(page: Page, found: Found):
    html, soup = page.text, page.soup
    gen = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    if gen and gen.get("content"):
        c = gen["content"]
        m = re.match(r"(WordPress|Drupal|Joomla!?|TYPO3)(?: CMS)?\s*v?(\d+(?:\.\d+)*)?", c, re.I)
        if m:
            found.add(m.group(1).lower().rstrip("!"), m.group(2), f'meta generator: "{c}"', "high")
    if "/wp-content/" in html or "/wp-includes/" in html:
        found.add("wordpress", None, "/wp-content/ or /wp-includes/ paths in HTML", "high")
        m = re.search(r"wp-(?:emoji-release|embed)\.min\.js\?ver=(\d+\.\d+(?:\.\d+)?)", html)
        if m:
            found.add("wordpress", m.group(1), "wp-emoji-release.min.js?ver=", "medium")
    if "/sites/default/files" in html or "Drupal.settings" in html:
        found.add("drupal", None, "Drupal paths in HTML", "high")
    if "/media/jui/" in html or "/media/system/js/" in html:
        found.add("joomla", None, "Joomla media paths in HTML", "high")
    if "typo3conf/" in html or "typo3temp/" in html:
        found.add("typo3", None, "typo3conf/ paths in HTML", "high")
    if "csrfmiddlewaretoken" in html or "/static/admin/" in html:
        found.add("django", None, "Django markers in HTML", "medium")
    if "__NEXT_DATA__" in html or "/_next/static/" in html:
        found.add("nextjs", None, "Next.js markers in HTML", "high")


def run(target, ctx):
    out = []
    if ctx.home is None:
        return out
    found = Found()
    for page in ctx.pages.values():
        detect(page, found)
        detect_html(page, found)

    # error page (also used by exposure checks): often reveals the server banner
    if ctx.cfg["paths"] >= 1:
        try:
            r = ctx.probe(f"{ctx.base}/__secaudit_{uuid.uuid4().hex[:8]}", maxbytes=6000)
            if r:
                status, hdrs, body = r
                text = body.decode("utf-8", "ignore")
                ctx.state["err404"] = Page(ctx.base, status, hdrs, text)
                m = re.search(r"(Apache Tomcat|Apache|nginx|Microsoft-IIS|openresty|LiteSpeed)/(\d[\d.]*)", text)
                if m:
                    pid = SERVER_NAMES.get(m.group(1).lower(), "tomcat" if "Tomcat" in m.group(1) else None)
                    if pid:
                        found.add(pid, m.group(2), "Error page banner", "medium", bool(DISTRO.search(text)))
        except Exception as e:
            ctx(f"Fingerprint: error-page probe failed: {e}")

    # version files for CMSs when only the product (not the version) is known
    if ctx.cfg["paths"] >= 1:
        probes = {"wordpress": [("/readme.html", r"Version\s+(\d+\.\d+(?:\.\d+)?)"),
                                ("/feed/", r"wordpress\.org/\?v=(\d+\.\d+(?:\.\d+)?)")],
                  "drupal": [("/CHANGELOG.txt", r"Drupal (\d+\.\d+(?:\.\d+)?)")],
                  "joomla": [("/administrator/manifests/files/joomla.xml", r"<version>(\d+\.\d+(?:\.\d+)?)</version>")]}
        for pid, items in probes.items():
            cur = found.items.get(pid)
            if cur and not cur["version"]:
                for path, rx in items:
                    r = ctx.probe(ctx.base + path, maxbytes=6000)
                    if r and r[0] == 200:
                        m = re.search(rx, r[2].decode("utf-8", "ignore"))
                        if m:
                            found.add(pid, m.group(1), f"{path}", "high")
                            break

    # JavaScript libraries from script URLs (and banners of first-party files)
    js, seen = [], set()
    fetched = 0
    for page in ctx.pages.values():
        for s in page.soup.find_all("script", src=True):
            src = s["src"]
            hit = js_from_url(src)
            if hit and hit not in seen:
                seen.add(hit)
                js.append(dict(lib=hit[0], version=hit[1], url=src))
            elif not hit and fetched < 5 and ctx.cfg["paths"] >= 1 and any(n in src.lower() for n in ("jquery", "bootstrap")) \
                    and (src.startswith("/") or ctx.base in src):
                fetched += 1
                full = src if src.startswith("http") else ctx.base + src
                r = ctx.probe(full, maxbytes=800)
                if r and r[0] == 200:
                    for lib, rx in JS_BANNERS:
                        m = re.search(rx, r[2].decode("utf-8", "ignore"))
                        if m and (lib, m.group(1)) not in seen:
                            seen.add((lib, m.group(1)))
                            js.append(dict(lib=lib, version=m.group(1), url=src))
    ctx.state["js"] = js

    tech = []
    for pid, d in found.items.items():
        display, kind, cpe = PRODUCTS[pid]
        tech.append(dict(id=pid, display=display, kind=kind, cpe=cpe, version=d["version"], confidence=d["confidence"],
                         backport=d["backport"], source=d["source"]))
        add(out, None, "tech_detected", d["source"], confidence=d["confidence"], product=display,
            version=d["version"] or "(version unknown)", kind=kind)
    for j in js:
        add(out, None, "tech_detected", j["url"], confidence="medium", product=j["lib"], version=j["version"], kind="JavaScript")
    ctx.state["tech"] = tech
    ctx(f"Fingerprint: {len(tech)} technologies, {len(js)} JS libraries")
    return out
