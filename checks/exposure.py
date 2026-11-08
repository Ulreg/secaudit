"""Exposed files, directory listing, HTTP methods, CORS, WordPress specifics, error disclosure and
crawl-based web application checks (mixed content, forms, SRI, third-party scripts, trackers)."""
import re
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from .common import add

MARK = "SecAuditProbe7x9k"


def _env(t, b, h):
    return bool(re.search(r"^[A-Z][A-Z0-9_]{2,}\s*=", t, re.M)) and "<html" not in t[:300].lower()


def _contains(*needles):
    return lambda t, b, h: any(n in t for n in needles)


def _regex(rx):
    return lambda t, b, h: bool(re.search(rx, t))


SQL = _regex(r"(INSERT INTO|CREATE TABLE|MySQL dump|PostgreSQL database dump)")
ZIP = lambda t, b, h: b.startswith(b"PK\x03\x04")
GZ = lambda t, b, h: b[:2] == b"\x1f\x8b"
WPCFG = _contains("DB_PASSWORD", "DB_NAME")
LOGRX = _regex(r"PHP (Notice|Warning|Fatal|Deprecated)|\[\d{2}-\w{3}-\d{4}|\.(ERROR|WARNING):|Stack trace")

# (path, key, validator, minimum level, extra add() params)
PATHS = [
    ("/.git/HEAD", "exposed_git", lambda t, b, h: t.startswith("ref:"), 1, {}),
    ("/.env", "exposed_env", _env, 1, {}),
    ("/.DS_Store", "exposed_dsstore", lambda t, b, h: b.startswith(b"\x00\x00\x00\x01Bud1"), 1, {}),
    ("/phpinfo.php", "exposed_phpinfo", _contains("phpinfo()", "PHP Version"), 1, {}),
    ("/info.php", "exposed_phpinfo", _contains("phpinfo()", "PHP Version"), 1, {}),
    ("/server-status", "exposed_serverstatus", _contains("Apache Server Status"), 1, {}),
    ("/server-info", "exposed_serverstatus", _contains("Apache Server Information"), 1, {}),
    ("/.htpasswd", "exposed_htpasswd", _regex(r"^[^\s:]+:(\$apr1\$|\{SHA\}|\$2[aby]\$)"), 1, {}),
    ("/wp-config.php.bak", "exposed_config", WPCFG, 1, {}),
    ("/wp-config.php.old", "exposed_config", WPCFG, 1, {}),
    ("/wp-config.php~", "exposed_config", WPCFG, 1, {}),
    ("/web.config", "exposed_config", _contains("<configuration"), 1, {}),
    ("/WEB-INF/web.xml", "exposed_config", _contains("<web-app"), 1, {}),
    ("/backup.zip", "exposed_backup", ZIP, 1, {}),
    ("/backup.sql", "exposed_backup", SQL, 1, {}),
    ("/db.sql", "exposed_backup", SQL, 1, {}),
    ("/dump.sql", "exposed_backup", SQL, 1, {}),
    ("/site.zip", "exposed_backup", ZIP, 1, {}),
    ("/www.zip", "exposed_backup", ZIP, 1, {}),
    ("/backup.tar.gz", "exposed_backup", GZ, 1, {}),
    ("/.svn/wc.db", "exposed_vcs", _contains("SQLite format 3"), 1, {}),
    ("/.hg/requires", "exposed_vcs", _contains("revlogv1", "store"), 1, {}),
    ("/wp-content/debug.log", "exposed_debuglog", LOGRX, 1, {}),
    ("/storage/logs/laravel.log", "exposed_debuglog", LOGRX, 1, {}),
    ("/error_log", "exposed_debuglog", LOGRX, 1, {}),
    ("/actuator/env", "exposed_actuator", _contains("propertySources", "activeProfiles"), 1, {}),
    ("/swagger.json", "api_docs", _regex(r'(?i)"(swagger|openapi)"'), 1, {}),
    ("/openapi.json", "api_docs", _regex(r'(?i)"openapi"'), 1, {}),
    ("/v2/api-docs", "api_docs", _regex(r'(?i)"swagger"'), 1, {}),
    ("/swagger-ui.html", "api_docs", _contains("swagger-ui", "Swagger UI"), 1, {}),
    ("/phpmyadmin/", "admin_panel", _contains("phpMyAdmin"), 1, {"severity": "Medium"}),
    ("/adminer.php", "admin_panel", _contains("Adminer"), 1, {"severity": "Medium"}),
    ("/wp-login.php", "admin_panel", _contains("user_login"), 1, {}),
    # level 2 (thorough)
    ("/.env.local", "exposed_env", _env, 2, {}),
    ("/.env.production", "exposed_env", _env, 2, {}),
    ("/.env.backup", "exposed_env", _env, 2, {}),
    ("/.env.old", "exposed_env", _env, 2, {}),
    ("/wp-config.php.save", "exposed_config", WPCFG, 2, {}),
    ("/config.php.bak", "exposed_config", _contains("password", "DB_"), 2, {}),
    ("/database.sql", "exposed_backup", SQL, 2, {}),
    ("/backup.sql.gz", "exposed_backup", GZ, 2, {}),
    ("/backup.tar", "exposed_backup", lambda t, b, h: b[257:262] == b"ustar", 2, {}),
    ("/administrator/", "admin_panel", _contains("Joomla"), 2, {}),
    ("/user/login", "admin_panel", _contains("Drupal", "drupal"), 2, {}),
    ("/jenkins/", "admin_panel", _contains("Jenkins"), 2, {"severity": "Medium"}),
    ("/manager/html", "admin_panel", _contains("Tomcat"), 2, {"severity": "Medium"}),
    ("/actuator/heapdump", "exposed_actuator", lambda t, b, h: b.startswith(b"JAVA PROFILE"), 2, {}),
]
DIRS = ["/uploads/", "/wp-content/uploads/", "/images/", "/files/", "/img/", "/assets/", "/backup/", "/backups/",
        "/old/", "/tmp/", "/temp/", "/test/", "/logs/"]
DIR_RX = re.compile(r"<title>Index of /|<h1>Index of /|Directory listing for /|Parent Directory</a>")
ERR_RX = re.compile(r"Traceback \(most recent call last\)|Stack trace:|Fatal error:|Parse error:|"
                    r"Warning:\s.{0,120}\son line \d+|\bat [\w.$]+\([\w.]+\.java:\d+\)|Whoops!|Unhandled Exception|"
                    r"Server Error in '/' Application|Whitelabel Error Page|SQLSTATE\[|You have an error in your SQL syntax")
TRACKERS = ("google-analytics.com", "googletagmanager.com", "facebook.net", "connect.facebook", "hotjar.com",
            "doubleclick.net", "clarity.ms", "snap.licdn.com", "analytics.tiktok.com", "static.ads-twitter.com")
REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "next", "return", "returnurl", "return_url", "goto", "dest",
                   "destination", "continue", "target", "redir"}


def _site_host(host):
    return host[4:] if host.startswith("www.") else host


def _external(host, site):
    return bool(host) and not (host == site or host.endswith("." + site))


def analyze_pages(pages: dict, site_host: str) -> list:
    """Pure analysis of crawled HTML (no network access)."""
    out = []
    site = _site_host(site_host)
    mixed, forms_http, csrf, no_sri, ext_hosts, trackers, redirects = [], [], [], [], set(), set(), []
    for page in pages.values():
        https = page.url.startswith("https://")
        soup = page.soup
        for tag in soup.find_all(["script", "img", "iframe", "audio", "video", "source", "embed"], src=True):
            src = tag["src"]
            if https and src.startswith("http://"):
                mixed.append(src)
            h = urlparse(src).hostname
            if tag.name == "script" and _external(h, site):
                ext_hosts.add(h)
                if not tag.get("integrity"):
                    no_sri.append(src)
                if any(t in src for t in TRACKERS):
                    trackers.add(h)
        for tag in soup.find_all("link", href=True):
            rel = " ".join(tag.get("rel", []))
            if "stylesheet" in rel:
                if https and tag["href"].startswith("http://"):
                    mixed.append(tag["href"])
                h = urlparse(tag["href"]).hostname
                if _external(h, site) and not tag.get("integrity"):
                    no_sri.append(tag["href"])
        for t in TRACKERS:
            if t in page.text:
                trackers.add(t)
        for form in soup.find_all("form"):
            action = form.get("action", "")
            has_pw = bool(form.find("input", attrs={"type": "password"}))
            if (https and action.startswith("http://")) or (not https and has_pw):
                forms_http.append(f"{page.url} -> {action or '(same page)'}")
            if (form.get("method", "get").lower() == "post"):
                names = [(i.get("name") or "").lower() for i in form.find_all("input")]
                visible = [i for i in form.find_all("input") if i.get("type", "text") not in ("hidden", "submit", "button")]
                token = any(re.search(r"csrf|token|nonce|authenticity|xsrf|_wp", n) for n in names)
                search = all(n in ("q", "s", "search", "query", "") for n in names if n) and names
                if visible and not token and not search:
                    csrf.append(f"{page.url} -> {action or '(same page)'}")
        for a in soup.find_all("a", href=True):
            q = parse_qs(urlparse(a["href"]).query)
            for k, v in q.items():
                if k.lower() in REDIRECT_PARAMS and v and (v[0].startswith(("http", "/")) or "." in v[0]):
                    redirects.append(a["href"])
    add(out, not mixed, "mixed_content", "; ".join(sorted(set(mixed))[:5]) or "none")
    add(out, not forms_http, "form_http", "; ".join(forms_http[:5]) or "none")
    add(out, not csrf, "form_csrf", "; ".join(csrf[:5]) or "none", confidence="low")
    add(out, not no_sri, "sri_missing", "; ".join(sorted(set(no_sri))[:5]) or "none", confidence="high")
    if ext_hosts:
        add(out, None, "third_party_scripts", ", ".join(sorted(ext_hosts)))
    if trackers:
        add(out, None, "tracking_consent", ", ".join(sorted(trackers)), confidence="low")
    if redirects:
        add(out, None, "open_redirect_param", "; ".join(sorted(set(redirects))[:5]), confidence="low")
    return out


def _paths(ctx, out, lvl):
    tested, found = {}, {}
    for path, key, valid, minlvl, extra in PATHS:
        if lvl < minlvl:
            continue
        ctx.stop()
        tested.setdefault(key, []).append(path)
        r = ctx.probe(ctx.base + path, maxbytes=4096)
        if not r or r[0] != 200:
            continue
        status, hdrs, raw = r
        text = raw.decode("utf-8", "ignore")
        if valid(text, raw, hdrs):
            found.setdefault(key, []).append((path, text[:120].replace("\n", " "), extra))
    for key, ps in tested.items():
        label = ", ".join(ps[:2]) + (", …" if len(ps) > 2 else "")
        if key in found:
            for path, snippet, extra in found[key]:
                add(out, False, key, f"{ctx.base}{path}  ->  {snippet}", path=path, **extra)
        else:
            add(out, True, key, f"{len(ps)} path(s) checked", path=label)


def _dirs(ctx, out, lvl):
    dirs = DIRS[:4] if lvl == 1 else list(DIRS)
    for url in ctx.pages:
        p = urlparse(url).path
        if p.count("/") >= 2:
            d = p.rsplit("/", 1)[0] + "/"
            if d not in dirs and len(dirs) < 20:
                dirs.append(d)
    found = []
    for d in dirs:
        ctx.stop()
        r = ctx.probe(ctx.base + d, maxbytes=4096)
        if r and r[0] == 200 and DIR_RX.search(r[2].decode("utf-8", "ignore")):
            found.append(d)
    for d in found:
        add(out, False, "dir_listing", ctx.base + d, path=d)
    if not found:
        add(out, True, "dir_listing", f"{len(dirs)} directories checked", path=", ".join(dirs[:2]) + ", …")


def _robots(ctx, out):
    r = ctx.probe(ctx.base + "/robots.txt", maxbytes=20000)
    if r and r[0] == 200:
        paths = [m.group(1).strip() for m in re.finditer(r"(?im)^disallow:\s*(\S+)", r[2].decode("utf-8", "ignore"))]
        paths = [p for p in paths if p not in ("/", "/wp-admin/", "/wp-admin/admin-ajax.php")]
        if paths:
            add(out, None, "robots_paths", ", ".join(paths[:10]))


def _methods(ctx, out):
    try:
        with ctx.client(follow=False) as c:
            o = c.request("OPTIONS", ctx.base + "/")
            t = c.request("TRACE", ctx.base + "/")
    except httpx.HTTPError as e:
        ctx(f"Exposure: methods test failed: {e}")
        return
    allow = {m.strip().upper() for m in (o.headers.get("allow", "") + "," + o.headers.get("public", "")).split(",") if m.strip()}
    risky = sorted(allow & {"PUT", "DELETE", "CONNECT", "TRACE", "PROPFIND", "MKCOL"})
    add(out, not risky, "methods_risky", f"Allow: {', '.join(sorted(allow)) or '-'}", confidence="low",
        methods=", ".join(risky) or "-")
    add(out, not (t.status_code == 200 and "TRACE /" in t.text), "methods_trace", f"TRACE -> HTTP {t.status_code}")


def _cors(ctx, out):
    evil = "https://evil.example"
    try:
        with ctx.client(headers={"Origin": evil}) as c:
            r = c.get(ctx.base + "/")
    except httpx.HTTPError:
        return
    acao = r.headers.get("access-control-allow-origin", "")
    cred = r.headers.get("access-control-allow-credentials", "").lower() == "true"
    bad = acao == evil or (acao == "*" and cred)
    sev = "High" if cred else "Medium"
    add(out, not bad, "cors_misconfig", f"Origin: {evil} -> Access-Control-Allow-Origin: {acao or '-'}"
        + (", Allow-Credentials: true" if cred else ""), severity=sev)


def _wordpress(ctx, out):
    if not any(t["id"] == "wordpress" for t in ctx.state.get("tech", [])):
        return
    r = ctx.probe(ctx.base + "/xmlrpc.php", maxbytes=1000)
    enabled = bool(r and (r[0] == 405 or (r[0] == 200 and b"XML-RPC server accepts POST" in r[2])))
    add(out, not enabled, "wp_xmlrpc", f"{ctx.base}/xmlrpc.php -> {r[0] if r else '-'}")
    r = ctx.probe(ctx.base + "/wp-json/wp/v2/users?per_page=5", maxbytes=6000)
    slugs = re.findall(r'"slug"\s*:\s*"([^"]+)"', r[2].decode("utf-8", "ignore")) if r and r[0] == 200 else []
    add(out, not slugs, "wp_user_enum", ("users: " + ", ".join(slugs)) if slugs else "REST users endpoint not public")
    plugins = {}
    for page in ctx.pages.values():
        for m in re.finditer(r"/wp-content/plugins/([a-z0-9_\-]+)/[^\"' ]*?(?:\?ver=(\d+(?:\.\d+)*))?[\"' ]", page.text):
            if m.group(1) not in plugins or m.group(2):
                plugins[m.group(1)] = m.group(2) or plugins.get(m.group(1)) or ""
    if plugins:
        add(out, None, "wp_plugins", ", ".join(f"{n} {v}".strip() for n, v in sorted(plugins.items())))


def _reflection(ctx, out):
    for param in ("q", "s", "search", "query"):
        ctx.stop()
        try:
            with ctx.client() as c:
                r = c.get(f"{ctx.base}/?{param}={MARK}")
        except httpx.HTTPError:
            continue
        if MARK in r.text:
            add(out, False, "param_reflected", f"?{param}={MARK} appears in the response", confidence="low", param=param)
            return
    add(out, True, "param_reflected", "q, s, search, query", param="q, s, search, query")


def _errors(ctx, out):
    texts = [("start page", ctx.home.text if ctx.home else "")]
    if ctx.state.get("err404"):
        texts.append(("404 page", ctx.state["err404"].text))
    for where, text in texts:
        m = ERR_RX.search(text)
        if m:
            add(out, False, "error_disclosure", f"{where}: {text[max(0, m.start() - 40):m.end() + 80]!r}")
            return
    add(out, True, "error_disclosure", "No error output found on checked pages")


def run(target, ctx):
    out = []
    if ctx.home is None:
        return out
    lvl = ctx.cfg["paths"]
    out += analyze_pages(ctx.pages, urlparse(ctx.base).hostname)
    _errors(ctx, out)
    if lvl >= 1:
        for fn in (_cors, _methods, _robots, _wordpress):
            try:
                fn(ctx, out)
            except (httpx.HTTPError, OSError) as e:
                ctx(f"Exposure: {fn.__name__} failed: {e}")
        _paths(ctx, out, lvl)
        _dirs(ctx, out, lvl)
    if ctx.cfg["probes"]:
        _reflection(ctx, out)
    return out
