from checks import dns_checks, exposure, fingerprint, headers, tls_checks
from checks.common import Ctx, add
from checks.crawl import Page


def test_parse_server():
    assert fingerprint.parse_server("nginx/1.18.0 (Ubuntu)") == [("nginx", "1.18.0", True)]
    assert fingerprint.parse_server("Apache/2.4.58 (Unix) OpenSSL/3.0.2") == [("apache", "2.4.58", True), ("openssl", "3.0.2", True)]
    assert fingerprint.parse_server("cloudflare") == []


def test_js_from_url():
    assert fingerprint.js_from_url("/js/jquery-1.12.4.min.js") == ("jquery", "1.12.4")
    assert fingerprint.js_from_url("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js") == ("jquery", "3.6.0")
    assert fingerprint.js_from_url("https://cdn.jsdelivr.net/npm/bootstrap@4.3.0/dist/js/bootstrap.min.js") == ("bootstrap", "4.3.0")
    assert fingerprint.js_from_url("/app.js") is None


def test_detect_wordpress_generator():
    page = Page("https://x.test/", 200, {"server": "nginx/1.18.0"}, '<meta name="generator" content="WordPress 6.2.1"><link href="/wp-content/a.css">', ["PHPSESSID=1"])
    f = fingerprint.Found()
    fingerprint.detect(page, f)
    fingerprint.detect_html(page, f)
    assert f.items["wordpress"]["version"] == "6.2.1"
    assert f.items["nginx"]["version"] == "1.18.0" and f.items["php"]["version"] is None


def test_hsts_eval():
    assert headers.evaluate_hsts("max-age=31536000; includeSubDomains; preload") == dict(max_age=31536000, subdomains=True, preload=True)
    assert headers.evaluate_hsts("max-age=300")["max_age"] == 300


def test_headers_findings():
    ctx = Ctx(log=lambda m: None)
    home = Page("https://example.test:8443/", 200, {"server": "Apache/2.4.1", "strict-transport-security": "max-age=100"},
                "<html></html>", ["sid=1; Path=/", "ok=1; Secure; HttpOnly; SameSite=Lax"])
    ctx.home, ctx.pages, ctx.base = home, {home.url: home}, "https://example.test:8443"
    res = {(f["key"], f["params"].get("name", "")): f["severity"] for f in headers.run("https://example.test:8443", ctx)}
    assert res[("hsts_present", "")] == "Pass" and res[("hsts_maxage", "")] == "Medium" or res[("hsts_maxage", "")] == "Low"
    assert res[("csp_present", "")] == "Medium"
    assert res[("cookie_flags", "sid")] == "Medium" and res[("cookie_flags", "ok")] == "Pass"
    assert ("version_disclosure", "") in res


def test_analyze_pages():
    html = """<html><body>
    <script src="http://cdn.other.com/a.js"></script><script src="https://cdn.other.com/b.js" integrity="sha384-x"></script>
    <script src="https://www.googletagmanager.com/gtm.js"></script>
    <form method="post" action="/login"><input name="user"><input type="password" name="pw"></form>
    <form method="post" action="/s"><input type="hidden" name="csrf_token" value="1"><input name="a"></form>
    <form method="get" action="/search"><input name="q"></form>
    <a href="/go?redirect=https://evil.example">x</a></body></html>"""
    page = Page("https://site.test/", 200, {}, html)
    res = {f["key"]: f for f in exposure.analyze_pages({page.url: page}, "www.site.test")}
    assert res["mixed_content"]["severity"] == "Medium" and "http://cdn.other.com/a.js" in res["mixed_content"]["evidence"]
    assert res["sri_missing"]["severity"] == "Low"
    assert res["form_csrf"]["severity"] == "Low" and "/login" in res["form_csrf"]["evidence"] and "/s" not in res["form_csrf"]["evidence"].replace("/site", "")
    assert res["form_http"]["severity"] == "Pass"
    assert "tracking_consent" in res and "third_party_scripts" in res and "open_redirect_param" in res


def test_exposure_validators():
    by = {(p, k): v for p, k, v, *_ in exposure.PATHS}
    assert by[("/.env", "exposed_env")]("DB_PASSWORD=secret\nAPP_KEY=x", b"", {})
    assert not by[("/.env", "exposed_env")]("<html><body>Not found</body></html>", b"", {})
    assert by[("/.git/HEAD", "exposed_git")]("ref: refs/heads/main", b"", {})
    assert not by[("/backup.zip", "exposed_backup")]("<html>soft 404</html>", b"<html>", {})
    assert by[("/backup.zip", "exposed_backup")]("", b"PK\x03\x04rest", {})


def test_cipher_classification():
    assert tls_checks.classify("DES-CBC3-SHA") == "insecure"
    assert tls_checks.classify("AES128-SHA") == "no_pfs"
    assert tls_checks.classify("ECDHE-RSA-AES128-SHA") == "phase_out"
    assert tls_checks.classify("ECDHE-RSA-AES256-GCM-SHA384") == "good"


def test_mail_evaluators():
    assert dns_checks.spf_ok(["v=spf1 mx -all"])[0] and not dns_checks.spf_ok(["v=spf1 +all"])[0]
    assert not dns_checks.spf_ok(["something else"])[0]
    assert dns_checks.dmarc_policy(["v=DMARC1; p=reject; rua=mailto:a@b"])[0] == "reject"
    assert dns_checks.dmarc_policy(["v=DMARC1; p=none"])[0] == "none"
    assert dns_checks.dmarc_policy([])[0] == ""


def test_add_semantics():
    out = []
    add(out, True, "hsts_present"); add(out, False, "hsts_present"); add(out, None, "hsts_present")
    add(out, False, "hsts_preload", optional=True); add(out, False, "cert_expiry", severity="High")
    assert [o["severity"] for o in out] == ["Pass", "Medium", "Info", "Info", "High"]
