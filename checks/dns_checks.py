"""IPv6, DNSSEC, DANE, CAA, subdomain takeover and mail-domain checks using validating resolvers."""
import errno
import hashlib
import ipaddress
import smtplib
import socket
import time

import dns.exception
import dns.flags
import dns.rdatatype
import dns.resolver
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .common import UA, add, fetch_der, host_of, https_port

RESOLVERS = ["9.9.9.9", "1.1.1.1"]  # validating resolvers: they set the AD flag
WEAK_ALGOS = {1, 3, 5, 6, 7, 12}
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "smtp"]
TAKEOVER = {
    "github.io": ("GitHub Pages", "There isn't a GitHub Pages site here"),
    "herokuapp.com": ("Heroku", "No such app"),
    "amazonaws.com": ("AWS S3", "NoSuchBucket"),
    "wordpress.com": ("WordPress.com", "Do you want to register"),
    "myshopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    "ghost.io": ("Ghost", "The thing you were looking for is no longer here"),
    "surge.sh": ("Surge", "project not found"),
    "readthedocs.io": ("Read the Docs", "unknown to Read the Docs"),
    "bitbucket.io": ("Bitbucket", "Repository not found"),
}


def q(name, rdtype, cd=False):
    """Returns (answer|None, status) where status is ok/nodata/nxdomain/servfail/error."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = RESOLVERS
    r.timeout, r.lifetime = 3, 6
    r.use_edns(0, dns.flags.DO, 1232)
    r.flags = dns.flags.RD | (dns.flags.CD if cd else 0)
    try:
        return r.resolve(name, rdtype), "ok"
    except dns.resolver.NoAnswer:
        return None, "nodata"
    except dns.resolver.NXDOMAIN:
        return None, "nxdomain"
    except dns.resolver.NoNameservers:
        return None, "servfail"
    except Exception:
        return None, "error"


def ad(ans) -> bool:
    return bool(ans is not None and ans.response.flags & dns.flags.AD)


def txt(name):
    ans, _ = q(name, "TXT")
    return [b"".join(r.strings).decode(errors="ignore") for r in ans] if ans else []


def spf_ok(records):
    """(ok, record) - an SPF policy must exist and end in -all / ~all (or redirect)."""
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return False, "No SPF record"
    s = spf[0].lower()
    return (s.split()[-1] in ("-all", "~all") or "redirect=" in s), spf[0]


def dmarc_policy(records):
    """(policy, record) from the _dmarc TXT records; policy '' when missing."""
    rec = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not rec:
        return "", "No DMARC record"
    for part in rec[0].split(";"):
        k, _, v = part.strip().partition("=")
        if k.lower() == "p":
            return v.strip().lower(), rec[0]
    return "", rec[0]


def _safe(ctx, label, fn, *a):
    try:
        return fn(*a)
    except Exception as e:
        if type(e).__name__ == "Cancelled":
            raise
        ctx(f"DNS: {label} failed: {e}")


def _dnssec(host, out, ctx):
    labels, apex = host.split("."), host
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        ns, _ = q(cand, "NS")
        if ns:
            apex = cand
            break
    ds, st = q(apex, "DS")
    if ds is None and st not in ("nodata", "nxdomain"):
        add(out, None, "dnssec_unknown", f"DS lookup for {apex}: {st}")
        return apex
    if ds is None:
        add(out, False, "dnssec_signed", f"No DS record for {apex} at the parent zone")
        return apex
    a, st = q(host, "A")
    if a is None and st == "nodata":
        a, st = q(host, "AAAA")
    if st == "servfail" and q(host, "A", cd=True)[1] == "ok":
        add(out, False, "dnssec_valid", "Validating resolver returns SERVFAIL, but the record resolves with checking disabled (bogus signatures)")
        return apex
    validated = ad(a)
    add(out, validated, "dnssec_valid", f"AD flag {'set' if validated else 'not set'} by {RESOLVERS[0]} for {host}", confidence="medium")
    if a is not None:
        for rrset in a.response.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                sig = rrset[0]
                algo, left = int(sig.algorithm), (sig.expiration - time.time()) / 86400
                add(out, algo not in WEAK_ALGOS, "dnssec_algo", f"Algorithm {algo}")
                add(out, left > 3, "dnssec_expiry", f"RRSIG expires in {left:.1f} days")
                break
    return apex


def _dane(host, port, out, ctx):
    name = f"_{port}._tcp.{host}"
    ans, _ = q(name, "TLSA")
    if ans is None:
        add(out, None, "dane_present", f"No TLSA record at {name}")
        return
    add(out, ad(ans), "dane_validated", f"{len(ans)} TLSA record(s) at {name}")
    der = fetch_der(host, port)
    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    matched = checked = False
    for rr in ans:
        if rr.usage not in (1, 3):
            continue
        checked = True
        material = der if rr.selector == 0 else spki
        digest = {0: material, 1: hashlib.sha256(material).digest(), 2: hashlib.sha512(material).digest()}.get(rr.mtype)
        matched = matched or digest == rr.cert
    if checked:
        add(out, matched, "dane_match", "Compared against the leaf certificate")
    else:
        add(out, None, "dane_unverified", ", ".join(f"{r.usage} {r.selector} {r.mtype}" for r in ans))


def _ipv6(host, apex, port, out, ctx):
    aaaa, _ = q(host, "AAAA")
    add(out, aaaa is not None, "ipv6_web", ", ".join(str(r) for r in aaaa) if aaaa else "No AAAA record")
    ns, _ = q(apex, "NS")
    if ns:
        names = [str(r.target) for r in ns][:8]
        missing = [n for n in names if q(n, "AAAA")[0] is None]
        add(out, not missing, "ipv6_ns", ", ".join(missing) or ", ".join(names))
    if aaaa:
        try:
            socket.create_connection((str(aaaa[0]), port), timeout=5).close()
            add(out, True, "ipv6_reach", f"Connected to [{aaaa[0]}]:{port}")
        except OSError as e:
            if e.errno in (errno.ENETUNREACH, errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
                add(out, None, "ipv6_untested", "This machine has no IPv6 connectivity")
            else:
                add(out, False, "ipv6_reach", f"{aaaa[0]}: {e}", confidence="medium")


def _caa(host, apex, out, ctx):
    ans, _ = q(host, "CAA")
    if ans is None:
        ans, _ = q(apex, "CAA")
    add(out, ans is not None, "caa", "; ".join(r.to_text() for r in ans) if ans else "No CAA record", optional=True)


def _takeover(host, apex, out, ctx):
    hosts = [host, "www." + apex] + [h for h in ctx.state.get("hosts", []) if h.endswith("." + apex)]
    hosts = list(dict.fromkeys(hosts))[:10]
    bad = False
    for h in hosts:
        ctx.stop()
        ans, _ = q(h, "CNAME")
        if ans is None:
            continue
        target = str(ans[0].target).rstrip(".")
        if q(target, "A")[1] == "nxdomain":
            add(out, False, "dangling_cname", f"{h} CNAME {target} (target does not exist)", host=h)
            bad = True
            continue
        for suffix, (service, needle) in TAKEOVER.items():
            if target.endswith(suffix):
                r = ctx.probe(f"http://{h}/", maxbytes=4000)
                if r and needle.encode().lower() in r[2].lower():
                    add(out, False, "takeover", f"{h} CNAME {target}: provider says '{needle}'", host=h, service=service)
                    bad = True
    if not bad and hosts:
        add(out, True, "dangling_cname", f"{len(hosts)} host(s) checked", host=", ".join(hosts[:2]))


def _mail(apex, out, ctx):
    mx, _ = q(apex, "MX")
    if mx is None:
        add(out, None, "mail_none", apex)
        return
    hosts = sorted((r.preference, str(r.exchange).rstrip(".")) for r in mx)
    ok, rec = spf_ok(txt(apex))
    add(out, ok, "spf", rec)
    pol, rec = dmarc_policy(txt(f"_dmarc.{apex}"))
    add(out, pol in ("quarantine", "reject"), "dmarc", rec)
    sts = [t for t in txt(f"_mta-sts.{apex}") if t.lower().startswith("v=stsv1")]
    mode = ""
    if sts:
        try:
            with ctx.client() as c:
                body = c.get(f"https://mta-sts.{apex}/.well-known/mta-sts.txt").text
            mode = next((l.split(":")[1].strip() for l in body.splitlines() if l.lower().startswith("mode:")), "")
        except httpx.HTTPError:
            pass
    add(out, mode == "enforce", "mta_sts", f"record: {sts[0] if sts else 'none'}; mode: {mode or '-'}", optional=True)
    rpt = [t for t in txt(f"_smtp._tls.{apex}") if t.lower().startswith("v=tlsrptv1")]
    add(out, bool(rpt), "tls_rpt", rpt[0] if rpt else "No record", optional=True)
    if ctx.cfg["dkim"]:
        found = [s for s in DKIM_SELECTORS if any("p=" in t for t in txt(f"{s}._domainkey.{apex}"))]
        add(out, bool(found), "dkim", ("selectors: " + ", ".join(found)) if found else "no common selector found",
            optional=True, confidence="low")
    for _, mxh in hosts[:3]:
        ctx.stop()
        t, _ = q(f"_25._tcp.{mxh}", "TLSA")
        add(out, t is not None, "mail_dane", f"TLSA {'present' if t else 'absent'} at _25._tcp.{mxh}", optional=True, host=mxh)
        try:
            with smtplib.SMTP(mxh, 25, timeout=8) as s:
                s.ehlo()
                has = s.has_extn("starttls")
            add(out, has, "mail_starttls", "EHLO response checked", host=mxh)
        except OSError as e:
            add(out, None, "mail_starttls_untested", f"{e} (outbound port 25 is often blocked)", host=mxh)


def run(target, ctx):
    out = []
    host = host_of(target)
    try:
        ipaddress.ip_address(host)
        ctx("DNS: target is an IP address - DNS checks skipped")
        return out
    except ValueError:
        pass
    if q("example.com", "A")[1] != "ok":
        ctx(f"DNS: cannot reach validating resolvers {RESOLVERS} - DNS checks skipped")
        add(out, None, "dns_skipped", ", ".join(RESOLVERS))
        return out
    port = https_port(target) or 443
    ctx("DNS: IPv6, DNSSEC, DANE, CAA, takeover, mail")
    apex = _safe(ctx, "DNSSEC", _dnssec, host, out, ctx) or host
    _safe(ctx, "DANE", _dane, host, port, out, ctx)
    _safe(ctx, "IPv6", _ipv6, host, apex, port, out, ctx)
    _safe(ctx, "CAA", _caa, host, apex, out, ctx)
    if ctx.cfg["takeover"]:
        _safe(ctx, "takeover", _takeover, host, apex, out, ctx)
    _safe(ctx, "Mail", _mail, apex, out, ctx)
    return out
