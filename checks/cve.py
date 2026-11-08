"""CVE lookup: NVD API 2.0 for server software/CMS (cached, filtered locally by version range) and
OSV.dev (with built-in fallback table) for JavaScript libraries. Includes CISA KEV flag."""
import re
import time

import httpx

from .common import UA, add

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV = "https://api.osv.dev/v1/query"
TTL = 24 * 3600


def vt(version: str):
    """Version string -> comparable tuple. '1.0.2k' -> (1, 0, 2, 11)."""
    m = re.match(r"(\d+(?:\.\d+)*)([a-z]?)", str(version).strip().lstrip("vV"))
    if not m:
        return ()
    nums = tuple(int(x) for x in m.group(1).split("."))
    return nums + ((ord(m.group(2)) - 96,) if m.group(2) else ())


def cmp(a, b):
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def in_range(version: str, r: dict) -> bool:
    """r: {v, vsi, vse, vei, vee} from an NVD cpeMatch entry."""
    v = vt(version)
    if not v:
        return False
    cv = r["v"]
    if cv == "-":
        return False
    if cv != "*":
        return cmp(v, vt(cv)) == 0
    if r.get("vsi") and cmp(v, vt(r["vsi"])) < 0:
        return False
    if r.get("vse") and cmp(v, vt(r["vse"])) <= 0:
        return False
    if r.get("vei") and cmp(v, vt(r["vei"])) > 0:
        return False
    if r.get("vee") and cmp(v, vt(r["vee"])) >= 0:
        return False
    return True


def split_cpe(s: str):
    return re.split(r"(?<!\\):", s)


def trim_cve(item: dict, vendor: str, product: str):
    """Reduce an NVD vulnerability entry to what we need; None if it has no ranges for this product."""
    c = item["cve"]
    ranges = []
    for conf in c.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = split_cpe(m["criteria"])
                if len(parts) > 5 and parts[3] == vendor and parts[4] == product:
                    ranges.append(dict(v=parts[5], vsi=m.get("versionStartIncluding"), vse=m.get("versionStartExcluding"),
                                       vei=m.get("versionEndIncluding"), vee=m.get("versionEndExcluding")))
    if not ranges:
        return None
    score = None
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if c.get("metrics", {}).get(k):
            score = c["metrics"][k][0]["cvssData"]["baseScore"]
            break
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    return dict(id=c["id"], score=score, kev="cisaExploitAdd" in c, summary=desc[:400], ranges=ranges)


def nvd_product(ctx, vendor, product):
    key = f"nvd:{vendor}:{product}"
    if ctx.cache:
        cached = ctx.cache.get(key, TTL)
        if cached is not None:
            return cached
    headers = {"User-Agent": UA}
    if ctx.nvd_key:
        headers["apiKey"] = ctx.nvd_key
    delay = 0.7 if ctx.nvd_key else 6.5
    out, start = [], 0
    while True:
        ctx.stop()
        for attempt in range(3):
            r = httpx.get(NVD, headers=headers, timeout=60, params={
                "virtualMatchString": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
                "resultsPerPage": 2000, "startIndex": start})
            if r.status_code in (403, 429, 503):
                time.sleep(delay * (attempt + 2))
                continue
            break
        r.raise_for_status()
        d = r.json()
        out += [t for it in d.get("vulnerabilities", []) if (t := trim_cve(it, vendor, product))]
        start += d.get("resultsPerPage", 0) or 2000
        if start >= d.get("totalResults", 0):
            break
        time.sleep(delay)
    if ctx.cache:
        ctx.cache.set(key, out)
    return out


def severity_for(score, kev):
    if kev:
        return "Critical" if (score or 0) >= 9 else "High"
    if score is None:
        return "Medium"
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"


# Offline fallback for common JS libraries: (lib, predicate on version tuple, ids, summary)
FALLBACK = [
    ("jquery", lambda v: cmp(v, (3, 5, 0)) < 0, "CVE-2020-11022, CVE-2020-11023", "Cross-site scripting in jQuery before 3.5.0."),
    ("bootstrap", lambda v: (v[:1] == (3,) and cmp(v, (3, 4, 1)) < 0) or (v[:1] == (4,) and cmp(v, (4, 3, 1)) < 0),
     "CVE-2019-8331", "Cross-site scripting in Bootstrap tooltip/popover."),
    ("angular", lambda v: v[:1] == (1,), "AngularJS end-of-life", "AngularJS 1.x no longer receives security fixes."),
    ("moment", lambda v: cmp(v, (2, 29, 4)) < 0, "CVE-2022-24785, CVE-2022-31129", "Path traversal / ReDoS in Moment.js."),
    ("lodash", lambda v: cmp(v, (4, 17, 21)) < 0, "CVE-2021-23337, CVE-2020-8203", "Command injection and prototype pollution in lodash."),
    ("handlebars", lambda v: cmp(v, (4, 7, 7)) < 0, "CVE-2021-23369, CVE-2021-23383", "Remote code execution in Handlebars templates."),
    ("underscore", lambda v: cmp(v, (1, 12, 1)) < 0, "CVE-2021-23358", "Arbitrary code execution in underscore templates."),
]


def js_vulns(ctx, lib, version):
    """Returns (ids, summary, severity) or None when not vulnerable."""
    key = f"osv:{lib}:{version}"
    vulns = ctx.cache.get(key, TTL) if ctx.cache else None
    if vulns is None:
        try:
            ctx.stop()
            r = httpx.post(OSV, json={"package": {"name": lib, "ecosystem": "npm"}, "version": version},
                           headers={"User-Agent": UA}, timeout=20)
            r.raise_for_status()
            vulns = [dict(id=v["id"], aliases=v.get("aliases", []), summary=v.get("summary", ""),
                          sev=(v.get("database_specific") or {}).get("severity", "")) for v in r.json().get("vulns", [])]
            if ctx.cache:
                ctx.cache.set(key, vulns)
        except Exception as e:
            ctx(f"CVE: OSV lookup failed for {lib} ({e}); using built-in table")
            v = vt(version)
            for name, pred, ids, summ in FALLBACK:
                if name == lib and v and pred(v):
                    return ids, summ, "Medium"
            return None
    if not vulns:
        return None
    ids = []
    for v in vulns:
        ids.append(next((a for a in v["aliases"] if a.startswith("CVE-")), v["id"]))
    order = {"LOW": "Low", "MODERATE": "Medium", "HIGH": "High", "CRITICAL": "Critical"}
    sev = max((order.get(v["sev"].upper(), "Medium") for v in vulns),
              key=["Low", "Medium", "High", "Critical"].index)
    return ", ".join(ids[:5]) + (f" (+{len(ids) - 5} more)" if len(ids) > 5 else ""), vulns[0]["summary"][:200], sev


def run(target, ctx):
    out = []
    techs = [t for t in ctx.state.get("tech", []) if t["cpe"] and t["version"]][: ctx.cfg["max_products"]]
    for t in techs:
        ctx.stop()
        ctx(f"CVE: looking up {t['display']} {t['version']}")
        try:
            hits = {}
            for vendor, product in t["cpe"]:
                for h in nvd_product(ctx, vendor, product):
                    if any(in_range(t["version"], r) for r in h["ranges"]):
                        hits[h["id"]] = h
        except Exception as e:
            ctx(f"CVE: lookup failed for {t['display']}: {e}")
            add(out, None, "cve_lookup_failed", str(e)[:200], product=t["display"], reason=str(e)[:150])
            continue
        hits = sorted(hits.values(), key=lambda h: (h["kev"], h["score"] or 0), reverse=True)
        if not hits:
            add(out, True, "cve_none", "NVD", product=t["display"], version=t["version"])
            continue
        # banner-based versions are never "confirmed"; distro packages often back-port fixes
        conf = "low" if t["backport"] or t["confidence"] == "low" else "medium"
        for h in hits[:8]:
            add(out, False, "cve", h["summary"][:200], severity=severity_for(h["score"], h["kev"]), confidence=conf,
                cve_id=h["id"], product=t["display"], version=t["version"],
                cvss=h["score"] if h["score"] is not None else "n/a", summary=h["summary"],
                kev_note="This CVE is on CISA's list of vulnerabilities exploited in the wild." if h["kev"] else "",
                kev=h["kev"], link=f"https://nvd.nist.gov/vuln/detail/{h['id']}")
        if len(hits) > 8:
            add(out, None, "cve_more", "NVD", count=len(hits) - 8, product=t["display"], version=t["version"])

    for j in ctx.state.get("js", []):
        ctx.stop()
        res = js_vulns(ctx, j["lib"], j["version"])
        if res:
            ids, summ, sev = res
            add(out, False, "js_vulnerable", j["url"], severity=sev, confidence="medium",
                lib=j["lib"], version=j["version"], ids=ids, summary=summ)
    return out
