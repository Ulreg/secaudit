"""Scoring, prioritisation, attack stories, diff and report export (HTML / Markdown / JSON)."""
import html
import json
from collections import Counter

import knowledge

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info", "Pass"]
SEV_WEIGHT = {"Critical": 25, "High": 12, "Medium": 5, "Low": 2}
IDENT_PARAMS = ("name", "host", "path", "cve_id", "product", "lib", "header", "param")

L = {
    "da": dict(
        report="Sikkerhedsrapport", customer="Kunde", target="Målsystem", date="Scanningsdato", grade="Karakter",
        score="Score", summary="Sammenfatning", scope="Aftale og afgrænsning", auth_by="Tilladelse givet af",
        auth_date="Dato for tilladelse", auth_ref="Reference", scope_note="Afgrænsning", profile="Scanningsprofil",
        method="Metode", tool="Værktøj", scanner_ip="Scannerens IP-adresse (til genkendelse i logs)",
        top="Ret disse først", plan="Handlingsplan", b1="Ret først", b2="Planlæg", b3="Når der er tid",
        stories="Sådan kunne en angriber udnytte det", tech="Fundet teknologi", cves="Kendte sårbarheder (CVE)",
        details="Detaljerede fund", passed="Beståede tests", notes="Bemærkninger", evidence="Dokumentation",
        what="Hvad er problemet", exploit="Sådan kan det udnyttes", fix="Sådan retter du det", refs="Henvisninger",
        confidence="Sikkerhed", conf={"high": "Høj", "medium": "Middel", "low": "Lav"}, possible="Mulig",
        likely="Sandsynlig", category="Kategori", cat_score="Score pr. kategori", tests="Tests", passed_n="bestået",
        failed_n="fejlet", nofind="Ingen svagheder fundet i denne kategori.", product="Produkt", version="Version",
        kind="Type", source="Kilde", cve="CVE", cvss="CVSS", kev="Aktivt udnyttet", yes="Ja", no="Nej",
        compare="Før og efter", fixed="Løst siden forrige scanning", new="Nye fund", persistent="Stadig åbne",
        prev="Forrige scanning", none="Ingen", sev={"Critical": "Kritisk", "High": "Høj", "Medium": "Middel",
        "Low": "Lav", "Info": "Info", "Pass": "Bestået"}, cat={"HTTPS": "HTTPS", "Headers": "Sikkerheds-headers",
        "Cookies": "Cookies", "TLS": "TLS og certifikat", "DNSSEC": "DNSSEC", "DANE": "DANE", "IPv6": "IPv6",
        "DNS": "DNS", "Mail": "Mail", "Technology": "Teknologi", "Vulnerabilities": "Sårbarheder",
        "Exposure": "Eksponering", "WebApp": "Webapplikation", "Other": "Andet"},
        limits_h="Forbehold og begrænsninger",
        limits=["Rapporten er en passiv konfigurationsaudit, ikke en penetrationstest. Der er ikke forsøgt udnyttelse, indtrængen eller loginforsøg.",
                "Fund kan være falske positiver og bør verificeres, især dem med lav sikkerhed (confidence).",
                "Versioner er aflæst udefra (headers, filer, kildekode). Distributionspakker kan have bagudporterede sikkerhedsrettelser, så CVE-fund markeret som mulige skal kontrolleres på serveren.",
                "Kun de sider, der blev fundet ved crawl inden for profilens grænse, er analyseret. Områder bag login er ikke testet.",
                "En ren rapport er ikke bevis for, at systemet er sikkert. Rapporten viser kun tilstanden på scanningstidspunktet."],
        method_text="Scanneren sender almindelige GET/HEAD/OPTIONS/TRACE-forespørgsler, DNS-opslag og TLS-handshakes med begrænset hastighed. Der køres ingen exploit-kode, brute force eller denial-of-service.",
        grades="A = fremragende, B = god, C = acceptabel, D = svag, E = dårlig, F = kritisk",
        prio_note="Prioritering efter alvorlighed og hvor let svagheden er at udnytte.",
    ),
    "en": dict(
        report="Security report", customer="Customer", target="Target", date="Scan date", grade="Grade",
        score="Score", summary="Summary", scope="Agreement and scope", auth_by="Permission given by",
        auth_date="Permission date", auth_ref="Reference", scope_note="Scope", profile="Scan profile",
        method="Method", tool="Tool", scanner_ip="Scanner IP address (to recognise the traffic in logs)",
        top="Fix these first", plan="Action plan", b1="Fix first", b2="Plan", b3="When time permits",
        stories="How an attacker could exploit this", tech="Detected technology", cves="Known vulnerabilities (CVE)",
        details="Detailed findings", passed="Passed tests", notes="Notes", evidence="Evidence",
        what="What is the problem", exploit="How it can be exploited", fix="How to fix it", refs="References",
        confidence="Confidence", conf={"high": "High", "medium": "Medium", "low": "Low"}, possible="Possible",
        likely="Likely", category="Category", cat_score="Score per category", tests="Tests", passed_n="passed",
        failed_n="failed", nofind="No weaknesses found in this category.", product="Product", version="Version",
        kind="Type", source="Source", cve="CVE", cvss="CVSS", kev="Actively exploited", yes="Yes", no="No",
        compare="Before and after", fixed="Fixed since the previous scan", new="New findings", persistent="Still open",
        prev="Previous scan", none="None", sev={"Critical": "Critical", "High": "High", "Medium": "Medium",
        "Low": "Low", "Info": "Info", "Pass": "Passed"}, cat={"HTTPS": "HTTPS", "Headers": "Security headers",
        "Cookies": "Cookies", "TLS": "TLS and certificate", "DNSSEC": "DNSSEC", "DANE": "DANE", "IPv6": "IPv6",
        "DNS": "DNS", "Mail": "Mail", "Technology": "Technology", "Vulnerabilities": "Vulnerabilities",
        "Exposure": "Exposure", "WebApp": "Web application", "Other": "Other"},
        limits_h="Disclaimers and limitations",
        limits=["This is a passive configuration audit, not a penetration test. No exploitation, intrusion or login attempts were made.",
                "Findings may be false positives and should be verified, especially those with low confidence.",
                "Versions are read from outside (headers, files, page source). Distribution packages may carry back-ported security fixes, so CVEs marked as possible must be verified on the server.",
                "Only pages found by the crawl within the profile limit were analysed. Areas behind a login were not tested.",
                "A clean report does not prove that a system is secure. It only shows the state at the time of the scan."],
        method_text="The scanner sends ordinary GET/HEAD/OPTIONS/TRACE requests, DNS lookups and TLS handshakes at a limited rate. No exploit code, brute force or denial-of-service is run.",
        grades="A = excellent, B = good, C = acceptable, D = weak, E = poor, F = critical",
        prio_note="Prioritised by severity and by how easy the weakness is to exploit.",
    ),
}


def is_fail(f):
    return f["severity"] not in ("Pass", "Info")


def view(f, lang):
    """Finding row (dict) + rendered texts + priority."""
    r = knowledge.render(f["key"], lang, f["params"])
    sev = f["severity"]
    prio = (4 - SEV_ORDER.index(sev)) * 10 + r["ease"] if is_fail(f) else 0
    if not is_fail(f):
        bucket = 0
    elif sev in ("Critical", "High") or (sev == "Medium" and r["ease"] >= 4):
        bucket = 1
    elif sev == "Medium":
        bucket = 2
    else:
        bucket = 3
    title = r["fail_title"] if is_fail(f) and r["fail_title"] else r["title"]
    return dict(f, title=title, test_title=r["title"], description=r["description"], exploitation=r["exploitation"],
                remediation=r["remediation"], references=r["references"], priority=prio, bucket=bucket)


def summarize(fs):
    counts = Counter(f["severity"] for f in fs)
    cats = {}
    for f in fs:
        c = cats.setdefault(f["category"], dict(passed=0, failed=0))
        if f["severity"] == "Pass":
            c["passed"] += 1
        elif is_fail(f):
            c["failed"] += 1
    for c in cats.values():
        t = c["passed"] + c["failed"]
        c["pct"] = round(100 * c["passed"] / t) if t else 100
    score = max(0, 100 - sum(SEV_WEIGHT[f["severity"]] for f in fs if is_fail(f)))
    if counts["Critical"]:
        score = min(score, 49)
    elif counts["High"]:
        score = min(score, 74)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "E" if score >= 35 else "F"
    p, n = counts["Pass"], sum(counts[s] for s in ("Critical", "High", "Medium", "Low"))
    return dict(counts={s: counts[s] for s in SEV_ORDER}, categories=cats, score=score, grade=grade,
                passed=p, failed=n, pct=round(100 * p / (p + n)) if p + n else 100)


def chains_for(fs, lang):
    active = {f["key"] for f in fs if f["severity"] != "Pass"}
    out = []
    for c in knowledge.chains(lang):
        if not (c["requires"] or c["any"]):
            continue
        if all(k in active for k in c["requires"]) and (not c["any"] or any(k in active for k in c["any"])):
            out.append(c)
    return out


def ident(f):
    return f["key"] + "|" + "|".join(str(f["params"].get(k, "")) for k in IDENT_PARAMS)


def diff(old, new):
    """Compare two scans' findings (lists of dicts). Returns fixed / new / persistent lists of new-side rows."""
    old_fail = {ident(f): f for f in old if is_fail(f)}
    new_fail = {ident(f): f for f in new if is_fail(f)}
    return dict(fixed=[v for k, v in old_fail.items() if k not in new_fail],
                new=[v for k, v in new_fail.items() if k not in old_fail],
                persistent=[v for k, v in new_fail.items() if k in old_fail])


# ---------------------------------------------------------------- HTML

CSS = """
*{box-sizing:border-box}body{font:14px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1a1a1a;max-width:900px;margin:0 auto;padding:24px}
h1{font-size:30px;margin:0 0 4px}h2{font-size:20px;border-bottom:2px solid #ddd;padding-bottom:4px;margin-top:32px}h3{font-size:15px;margin:14px 0 4px}
.cover{min-height:90vh;display:flex;flex-direction:column;justify-content:center}.grade{font-size:96px;font-weight:700;line-height:1}
.meta td{padding:2px 14px 2px 0;vertical-align:top}table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border:1px solid #d5d5da;padding:5px 8px;text-align:left;vertical-align:top}th{background:#f2f2f5}
.sev{display:inline-block;min-width:64px;text-align:center;border-radius:4px;color:#fff;font-size:12px;padding:1px 6px;margin-right:6px}
.Critical{background:#7f1d1d}.High{background:#dc2626}.Medium{background:#d97706}.Low{background:#2563eb}.Info{background:#6b7280}.Pass{background:#16a34a}
.card{border:1px solid #d5d5da;border-radius:6px;padding:10px 14px;margin:10px 0;break-inside:avoid}pre{background:#f4f4f6;padding:8px;border-radius:4px;white-space:pre-wrap;word-break:break-word;font-size:12px;margin:4px 0}
.story{border-left:4px solid #dc2626;background:#fef2f2;padding:8px 14px;margin:10px 0;break-inside:avoid}.small{color:#555;font-size:12px}
.g-A,.g-B{color:#16a34a}.g-C{color:#ca8a04}.g-D,.g-E,.g-F{color:#dc2626}.ok{color:#16a34a}.bad{color:#dc2626}
@media print{body{padding:0;max-width:none}.cover{page-break-after:always}h2{page-break-after:avoid}}
"""


def _e(x):
    return html.escape(str(x), quote=True)


def _fmt_date(dt):
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "-"


def to_html(scan, findings, lang="da", compare=None):
    """scan: dict from scan_dict(); findings: list of rows; compare: (scan_dict, findings) of an older scan."""
    t = L[lang]
    fs = [view(f, lang) for f in findings]
    s = summarize(fs)
    fails = sorted([f for f in fs if is_fail(f)], key=lambda f: (f["bucket"], -f["priority"]))
    o = [f"<!DOCTYPE html><html lang='{lang}'><head><meta charset='utf-8'><title>{_e(t['report'])} - {_e(scan['target'])}</title><style>{CSS}</style></head><body>"]
    o.append(f"<div class='cover'><div class='small'>{_e(t['report'])}</div><h1>{_e(scan['customer'] or scan['target'])}</h1>"
             f"<p>{_e(scan['target'])}</p><div class='grade g-{s['grade']}'>{s['grade']}</div>"
             f"<p>{_e(t['score'])}: {s['score']}/100 &middot; {s['passed']} {_e(t['passed_n'])}, {s['failed']} {_e(t['failed_n'])}</p>"
             f"<table class='meta' style='width:auto;border:0'>"
             f"<tr><td>{_e(t['date'])}</td><td>{_e(_fmt_date(scan['created_at']))}</td></tr>"
             f"<tr><td>{_e(t['profile'])}</td><td>{_e(scan['profile'])}</td></tr>"
             f"<tr><td>{_e(t['tool'])}</td><td>SecAuditTool {_e(scan['tool_version'])}</td></tr></table>"
             f"<p class='small'>{_e(t['grades'])}</p></div>")

    o.append(f"<h2>{_e(t['summary'])}</h2>")
    sev_row = "".join(f"<td><span class='sev {k}'>{_e(t['sev'][k])}</span> {s['counts'][k]}</td>" for k in SEV_ORDER)
    o.append(f"<table><tr>{sev_row}</tr></table>")
    o.append(f"<h3>{_e(t['cat_score'])}</h3><table><tr><th>{_e(t['category'])}</th><th>{_e(t['score'])}</th><th>{_e(t['tests'])}</th></tr>")
    for k, c in sorted(s["categories"].items()):
        o.append(f"<tr><td>{_e(t['cat'].get(k, k))}</td><td>{c['pct']}%</td><td>{c['passed']} {_e(t['passed_n'])} / {c['failed']} {_e(t['failed_n'])}</td></tr>")
    o.append("</table>")
    top = [f for f in fails if f["bucket"] == 1][:5]
    if top:
        o.append(f"<h3>{_e(t['top'])}</h3><ol>" + "".join(f"<li><span class='sev {f['severity']}'>{_e(t['sev'][f['severity']])}</span>{_e(f['title'])}</li>" for f in top) + "</ol>")

    o.append(f"<h2>{_e(t['scope'])}</h2><table class='meta'>")
    for lab, val in ((t["customer"], scan["customer"]), (t["target"], scan["target"]), (t["auth_by"], scan["auth_by"]),
                     (t["auth_date"], scan["auth_date"]), (t["auth_ref"], scan["auth_ref"]), (t["scope_note"], scan["scope_note"]),
                     (t["scanner_ip"], scan["scanner_ip"])):
        o.append(f"<tr><th style='width:34%'>{_e(lab)}</th><td>{_e(val or '-')}</td></tr>")
    o.append(f"</table><h3>{_e(t['method'])}</h3><p>{_e(t['method_text'])}</p>")

    if compare:
        old_scan, old_f = compare
        d = diff(old_f, findings)
        old_s = summarize([view(f, lang) for f in old_f])
        o.append(f"<h2>{_e(t['compare'])}</h2><p>{_e(t['prev'])}: #{old_scan['id']} ({_e(_fmt_date(old_scan['created_at']))}) - "
                 f"{_e(t['grade'])} {old_s['grade']} &rarr; <b>{s['grade']}</b> ({old_s['score']} &rarr; {s['score']})</p>")
        for lab, key, cls in ((t["fixed"], "fixed", "ok"), (t["new"], "new", "bad"), (t["persistent"], "persistent", "")):
            rows = [view(f, lang) for f in d[key]]
            o.append(f"<h3 class='{cls}'>{_e(lab)} ({len(rows)})</h3>")
            o.append("<ul>" + "".join(f"<li>{_e(r['title'])}</li>" for r in rows) + "</ul>" if rows else f"<p>{_e(t['none'])}</p>")

    stories = chains_for(fs, lang)
    if stories:
        o.append(f"<h2>{_e(t['stories'])}</h2>")
        o += [f"<div class='story'><b>{_e(c['title'])}</b><br>{_e(c['story'])}</div>" for c in stories]

    techs = [f for f in fs if f["key"] == "tech_detected"]
    if techs:
        o.append(f"<h2>{_e(t['tech'])}</h2><table><tr><th>{_e(t['product'])}</th><th>{_e(t['version'])}</th><th>{_e(t['kind'])}</th><th>{_e(t['source'])}</th><th>{_e(t['confidence'])}</th></tr>")
        for f in techs:
            p = f["params"]
            o.append(f"<tr><td>{_e(p.get('product'))}</td><td>{_e(p.get('version'))}</td><td>{_e(p.get('kind'))}</td><td>{_e(f['evidence'])}</td><td>{_e(t['conf'].get(f['confidence'], ''))}</td></tr>")
        o.append("</table>")
    cv = [f for f in fs if f["key"] == "cve"]
    if cv:
        o.append(f"<h2>{_e(t['cves'])}</h2><table><tr><th>{_e(t['cve'])}</th><th>{_e(t['product'])}</th><th>{_e(t['cvss'])}</th><th>{_e(t['kev'])}</th><th>{_e(t['confidence'])}</th></tr>")
        for f in cv:
            p = f["params"]
            tag = t["likely"] if f["confidence"] == "high" else t["possible"]
            o.append(f"<tr><td><a href='{_e(p.get('link', '#'))}'>{_e(p.get('cve_id'))}</a></td><td>{_e(p.get('product'))} {_e(p.get('version'))}</td>"
                     f"<td>{_e(p.get('cvss'))}</td><td>{_e(t['yes'] if p.get('kev') else t['no'])}</td><td>{_e(tag)}</td></tr>")
        o.append("</table>")

    o.append(f"<h2>{_e(t['plan'])}</h2><p class='small'>{_e(t['prio_note'])}</p>")
    for b, lab in ((1, t["b1"]), (2, t["b2"]), (3, t["b3"])):
        rows = [f for f in fails if f["bucket"] == b]
        if rows:
            o.append(f"<h3>{_e(lab)} ({len(rows)})</h3><ul>" + "".join(f"<li><span class='sev {f['severity']}'>{_e(t['sev'][f['severity']])}</span>{_e(f['title'])}</li>" for f in rows) + "</ul>")
    if not fails:
        o.append(f"<p>{_e(t['nofind'])}</p>")

    o.append(f"<h2>{_e(t['details'])}</h2>")
    for f in fails:
        o.append(f"<div class='card'><span class='sev {f['severity']}'>{_e(t['sev'][f['severity']])}</span><b>{_e(f['title'])}</b>"
                 f"<div class='small'>{_e(t['cat'].get(f['category'], f['category']))} &middot; {_e(t['confidence'])}: {_e(t['conf'].get(f['confidence'], ''))}</div>"
                 f"<h3>{_e(t['evidence'])}</h3><pre>{_e(f['evidence'])}</pre>"
                 f"<h3>{_e(t['what'])}</h3><p>{_e(f['description'])}</p>"
                 f"<h3>{_e(t['exploit'])}</h3><p>{_e(f['exploitation'])}</p>"
                 f"<h3>{_e(t['fix'])}</h3><pre>{_e(f['remediation'])}</pre>"
                 f"<div class='small'>{_e(t['refs'])}: {_e(f['references'])}</div></div>")

    notes = [f for f in fs if f["severity"] == "Info" and f["key"] not in ("tech_detected", "cve_none")]
    if notes:
        o.append(f"<h2>{_e(t['notes'])}</h2>")
        for f in notes:
            o.append(f"<div class='card'><b>{_e(f['title'])}</b><p>{_e(f['description'])}</p><pre>{_e(f['evidence'])}</pre></div>")

    o.append(f"<h2>{_e(t['passed'])}</h2>")
    by = {}
    for f in fs:
        if f["severity"] == "Pass":
            by.setdefault(f["category"], []).append(f["title"])
    for k, titles in sorted(by.items()):
        o.append(f"<h3>{_e(t['cat'].get(k, k))}</h3><ul>" + "".join(f"<li class='ok'>{_e(x)}</li>" for x in titles) + "</ul>")

    o.append(f"<h2>{_e(t['limits_h'])}</h2><ul>" + "".join(f"<li>{_e(x)}</li>" for x in t["limits"]) + "</ul></body></html>")
    return "".join(o)


def to_markdown(scan, findings, lang="da", compare=None):
    t = L[lang]
    fs = [view(f, lang) for f in findings]
    s = summarize(fs)
    fails = sorted([f for f in fs if is_fail(f)], key=lambda f: (f["bucket"], -f["priority"]))
    m = [f"# {t['report']}: {scan['customer'] or scan['target']}", "",
         f"- **{t['target']}:** {scan['target']}", f"- **{t['date']}:** {_fmt_date(scan['created_at'])}",
         f"- **{t['grade']}:** {s['grade']} ({t['score']} {s['score']}/100)", f"- **{t['profile']}:** {scan['profile']}",
         f"- **{t['auth_by']}:** {scan['auth_by'] or '-'} ({scan['auth_date'] or '-'}, {scan['auth_ref'] or '-'})",
         f"- **{t['tool']}:** SecAuditTool {scan['tool_version']}, IP {scan['scanner_ip'] or '-'}", "",
         f"## {t['summary']}", "", " | ".join(f"{t['sev'][k]}: {s['counts'][k]}" for k in SEV_ORDER), ""]
    if compare:
        d = diff(compare[1], findings)
        m += [f"## {t['compare']}", "", f"- {t['fixed']}: {len(d['fixed'])}", f"- {t['new']}: {len(d['new'])}",
              f"- {t['persistent']}: {len(d['persistent'])}", ""]
    stories = chains_for(fs, lang)
    if stories:
        m += [f"## {t['stories']}", ""]
        for c in stories:
            m += [f"**{c['title']}**", "", c["story"], ""]
    m += [f"## {t['details']}", ""]
    for f in fails:
        m += [f"### [{t['sev'][f['severity']]}] {f['title']}", "", f"*{t['confidence']}: {t['conf'].get(f['confidence'], '')}*", "",
              f"**{t['evidence']}:** `{f['evidence'][:300]}`", "", f"**{t['what']}:** {f['description']}", "",
              f"**{t['exploit']}:** {f['exploitation']}", "", f"**{t['fix']}:**", "", "```", f['remediation'], "```", "",
              f"{t['refs']}: {f['references']}", ""]
    m += [f"## {t['limits_h']}", ""] + [f"- {x}" for x in t["limits"]]
    return "\n".join(m)


def to_json(scan, findings, lang="da"):
    fs = [view(f, lang) for f in findings]
    return json.dumps(dict(scan=scan, summary=summarize(fs), findings=fs,
                           chains=[c for c in chains_for(fs, lang)]), default=str, ensure_ascii=False, indent=2)
