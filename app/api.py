import json
import threading
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from checks.common import PROFILES

from . import db, models, report, scanner

models.Base.metadata.create_all(bind=db.engine)
app = FastAPI(title="SecAuditTool API")


class ScanCreate(BaseModel):
    target: str
    authorized: bool
    customer: str = ""
    auth_by: str = ""
    auth_date: str = ""
    auth_ref: str = ""
    scope_note: str = ""
    profile: str = "standard"


def finding_row(f):
    return dict(id=f.id, key=f.key, category=f.category, severity=f.severity, confidence=f.confidence,
                evidence=f.evidence or "", params=json.loads(f.params or "{}"))


def scan_dict(s):
    return dict(id=s.id, target=s.target, customer=s.customer or "", auth_by=s.auth_by or "", auth_date=s.auth_date or "",
                auth_ref=s.auth_ref or "", scope_note=s.scope_note or "", profile=s.profile, status=s.status,
                log=s.log or "", tool_version=s.tool_version or "", scanner_ip=s.scanner_ip or "",
                created_at=s.created_at, finished_at=s.finished_at)


def load(session, scan_id):
    s = session.get(models.Scan, scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    return scan_dict(s), [finding_row(f) for f in s.findings]


@app.post("/api/scans")
def create_scan(data: ScanCreate, session: Session = Depends(db.get_db)):
    if not data.authorized:
        raise HTTPException(403, "You must confirm you are authorized to test this target.")
    if not data.auth_by.strip():
        raise HTTPException(400, "State who gave permission (for your own site: write 'own site').")
    if data.profile not in PROFILES:
        raise HTTPException(400, "Unknown profile")
    try:
        target = scanner.normalize_target(data.target)
        scanner.check_scope(target)
    except ValueError as e:
        raise HTTPException(400, str(e))
    scan = models.Scan(target=target, customer=data.customer.strip(), auth_by=data.auth_by.strip(),
                       auth_date=data.auth_date, auth_ref=data.auth_ref, scope_note=data.scope_note,
                       profile=data.profile, status="pending", log="")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    threading.Thread(target=scanner.run_scan, args=(scan.id,), daemon=True).start()
    return scan_dict(scan)


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int):
    return {"cancelled": scanner.cancel(scan_id)}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, lang: str = "da", session: Session = Depends(db.get_db)):
    scan, rows = load(session, scan_id)
    fs = [report.view(f, lang) for f in rows]
    return dict(scan=scan, summary=report.summarize(fs), findings=fs, chains=report.chains_for(fs, lang))


@app.get("/api/scans")
def list_scans(session: Session = Depends(db.get_db)):
    out = []
    for s in session.query(models.Scan).order_by(models.Scan.id.desc()).all():
        sm = report.summarize([report.view(finding_row(f), "en") for f in s.findings])
        d = scan_dict(s)
        d.pop("log")
        out.append(dict(d, grade=sm["grade"], score=sm["score"], counts=sm["counts"]))
    return out


@app.get("/api/customers")
def customers(session: Session = Depends(db.get_db)):
    rows = session.query(models.Scan.customer).distinct().all()
    return sorted(r[0] for r in rows if r[0])


@app.get("/api/diff/{old_id}/{new_id}")
def diff(old_id: int, new_id: int, lang: str = "da", session: Session = Depends(db.get_db)):
    old_scan, old = load(session, old_id)
    new_scan, new = load(session, new_id)
    d = report.diff(old, new)
    so, sn = report.summarize([report.view(f, lang) for f in old]), report.summarize([report.view(f, lang) for f in new])
    return dict(before=dict(scan=old_scan, grade=so["grade"], score=so["score"]),
                after=dict(scan=new_scan, grade=sn["grade"], score=sn["score"]),
                **{k: [report.view(f, lang) for f in v] for k, v in d.items()})


@app.get("/api/scans/{scan_id}/report.{fmt}")
def export(scan_id: int, fmt: str, lang: str = "da", compare: int | None = Query(None),
           session: Session = Depends(db.get_db)):
    if lang not in report.L:
        raise HTTPException(400, "lang must be da or en")
    scan, rows = load(session, scan_id)
    cmp = load(session, compare) if compare else None
    name = f"report-{scan['customer'] or scan['target']}-{scan_id}".replace("/", "_").replace(":", "_").replace(" ", "_")
    if fmt == "html":
        return HTMLResponse(report.to_html(scan, rows, lang, cmp))
    if fmt == "md":
        return PlainTextResponse(report.to_markdown(scan, rows, lang, cmp), media_type="text/markdown",
                                 headers={"Content-Disposition": f'attachment; filename="{name}.md"'})
    if fmt == "json":
        return PlainTextResponse(report.to_json(scan, rows, lang), media_type="application/json",
                                 headers={"Content-Disposition": f'attachment; filename="{name}.json"'})
    raise HTTPException(404, "Unknown format (html, md, json)")


WEB_DIR = Path(__file__).resolve().parent.parent / "web"
app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
