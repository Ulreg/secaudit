from app import report


def F(key, sev, **params):
    return dict(id=1, key=key, category="X", severity=sev, confidence="high", evidence="ev", params=params)


def test_grade_and_caps():
    assert report.summarize([F("hsts_present", "Pass")])["grade"] == "A"
    assert report.summarize([F("exposed_env", "Critical")])["score"] <= 49
    assert report.summarize([F("csp_present", "High")])["score"] <= 74
    many = [F("nosniff", "Low") for _ in range(30)]
    assert report.summarize(many)["grade"] in ("E", "F")


def test_priority_buckets():
    a = report.view(F("exposed_env", "Critical"), "da")
    b = report.view(F("referrer_policy", "Low"), "da")
    c = report.view(F("hsts_present", "Pass"), "da")
    assert a["bucket"] == 1 and b["bucket"] == 3 and c["bucket"] == 0
    assert a["priority"] > b["priority"]
    assert a["title"].startswith(".env")


def test_chains():
    fs = [F("cookie_flags", "Medium", name="sid"), F("hsts_present", "Medium")]
    assert "session_hijack" in [c["id"] for c in report.chains_for(fs, "da")]
    assert not report.chains_for([F("hsts_present", "Pass")], "da")


def test_diff():
    old = [F("cookie_flags", "Medium", name="a"), F("cookie_flags", "Medium", name="b"), F("hsts_present", "Medium")]
    new = [F("cookie_flags", "Pass", name="a"), F("cookie_flags", "Medium", name="b"), F("csp_present", "Medium")]
    d = report.diff(old, new)
    assert [f["params"].get("name") for f in d["fixed"]] == ["a"] or len(d["fixed"]) == 2
    assert {f["key"] for f in d["fixed"]} == {"cookie_flags", "hsts_present"}
    assert {f["key"] for f in d["new"]} == {"csp_present"}
    assert [f["params"]["name"] for f in d["persistent"]] == ["b"]


def test_html_report_contains_sections_and_escapes():
    import datetime
    scan = dict(id=2, target="https://x.test", customer="Kunde <A/S>", auth_by="Jens", auth_date="2026-11-01", auth_ref="K-1",
                scope_note="kun forsiden", profile="standard", status="completed", log="", tool_version="1.0",
                scanner_ip="10.0.0.5", created_at=datetime.datetime(2026, 11, 7, 12, 0), finished_at=None)
    fs = [F("exposed_env", "Critical"), F("hsts_present", "Pass"), F("cve", "High", cve_id="CVE-1", product="nginx", version="1.0",
          cvss=7.5, summary="s", kev_note="", kev=True, link="https://nvd.nist.gov/vuln/detail/CVE-1")]
    h = report.to_html(scan, fs, "da")
    assert "Sikkerhedsrapport" in h and "Kunde &lt;A/S&gt;" in h and "Kunde <A/S>" not in h
    assert "Sådan kunne en angriber" in h and "Forbehold og begrænsninger" in h and "CVE-1" in h
    assert "Mulig" not in h or "Sandsynlig" in h
    assert "Security report" in report.to_html(scan, fs, "en")
    assert "# Sikkerhedsrapport" in report.to_markdown(scan, fs, "da")


def test_diff_endpoint_shape(tmp_path, monkeypatch):
    """Regression: the endpoint once used the key 'new' twice."""
    import importlib
    import json
    from fastapi.testclient import TestClient
    from app import db as dbm
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    eng = create_engine(f"sqlite:///{tmp_path}/t.db", connect_args={"check_same_thread": False})
    monkeypatch.setattr(dbm, "engine", eng)
    monkeypatch.setattr(dbm, "SessionLocal", sessionmaker(bind=eng))
    from app import api, models
    models.Base.metadata.create_all(bind=eng)
    s = dbm.SessionLocal()
    for i, sev in ((1, "Medium"), (2, "Pass")):
        sc = models.Scan(target="https://x.test", profile="quick", status="completed", log="")
        s.add(sc); s.commit()
        s.add(models.Finding(scan_id=sc.id, key="hsts_present", category="HTTPS", severity=sev, confidence="high",
                             evidence="", params=json.dumps({})))
        s.commit()
    api.app.dependency_overrides[dbm.get_db] = lambda: (yield s)
    c = TestClient(api.app)
    d = c.get("/api/diff/1/2").json()
    assert d["before"]["grade"] != "" and d["after"]["grade"] == "A"
    assert len(d["fixed"]) == 1 and d["new"] == [] and d["persistent"] == []
    assert c.get("/api/scans/2/report.html?lang=da&compare=1").status_code == 200
    assert c.get("/api/scans/2/report.json").status_code == 200
