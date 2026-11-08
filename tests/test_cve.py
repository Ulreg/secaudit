from checks import cve

NVD_ITEM = {"cve": {"id": "CVE-2021-23017", "descriptions": [{"lang": "en", "value": "nginx resolver off-by-one"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.7}}]}, "cisaExploitAdd": "2022-01-01",
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "versionStartIncluding": "0.6.18", "versionEndExcluding": "1.20.1"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:1.9.0:*:*:*:*:*:*:*"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*"}]}]}]}}


def test_vt_and_cmp():
    assert cve.vt("1.18.0") == (1, 18, 0)
    assert cve.vt("1.0.2k") == (1, 0, 2, 11)
    assert cve.cmp(cve.vt("1.18"), cve.vt("1.18.0")) == 0
    assert cve.cmp(cve.vt("2.4.9"), cve.vt("2.4.10")) < 0


def test_trim_and_match():
    t = cve.trim_cve(NVD_ITEM, "f5", "nginx")
    assert t["id"] == "CVE-2021-23017" and t["score"] == 7.7 and t["kev"] is True
    assert len(t["ranges"]) == 2  # non-vulnerable and other-product entries are ignored
    assert any(cve.in_range("1.18.0", r) for r in t["ranges"])
    assert not any(cve.in_range("1.20.1", r) for r in t["ranges"])   # fixed version
    assert not any(cve.in_range("0.5.0", r) for r in t["ranges"])    # before start
    assert any(cve.in_range("1.9.0", r) for r in t["ranges"])        # exact
    assert cve.trim_cve(NVD_ITEM, "apache", "http_server") is None


def test_severity():
    assert cve.severity_for(9.8, False) == "Critical"
    assert cve.severity_for(5.0, False) == "Medium"
    assert cve.severity_for(5.0, True) == "High"   # known exploited is bumped
    assert cve.severity_for(None, False) == "Medium"
