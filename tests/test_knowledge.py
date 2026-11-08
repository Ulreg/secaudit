import ast
import glob

import knowledge


def used_keys():
    keys = set()
    for path in glob.glob("checks/*.py"):
        for node in ast.walk(ast.parse(open(path, encoding="utf-8").read())):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "add" and len(node.args) >= 3:
                a = node.args[2]
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    keys.add(a.value)
    return keys


def test_every_used_key_has_text_in_both_languages():
    f = knowledge.data()["findings"]
    missing = [k for k in used_keys() if k not in f]
    assert not missing, f"keys without text: {missing}"
    for k in used_keys():
        for lang in ("en", "da"):
            assert f[k][lang]["t"] and f[k][lang]["d"], (k, lang)


def test_failing_findings_explain_exploitation_and_fix():
    for k, e in knowledge.data()["findings"].items():
        if e.get("sev") != "Info":
            for lang in ("en", "da"):
                assert e[lang]["x"] and e[lang]["r"], (k, lang)


def test_chain_keys_exist():
    f = knowledge.data()["findings"]
    for c in knowledge.data()["chains"]:
        for k in c["requires"] + c["any"]:
            assert k in f, (c["id"], k)


def test_render_fills_params():
    r = knowledge.render("cookie_flags", "da", {"name": "sid"})
    assert "sid" in r["title"] and "{name}" not in r["title"]
    assert knowledge.render("nope", "da")["title"] == "nope"


def test_failing_tests_have_a_failure_title():
    f = knowledge.data()["findings"]
    skip = {"cve", "js_vulnerable"}
    for k in used_keys():
        if f[k].get("sev", "Info") != "Info" and k not in skip:
            for lang in ("en", "da"):
                assert f[k][lang].get("tf"), (k, lang)
