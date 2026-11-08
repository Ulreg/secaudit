"""Loads knowledge/findings.yaml and renders finding texts in a chosen language."""
from pathlib import Path

import yaml

_DATA = None


class _Params(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def data() -> dict:
    global _DATA
    if _DATA is None:
        with open(Path(__file__).with_name("findings.yaml"), encoding="utf-8") as fh:
            _DATA = yaml.safe_load(fh)
        with open(Path(__file__).with_name("fail_titles.yaml"), encoding="utf-8") as fh:
            for key, titles in yaml.safe_load(fh).items():
                for lang, text in titles.items():
                    _DATA["findings"][key][lang]["tf"] = text
    return _DATA


def entry(key: str):
    return data()["findings"].get(key)


def render(key: str, lang: str = "da", params: dict | None = None) -> dict:
    """Return title/description/exploitation/remediation/references for a key, filled with params."""
    e = entry(key)
    if not e:
        return dict(title=key, description="", exploitation="", remediation="", references="",
                    category="Other", sev="Info", ease=3)
    t = e.get(lang) or e["en"]
    p = _Params(params or {})

    def fill(s):
        return str(s).format_map(p) if s else ""

    rem = fill(t.get("r", ""))
    if e.get("cfg"):
        rem = (rem + "\n" + e["cfg"]).strip()
    return dict(title=fill(t["t"]), fail_title=fill(t.get("tf", "")), description=fill(t.get("d", "")), exploitation=fill(t.get("x", "")),
                remediation=rem, references=fill(e.get("ref", "")), category=e["cat"],
                sev=e.get("sev", "Info"), ease=e.get("ease", 3))


def chains(lang: str = "da") -> list[dict]:
    out = []
    for c in data().get("chains", []):
        t = c.get(lang) or c["en"]
        out.append(dict(id=c["id"], requires=c.get("requires", []), any=c.get("any", []), title=t["t"], story=t["s"]))
    return out
