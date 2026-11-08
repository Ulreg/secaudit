import ipaddress
import json
import os
import socket
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from checks import crawl, cve, dns_checks, exposure, fingerprint, headers, tls_checks
from checks.common import Cancelled, Ctx

from . import config, db, models
from .cache import DbCache

# (name, function, timeout in seconds)
PIPELINE = [
    ("Crawl", crawl.run, 300),
    ("HTTPS, headers & cookies", headers.run, 120),
    ("Technology fingerprinting", fingerprint.run, 180),
    ("Vulnerabilities (CVE)", cve.run, 900),
    ("Exposure & web application", exposure.run, 300),
    ("TLS & certificate", tls_checks.run, 300),
    ("DNS, IPv6, DNSSEC, DANE & mail", dns_checks.run, 300),
]
CANCEL: dict[int, threading.Event] = {}


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    if not urlparse(raw).hostname:
        raise ValueError("Invalid target")
    return raw


def check_scope(target: str) -> None:
    host = urlparse(target).hostname
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve {host}")
    if config.ALLOW_PRIVATE:
        return
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError("Private/loopback targets are blocked (start with --allow-private to override)")


def local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return ""


def cancel(scan_id: int) -> bool:
    ev = CANCEL.get(scan_id)
    if ev:
        ev.set()
    return bool(ev)


def run_scan(scan_id: int):
    session = db.SessionLocal()
    scan = session.get(models.Scan, scan_id)
    stop = threading.Event()
    CANCEL[scan_id] = stop
    scan.status, scan.tool_version = "running", config.VERSION
    scan.scanner_ip = config.SCANNER_IP or local_ip()
    session.commit()

    def log(msg: str):
        scan.log = (scan.log or "") + msg + "\n"
        session.commit()

    ctx = Ctx(profile=scan.profile, rate=config.RATE, log=log, cancel=stop,
              nvd_key=os.environ.get("NVD_API_KEY"), cache=DbCache())
    try:
        for name, fn, timeout in PIPELINE:
            if stop.is_set():
                raise Cancelled()
            log(f"== {name}")
            ctx.deadline = time.monotonic() + timeout
            try:
                results = fn(scan.target, ctx)
            except Cancelled:
                raise
            except TimeoutError:
                log(f"{name}: timed out - partial results discarded")
                results = []
            except Exception as e:  # a failing check must never crash the whole scan
                log(f"ERROR in {name}: {e}")
                results = []
            for r in results:
                session.add(models.Finding(scan_id=scan_id, key=r["key"], category=r["category"],
                                           severity=r["severity"], confidence=r["confidence"],
                                           evidence=r["evidence"], params=json.dumps(r["params"], default=str)))
            session.commit()
        scan.status = "completed"
        log("Scan completed.")
    except Cancelled:
        scan.status = "cancelled"
        log("Scan cancelled.")
    except Exception as e:
        scan.status = "failed"
        log(f"Scan failed: {e}")
    finally:
        scan.finished_at = datetime.now(timezone.utc)
        session.commit()
        session.close()
        CANCEL.pop(scan_id, None)
