"""SQLite-backed cache for CVE data so the NVD rate limits are respected."""
import json
import time

from .db import SessionLocal
from .models import CacheEntry


class DbCache:
    def get(self, key, ttl):
        with SessionLocal() as s:
            e = s.get(CacheEntry, key)
            if e and time.time() - e.fetched_at < ttl:
                return json.loads(e.value)
        return None

    def set(self, key, value):
        with SessionLocal() as s:
            e = s.get(CacheEntry, key)
            if e is None:
                e = CacheEntry(key=key)
                s.add(e)
            e.value, e.fetched_at = json.dumps(value), time.time()
            s.commit()
