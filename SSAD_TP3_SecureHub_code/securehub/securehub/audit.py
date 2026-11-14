"""Accountability: an append-only log in which every entry contains the hash of the previous one.
Changing, removing or inserting an entry in the middle breaks every hash after it, and verify()
reports the first bad entry. Limit (stated in the report): deleting the LAST entries is only caught if
the head hash was written down elsewhere, so head() is shown on the dashboard."""
import hashlib
import json
import os
import queue
import threading
import time

GENESIS = "0" * 64


def _canon(entry):
    return json.dumps({k: v for k, v in entry.items() if k != "hash"}, sort_keys=True, separators=(",", ":"))


def _hash(prev, entry):
    return hashlib.sha256((prev + _canon(entry)).encode()).hexdigest()


class AuditLog:
    def __init__(self, path=None, clock=time.time):
        self.path, self.clock = path, clock
        self.entries = []
        self.lock = threading.Lock()
        self.subs = []
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self.entries = [json.loads(line) for line in f if line.strip()]

    def record(self, **fields):
        with self.lock:
            e = {"id": len(self.entries) + 1, "ts": round(self.clock(), 3), "type": "request"}
            e.update({k: v for k, v in fields.items() if v is not None})
            e["prev"] = self.entries[-1]["hash"] if self.entries else GENESIS
            e["hash"] = _hash(e["prev"], e)
            self.entries.append(e)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(e, separators=(",", ":")) + "\n")
            subs = list(self.subs)
        for q in subs:
            try:
                q.put_nowait(e)
            except queue.Full:
                pass
        return e

    def verify(self):
        prev = GENESIS
        for e in self.entries:
            if e.get("prev") != prev:
                return {"ok": False, "checked": e["id"], "first_bad": e["id"], "reason": "chain link broken"}
            if _hash(prev, e) != e.get("hash"):
                return {"ok": False, "checked": e["id"], "first_bad": e["id"], "reason": "entry content changed"}
            prev = e["hash"]
        return {"ok": True, "checked": len(self.entries), "first_bad": None, "reason": "all links valid"}

    def head(self):
        return {"count": len(self.entries), "hash": self.entries[-1]["hash"] if self.entries else GENESIS}

    def since(self, after=0, limit=200, kind=None):
        out = [e for e in self.entries if e["id"] > after and (kind is None or e["type"] == kind)]
        return out[-limit:] if after == 0 else out[:limit]

    def subscribe(self):
        q = queue.Queue(maxsize=1000)
        with self.lock:
            self.subs.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.subs:
                self.subs.remove(q)

    # lab only: simulate an intruder editing the stored log
    def tamper(self, entry_id, field, value):
        for e in self.entries:
            if e["id"] == entry_id:
                e[field] = value
                return True
        return False

    def export_jsonl(self, path):
        with open(path, "w", encoding="utf-8") as f:
            for e in self.entries:
                f.write(json.dumps(e, separators=(",", ":")) + "\n")
        return path
