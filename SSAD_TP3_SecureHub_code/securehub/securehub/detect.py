"""Intrusion detection: rule-based, over a sliding window of the audit stream.
Eight rules; thresholds are starting values and can be changed in DEFAULTS or per app config.
Rule-based (not machine learning) on purpose: every alert can be explained by one sentence and one threshold."""
from collections import defaultdict, deque

TAMPER = {"malformed", "alg_not_allowed", "unknown_kid", "bad_signature", "no_gateway_proof"}
DEFAULTS = {
    "brute_force": {"count": 5, "window": 60},
    "token_tampering": {"count": 1, "window": 60},
    "privilege_escalation": {"count": 3, "window": 60},
    "object_enumeration": {"count": 8, "window": 60},
    "request_burst": {"count": 30, "window": 10},
    "expired_reuse": {"count": 3, "window": 60},
    "mass_access": {"rows": 500, "window": 60},
    "repeated_denied": {"count": 3, "window": 60},
    "cooldown": 30,
}
SEVERITY = {"brute_force": "high", "token_tampering": "high", "privilege_escalation": "medium",
            "object_enumeration": "high", "request_burst": "low", "expired_reuse": "low",
            "mass_access": "high", "repeated_denied": "medium"}
MESSAGES = {
    "brute_force": "many failed logins in a short time",
    "token_tampering": "a token or gateway proof that fails its cryptographic check",
    "privilege_escalation": "repeated refusals of actions the role may never perform",
    "object_enumeration": "many different object ids refused or not found: guessing ids",
    "request_burst": "too many requests from one address in a few seconds",
    "expired_reuse": "an expired token used again and again",
    "mass_access": "a large number of data-lake rows read in one minute",
    "repeated_denied": "several data-lake queries refused in one minute",
}


class Detector:
    def __init__(self, config=None):
        self.cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULTS.items()}
        for k, v in (config or {}).items():
            if isinstance(v, dict):
                self.cfg[k].update(v)
            else:
                self.cfg[k] = v
        self.win = defaultdict(deque)       # (rule, subject) -> deque of (ts, value, entry id)
        self.last = {}                      # (rule, subject) -> ts of last alert

    def reset(self):
        self.win.clear()
        self.last.clear()

    def _push(self, rule, subject, ts, value, eid):
        dq = self.win[(rule, subject)]
        dq.append((ts, value, eid))
        w = self.cfg[rule]["window"]
        while dq and dq[0][0] <= ts - w:
            dq.popleft()
        return dq

    def feed(self, e):
        """Return a list of alert dicts triggered by this request entry."""
        if e.get("type", "request") != "request":
            return []
        ts, status, path, reason = e["ts"], e["status"], e.get("path", ""), e.get("reason")
        user, ip, eid, obj = e.get("user") or "-", e.get("ip", "-"), e["id"], e.get("object")
        hits = []

        def check(rule, subject, value, threshold, dq_value=None):
            dq = self._push(rule, subject, ts, value, eid)
            total = sum(v for _, v, _ in dq)
            if total >= threshold:
                hits.append((rule, subject, total, [i for _, _, i in dq]))

        if path == "/auth/login" and status in (401, 429):
            check("brute_force", "ip:" + ip, 1, self.cfg["brute_force"]["count"])
            check("brute_force", "user:" + user, 1, self.cfg["brute_force"]["count"])
        if reason in TAMPER:
            check("token_tampering", "ip:" + ip, 1, self.cfg["token_tampering"]["count"])
        if status == 403 and reason in ("role_lacks_permission", "separation_of_duties"):
            check("privilege_escalation", "user:" + user, 1, self.cfg["privilege_escalation"]["count"])
        if status in (403, 404) and path.startswith("/api/documents/") and e.get("object") is not None:
            dq = self._push("object_enumeration", "user:" + user, ts, str(e["object"]), eid)
            if len({v for _, v, _ in dq}) >= self.cfg["object_enumeration"]["count"]:
                hits.append(("object_enumeration", "user:" + user, len({v for _, v, _ in dq}), [i for _, _, i in dq]))
        check("request_burst", "ip:" + ip, 1, self.cfg["request_burst"]["count"])
        if reason == "expired":
            check("expired_reuse", "ip:" + ip, 1, self.cfg["expired_reuse"]["count"])
        if obj == "lake":
            if status < 400:
                check("mass_access", "user:" + user, int(e.get("rows") or 0), self.cfg["mass_access"]["rows"])
            elif status == 403:
                check("repeated_denied", "user:" + user, 1, self.cfg["repeated_denied"]["count"])
        alerts = []
        for rule, subject, total, ids in hits:
            if ts - self.last.get((rule, subject), -1e18) < self.cfg["cooldown"]:
                continue
            self.last[(rule, subject)] = ts
            alerts.append({"rule": rule, "severity": SEVERITY[rule], "subject": subject, "measured": total,
                           "evidence": ids[-10:], "message": MESSAGES[rule]})
        return alerts
