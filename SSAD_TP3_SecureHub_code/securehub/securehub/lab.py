"""Attack lab (administrator only). Every attack is sent through the REAL gateway as ordinary HTTP
requests, from a simulated source address, flagged 'lab' in the audit log. Detector state is reset before each
attack so the experiment is clean (cooldowns would otherwise hide a second run)."""
import json
import threading

from flask import jsonify, request

from . import tokens
from .store import DEMO_USERS

PASSWORDS = {u: p for u, p, _, _ in DEMO_USERS}
Q_LIST = {"columns": ["record_id", "full_name", "diagnosis_label"], "limit": 100}


def _threaded(fn):
    """Nested requests run in their own thread so they get their own Flask context (g)."""
    box = {}

    def run():
        try:
            box["r"] = fn()
        except Exception as e:           # noqa
            box["e"] = e
    t = threading.Thread(target=run)
    t.start()
    t.join()
    if "e" in box:
        raise box["e"]
    return box["r"]


class Runner:
    def __init__(self, app, S):
        self.app, self.S = app, S

    def ip(self, internal=False):
        self.S.lab_n += 1
        n = self.S.lab_n
        return ("10.1.%d.%d" if internal else "10.66.%d.%d") % (n // 250, n % 250 + 1)

    def call(self, trace, method, path, token=None, js=None, ip=None, label=None, headers=None):
        h = {"X-Lab": "1", "X-Sim-IP": ip or self.ip()}
        if token:
            h["Authorization"] = "Bearer " + token
        h.update(headers or {})

        def go():
            return self.app.test_client().open(path, method=method, json=js, headers=h)
        r = _threaded(go)
        j = r.get_json(silent=True) or {}
        trace.append({"call": "%s %s" % (method, label or path), "status": r.status_code,
                      "reason": j.get("reason") or j.get("error") or ("ok" if r.status_code < 400 else "error")})
        return r.status_code, j

    def login(self, user, ip, trace=None, password=None):
        st, j = self.call(trace if trace is not None else [], "POST", "/auth/login",
                          js={"username": user, "password": password or PASSWORDS[user]}, ip=ip, label="/auth/login (%s)" % user)
        return j.get("token")


def collapse(trace):
    out = []
    for t in trace:
        if out and all(out[-1][k] == t[k] for k in ("call", "status", "reason")):
            out[-1]["count"] += 1
        else:
            out.append(dict(t, count=1))
    return out


# ------------------------------------------------------------------ the attacks
def a_brute_force(R, tr):
    ip = R.ip()
    for i in range(6):
        R.call(tr, "POST", "/auth/login", js={"username": "alice", "password": "guess%d" % i}, ip=ip, label="/auth/login (alice, wrong password)")
    R.S.fails.pop("alice", None)


def a_token_tamper(R, tr):
    ip = R.ip()
    tok = R.login("alice", ip, tr)
    h, p, s = tok.split(".")
    pl = json.loads(tokens.unb64u(p))
    pl["role"] = "administrator"
    forged = ".".join([h, tokens.b64u(json.dumps(pl, separators=(",", ":")).encode()), s])
    R.call(tr, "GET", "/admin/stats", token=forged, ip=ip, label="/admin/stats (payload edited: role=administrator)")


def a_alg_none(R, tr):
    ip = R.ip()
    h = tokens.b64u(json.dumps({"alg": "none", "typ": "SHT", "kid": R.S.keyring.active}).encode())
    p = tokens.b64u(json.dumps({"iss": tokens.ISSUER, "sub": "alice", "role": "administrator", "aud": tokens.AUDIENCE,
                                "iat": 1, "exp": 9999999999, "jti": "x"}).encode())
    R.call(tr, "GET", "/admin/stats", token=h + "." + p + ".", ip=ip, label="/admin/stats (alg none, empty signature)")


def a_expired(R, tr):
    ip = R.ip()
    tok, _ = tokens.issue(R.S.keyring, "alice", "student", ttl=60, now=R.S.clock() - 3600)
    for _ in range(3):
        R.call(tr, "GET", "/api/documents", token=tok, ip=ip, label="/api/documents (expired token)")


def a_priv_esc(R, tr):
    ip = R.ip()
    tok = R.login("alice", ip, tr)
    R.call(tr, "DELETE", "/api/documents/1", token=tok, ip=ip)
    R.call(tr, "GET", "/admin/audit", token=tok, ip=ip)
    R.call(tr, "POST", "/api/documents", token=tok, js={"title": "x", "course": "SSAD", "kind": "lecture", "body": ""}, ip=ip)


def a_enum(R, tr):
    ip = R.ip()
    tok = R.login("alice", ip, tr)
    for i in range(1, 31):
        R.call(tr, "GET", "/api/documents/%d" % i, token=tok, ip=ip, label="/api/documents/<id> (id guessing)")


def a_burst(R, tr):
    ip = R.ip()
    tok = R.login("alice", ip, tr)
    for _ in range(35):
        R.call(tr, "GET", "/api/documents", token=tok, ip=ip)


def a_direct(R, tr):
    ip = R.ip()
    R.call(tr, "GET", "/internal/docs/5", ip=ip, label="/internal/docs/5 (no proof)")
    R.call(tr, "GET", "/internal/docs/5", ip=ip, label="/internal/docs/5 (forged proof)",
           headers={"X-Proof-Sub": "alice", "X-Proof-Role": "administrator", "X-Proof-Ts": "1", "X-Gateway-Proof": "00" * 32})


def a_bola(R, tr):
    ip = R.ip()
    tok = R.login("alice", ip, tr)
    R.call(tr, "GET", "/api/documents/5", token=tok, ip=ip, label="/api/documents/5 (bob's grades, check ON)")
    R.S.docs.vulnerable_bola = True
    try:
        R.call(tr, "GET", "/api/documents/5", token=tok, ip=ip, label="/api/documents/5 (bob's grades, object check REMOVED)")
    finally:
        R.S.docs.vulnerable_bola = False


def a_lake_overreach(R, tr):
    ip = R.ip(True)
    tok = R.login("lina", ip, tr)
    qs = [("research", {"columns": "*", "limit": 5}), ("research", {"group_by": ["national_id"], "metrics": [{"fn": "count"}]}),
          ("care", {"group_by": ["service"], "metrics": [{"fn": "count"}]}), ("research", {"metrics": [{"fn": "avg", "col": "full_name"}]})]
    for purpose, q in qs:
        R.call(tr, "POST", "/lake/query", token=tok, js={"purpose": purpose, "query": q}, ip=ip,
               label="/lake/query (analyst, purpose=%s)" % purpose)


def a_lake_mass(R, tr):
    ip = R.ip(True)
    tok = R.login("dr_amine", ip, tr)
    for _ in range(6):
        R.call(tr, "POST", "/lake/query", token=tok, js={"purpose": "care", "query": Q_LIST}, ip=ip,
               label="/lake/query (doctor dumps 100 rows)")


def a_lake_inference(R, tr):
    ip = R.ip(True)
    tok = R.login("lina", ip, tr)
    base = {"group_by": ["city"], "metrics": [{"fn": "count"}]}
    for w in ({"col": "national_id", "op": "=", "value": "123456789012"}, {"col": "patient_id", "op": "=", "value": "P0000001"},
              {"col": "city", "op": "=", "value": "x' OR '1'='1"}):
        R.call(tr, "POST", "/lake/query", token=tok, js={"purpose": "research", "query": dict(base, where=[w])}, ip=ip,
               label="/lake/query (filter on %s)" % w["col"])


ATTACKS = {
    "brute_force": ("Password guessing", "brute_force", a_brute_force,
                    "Six wrong passwords for alice from one address.", "Lockout after 5 failures; same error for any failure; rule brute_force."),
    "token_tamper": ("Edited token payload", "token_tampering", a_token_tamper,
                     "A student changes role to administrator inside the token and keeps the old signature.",
                     "The RSA signature no longer matches the payload: 401 bad_signature."),
    "alg_none": ("alg=none token", "token_tampering", a_alg_none,
                 "A token that declares no algorithm and has an empty signature.", "The algorithm comes from the server allow-list, never from the token."),
    "expired_reuse": ("Expired token reuse", "expired_reuse", a_expired,
                      "An old, once-valid token is replayed three times.", "exp claim is checked; repeated use raises expired_reuse."),
    "priv_esc": ("Privilege escalation", "privilege_escalation", a_priv_esc,
                 "A student calls delete, audit and create endpoints.", "RBAC refuses (403) and three refusals raise the alert."),
    "enumeration": ("Object-id guessing", "object_enumeration", a_enum,
                    "A student walks ids 1..30 of /api/documents/<id>.", "Object-level check refuses others' documents; many refused ids raise the alert."),
    "burst": ("Request burst", "request_burst", a_burst, "35 requests in a few seconds from one address.", "Burst rule (30 requests / 10 s)."),
    "direct_call": ("Bypass the gateway", "token_tampering", a_direct,
                    "Calling the document service directly, with no or a forged gateway proof.", "The service answers only calls carrying the gateway's HMAC proof."),
    "bola": ("BOLA: read another student's grades", None, a_bola,
             "alice requests bob's grades document by id; then the same request with the object-level check removed.",
             "With the check: 403 not_owner. Without it: 200 and the data leaks - proof that role checks alone are not enough."),
    "lake_overreach": ("Data lake: analyst over-reach", "repeated_denied", a_lake_overreach,
                       "An analyst asks for raw rows, a restricted column, the wrong purpose and a metric on a name.",
                       "ABAC: aggregate-only, default deny, purpose limitation; repeated refusals raise the alert."),
    "lake_mass": ("Data lake: mass access", "mass_access", a_lake_mass,
                  "A doctor account dumps 100 rows six times in one minute.", "Row cap per query and the mass_access rule (rows read per minute)."),
    "lake_inference": ("Data lake: inference by filtering", None, a_lake_inference,
                       "An analyst filters on a hashed or restricted column to test guesses, and tries a quote injection.",
                       "Filters on non-clear columns are refused; values are allow-listed so nothing can be injected into the SQL."),
}


def attack_info():
    return [{"name": k, "title": v[0], "expected_rule": v[1], "what": v[3], "defence": v[4]} for k, v in ATTACKS.items()]


def run_attack(R, name):
    S = R.S
    title, expected, fn, what, defence = ATTACKS[name]
    S.detector.reset()
    S.fails.clear()
    before = len(S.audit.entries)
    tr = []
    fn(R, tr)
    new = S.audit.entries[before:]
    fired = [e["rule"] for e in new if e["type"] == "alert"]
    flat = [t for t in tr if "/auth/login (" not in t["call"] or "wrong" in t["call"]]
    if expected:
        passed = expected in fired
    elif name == "bola":
        st = [t["status"] for t in tr if "/api/documents/5" in t["call"]]
        passed = st == [403, 200]
    else:
        passed = all(t["status"] >= 400 for t in flat)
    return {"name": name, "title": title, "what": what, "defence": defence, "expected_rule": expected,
            "alerts_fired": sorted(set(fired)), "passed": passed, "trace": collapse(tr)}


def benign(R):
    """Normal use of the platform by every demo user from its own address: nothing should alert."""
    S = R.S
    S.detector.reset()
    S.fails.clear()
    before = len(S.audit.entries)
    for user, plan in (("alice", "student"), ("bob", "student"), ("carol", "teacher"), ("dave", "teacher"), ("root", "admin"),
                       ("dr_amine", "doctor"), ("dr_sofia", "doctor"), ("lina", "analyst")):
        tr, ip = [], R.ip(True)
        if user == "bob":
            R.login("bob", ip, tr, password="typo")                 # a normal mistake
        tok = R.login(user, ip, tr)
        if plan == "student":
            R.call(tr, "GET", "/api/documents", token=tok, ip=ip)
            for i in ((1, 2, 4) if user == "alice" else (1, 2, 5)):
                R.call(tr, "GET", "/api/documents/%d" % i, token=tok, ip=ip)
            R.call(tr, "GET", "/api/documents/3", token=tok, ip=ip)   # a normal click on a forbidden item
        elif plan == "teacher":
            R.call(tr, "GET", "/api/documents", token=tok, ip=ip)
            R.call(tr, "GET", "/api/documents/%d" % (3 if user == "carol" else 7), token=tok, ip=ip)
            R.call(tr, "POST", "/api/documents", token=tok, ip=ip,
                   js={"title": "Notes %s" % user, "course": "SSAD" if user == "carol" else "NET", "kind": "lecture", "body": "x"})
        elif plan == "admin":
            for p in ("/admin/stats", "/admin/audit", "/admin/verify-chain"):
                R.call(tr, "GET", p, token=tok, ip=ip)
        elif plan == "doctor":
            for _ in range(3):
                R.call(tr, "POST", "/lake/query", token=tok, ip=ip, js={"purpose": "care", "query": {"columns": ["record_id", "full_name", "diagnosis_label"], "limit": 20}})
        else:
            for _ in range(3):
                R.call(tr, "POST", "/lake/query", token=tok, ip=ip, js={"purpose": "research", "query": {"group_by": ["service"], "metrics": [{"fn": "count"}, {"fn": "avg", "col": "treatment_cost"}]}})
        R.call(tr, "POST", "/auth/logout", token=tok, ip=ip)
    new = S.audit.entries[before:]
    alerts = [e for e in new if e["type"] == "alert"]
    return {"requests": sum(1 for e in new if e["type"] == "request"), "alerts": len(alerts),
            "false_positives": [a["rule"] for a in alerts]}


VIEW_FALLBACK = {
    "analyst": ("research", {"group_by": ["diagnosis_code"], "metrics": [{"fn": "count"}, {"fn": "avg", "col": "treatment_cost"}, {"fn": "count_distinct", "col": "patient_id"}], "order_by": [{"col": "diagnosis_code"}]}),
    "administrator": ("maintenance", {"group_by": ["service"], "metrics": [{"fn": "count"}], "order_by": [{"col": "service"}]}),
}


def views(R, query):
    """Same table, same question, three identities."""
    out = []
    for user, role, purpose in (("dr_amine", "doctor", "care"), ("lina", "analyst", "research"), ("root", "administrator", "maintenance")):
        tr, ip = [], R.ip(True)
        tok = R.login(user, ip, tr)
        item = {"user": user, "role": role, "purpose": purpose}
        st, j = R.call(tr, "POST", "/lake/query", token=tok, js={"purpose": purpose, "query": query}, ip=ip)
        item["attempt"] = j
        item["attempt_status"] = st
        if role in VIEW_FALLBACK and st != 200:
            p2, q2 = VIEW_FALLBACK[role]
            st2, j2 = R.call(tr, "POST", "/lake/query", token=tok, js={"purpose": p2, "query": q2}, ip=ip)
            item["fallback"], item["fallback_status"], item["fallback_query"] = j2, st2, q2
        out.append(item)
    return out


def register(app, S, cfg, guard, Refuse, body):
    R = Runner(app, S)

    @app.get("/lab/attacks")
    @guard("lab:attack")
    def list_attacks():
        return jsonify(attacks=attack_info())

    @app.post("/lab/attack/<name>")
    @guard("lab:attack")
    def attack(name):
        if name == "all":
            res = [run_attack(R, n) for n in ATTACKS]
            return jsonify(results=res, passed=sum(r["passed"] for r in res), total=len(res))
        if name not in ATTACKS:
            raise Refuse(404, "unknown_attack", name)
        return jsonify(run_attack(R, name))

    @app.post("/lab/benign")
    @guard("lab:attack")
    def run_benign():
        return jsonify(benign(R))

    @app.post("/lab/lake-views")
    @guard("lab:attack")
    def lake_views():
        q = body().get("query") or {"columns": ["record_id", "patient_id", "full_name", "national_id", "birth_date", "city", "service", "diagnosis_label", "treatment_cost"], "limit": 3}
        return jsonify(views=views(R, q), query=q)

    @app.post("/lab/tamper-log")
    @guard("lab:attack")
    def tamper():
        b = body()
        eid = int(b.get("id") or max(1, len(S.audit.entries) // 2))
        ok = S.audit.tamper(eid, "user", "nobody")
        return jsonify(tampered=ok, id=eid, verify=S.audit.verify())

    @app.post("/lab/vuln")
    @guard("lab:attack")
    def vuln():
        S.docs.vulnerable_bola = bool(body().get("bola"))
        return jsonify(bola_vulnerable=S.docs.vulnerable_bola)

    @app.post("/lab/reset")
    @guard("lab:attack")
    def reset():
        S.store.reset()
        S.fails.clear()
        S.revoked.clear()
        S.detector.reset()
        S.docs.vulnerable_bola = False
        with S.audit.lock:
            S.audit.entries.clear()
            if S.audit.path:
                open(S.audit.path, "w").close()
        return jsonify(reset=True)
