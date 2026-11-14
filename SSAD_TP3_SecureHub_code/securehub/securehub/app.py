"""SecureHub gateway: authentication server, policy enforcement point, document service, data lake,
audit and detection in one Flask app (one process so the lab runs with a single command).
Every request to /auth /api /admin /lab /lake /internal is written to the audit log, allowed or refused."""
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from functools import wraps

from flask import Flask, Response, g, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

from . import passwords, rbac, rsa, tokens
from .audit import AuditLog
from .detect import Detector
from .docsvc import DocumentService, ProofError
from .store import Store
from .tokens import Keyring, TokenError
from lake import data as lake_data
from lake import engines, policy
from lake.catalog import COLUMNS, SENSITIVITY_NAMES

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
LOGGED = ("/auth", "/api", "/admin", "/lab", "/lake", "/internal")

DEFAULTS = dict(DATA_DIR=None, KEY_BITS=1024, PBKDF2_ITER=100_000, TOKEN_TTL=900, CLOCK=time.time,
                HIDE_EXISTENCE=False, ALLOW_SIM_IP=True, LOCK_FAILS=5, LOCK_SECONDS=60, DETECT={},
                LAKE_ROWS=5000, LAKE_SEED=2026, SHOW_DEMO_USERS=True, SPARK_CORES=2)


class Refuse(Exception):
    def __init__(self, status, reason, message=""):
        self.status, self.reason, self.message = status, reason, message or reason


class State:
    def __init__(self, cfg):
        self.cfg = cfg
        self.clock = cfg["CLOCK"]
        self.store = Store(cfg["PBKDF2_ITER"])
        d = cfg["DATA_DIR"]
        if d:
            os.makedirs(d, exist_ok=True)
        kp = os.path.join(d, "keys.json") if d else None
        if kp and os.path.exists(kp):
            with open(kp) as f:
                self.keyring = Keyring(cfg["KEY_BITS"], keys=json.load(f))
        else:
            self.keyring = Keyring(cfg["KEY_BITS"])
            if kp:
                with open(kp, "w") as f:                       # lab only: a private key in a plain file
                    json.dump(self.keyring.to_dict(), f)
        self.audit = AuditLog(os.path.join(d, "audit.jsonl") if d else None, self.clock)
        self.detector = Detector(cfg["DETECT"])
        self.revoked, self.fails = set(), {}
        self.secret = secrets.token_bytes(32)
        self.docs = DocumentService(self.store, self.secret, self.clock)
        self.lake_rows = list(lake_data.generate_rows(cfg["LAKE_ROWS"], cfg["LAKE_SEED"]))
        self.py_engine = engines.PyEngine(self.lake_rows)
        self.spark_engine = None
        self.lab_n = 0
        self.tmp = tempfile.mkdtemp(prefix="securehub_")

    def spark(self):
        if self.spark_engine is None:
            path = os.path.join(self.tmp, "lake.csv")
            lake_data.write_csv(path, self.cfg["LAKE_ROWS"], self.cfg["LAKE_SEED"])
            self.spark_engine = engines.SparkEngine(path, "csv", spark=engines.get_spark(self.cfg["SPARK_CORES"]))
        return self.spark_engine


def create_app(config=None):
    cfg = dict(DEFAULTS, **(config or {}))
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    S = State(cfg)
    app.sh = S
    now = S.clock

    # ------------------------------------------------------------------ gateway plumbing
    @app.before_request
    def start():
        g.ip = (request.headers.get("X-Sim-IP") if cfg["ALLOW_SIM_IP"] and request.headers.get("X-Sim-IP")
                else request.remote_addr or "-")
        g.reason = g.user = g.role = g.object = g.rows = g.purpose = g.attempt = None
        g.extra = {}

    @app.after_request
    def audit(resp):
        p = request.path
        if p.startswith(LOGGED):
            st = resp.status_code
            reason = g.get("reason") or ("ok" if st < 400 else "error")
            e = S.audit.record(method=request.method, path=p, ip=g.get("ip"), user=g.get("user") or g.get("attempt"),
                               role=g.get("role"), status=st, decision="allowed" if st < 400 else "refused",
                               reason=reason, object=g.get("object"), rows=g.get("rows"), purpose=g.get("purpose"),
                               lab=True if request.headers.get("X-Lab") else None, **g.get("extra", {}))
            for a in S.detector.feed(e):
                S.audit.record(type="alert", user=a["subject"], **a)
        return resp

    @app.errorhandler(Refuse)
    def refused(e):
        g.reason = e.reason
        return jsonify(error=e.reason, message=e.message), e.status

    @app.errorhandler(HTTPException)
    def http_err(e):
        g.reason = g.get("reason") or e.name.lower().replace(" ", "_")
        return jsonify(error=e.name.lower().replace(" ", "_"), message=e.description), e.code

    @app.errorhandler(Exception)
    def boom(e):
        app.logger.exception("unhandled")
        g.reason = "server_error"
        return jsonify(error="server_error", message="internal error"), 500

    def authenticate():
        h = request.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            raise Refuse(401, "no_token", "send Authorization: Bearer <token>")
        try:
            claims = tokens.verify(S.keyring, h[7:], now=now(), revoked=S.revoked)
        except TokenError as e:
            raise Refuse(401, e.reason, str(e))
        acct = S.store.get_user(claims["sub"])
        if acct is None or acct["role"] != claims["role"]:
            raise Refuse(401, "unknown_subject", "account missing or role changed")
        g.claims, g.acct, g.user, g.role = claims, acct, claims["sub"], claims["role"]

    def guard(perm):
        def deco(fn):
            @wraps(fn)
            def inner(*a, **kw):
                authenticate()
                if not rbac.has_permission(g.role, perm):
                    raise Refuse(403, "role_lacks_permission", "your role may not do this")
                return fn(*a, **kw)
            return inner
        return deco

    def body():
        b = request.get_json(silent=True)
        return b if isinstance(b, dict) else {}

    def pub():
        return S.store.public_user(g.user)

    # ------------------------------------------------------------------ static pages
    @app.get("/")
    def index():
        return send_from_directory(WEB, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(WEB, name)

    @app.get("/favicon.ico")
    def favicon():
        return "", 204

    @app.get("/api/info")
    def info():
        out = {"name": "SecureHub", "alg": tokens.ALG, "spark": engines.spark_available(),
               "lake_rows": len(S.lake_rows), "ttl": cfg["TOKEN_TTL"]}
        if cfg["SHOW_DEMO_USERS"]:
            from .store import DEMO_USERS
            out["demo_users"] = [{"username": u, "password": p, "role": r} for u, p, r, _ in DEMO_USERS]
        return jsonify(out)

    # ------------------------------------------------------------------ authentication server
    @app.post("/auth/login")
    def login():
        b = body()
        username, password = str(b.get("username", ""))[:64], str(b.get("password", ""))[:200]
        g.attempt = username
        t = now()
        fl = [x for x in S.fails.get(username, []) if x > t - cfg["LOCK_SECONDS"]]
        S.fails[username] = fl
        if len(fl) >= cfg["LOCK_FAILS"]:
            g.reason = "locked"
            return jsonify(error="too_many_attempts", retry_after=int(fl[0] + cfg["LOCK_SECONDS"] - t) + 1), 429
        acct = S.store.get_user(username)
        ok = passwords.verify_password(password, acct["hash"] if acct else S.store.dummy_hash) and acct is not None
        if not ok:                                   # same answer for unknown user and wrong password
            fl.append(t)
            g.reason = "bad_credentials"
            return jsonify(error="invalid_credentials", message="Wrong username or password"), 401
        S.fails.pop(username, None)
        token, claims = tokens.issue(S.keyring, username, acct["role"], cfg["TOKEN_TTL"], now=t)
        g.user, g.role = username, acct["role"]
        return jsonify(token=token, expires_at=claims["exp"], user=S.store.public_user(username))

    @app.post("/auth/logout")
    def logout():
        authenticate()
        S.revoked.add(g.claims["jti"])
        return "", 204

    @app.get("/auth/public-key")
    def public_key():
        return jsonify(S.keyring.public_info())

    @app.get("/auth/me")
    def me():
        authenticate()
        return jsonify(claims=g.claims, user=pub())

    # ------------------------------------------------------------------ documents (RBAC + object rules)
    def call_docs(action, ref=None, payload=None):
        ts = int(now())
        proof = S.docs.make_proof(g.user, g.role, action, ref, ts)
        return S.docs.call(action, g.user, g.role, ref, payload, proof, ts)

    @app.get("/api/documents")
    @guard("doc:list")
    def list_docs():
        st, b, why = call_docs("list")
        g.rows = len(b["documents"])
        return jsonify(b), st

    @app.get("/api/documents/<ref>")
    @guard("doc:read")
    def read_doc(ref):
        g.object = ref[:20]
        st, b, why = call_docs("read", ref)
        if st != 200:
            g.reason = why
            if st == 403 and cfg["HIDE_EXISTENCE"]:
                return jsonify(error="not_found"), 404
        return jsonify(b), st

    @app.post("/api/documents")
    @guard("doc:create")
    def create_doc():
        b = body()
        t, c, k, x = b.get("title"), b.get("course"), b.get("kind"), b.get("body", "")
        if not (isinstance(t, str) and 1 <= len(t) <= 120 and isinstance(x, str) and len(x) <= 2000
                and k in ("lecture", "exam") and isinstance(c, str)):
            raise Refuse(400, "bad_input", "title (1-120), course, kind lecture|exam, body (<=2000)")
        st, out, why = call_docs("create", None, {"title": t, "course": c, "kind": k, "body": x})
        if st != 201:
            g.reason = why
        return jsonify(out), st

    @app.delete("/api/documents/<ref>")
    @guard("doc:delete")
    def delete_doc(ref):
        g.object = ref[:20]
        st, out, why = call_docs("delete", ref)
        if st != 200:
            g.reason = why
        return jsonify(out), st

    @app.get("/internal/docs/<ref>")
    def internal_doc(ref):
        """The document service seen from the network: refuses anyone who is not the gateway."""
        g.object = ref[:20]
        h = request.headers
        try:
            S.docs.check_proof(h.get("X-Proof-Sub", ""), h.get("X-Proof-Role", ""), "read", ref,
                               h.get("X-Proof-Ts", ""), h.get("X-Gateway-Proof", ""))
        except ProofError:
            raise Refuse(401, "no_gateway_proof", "this service only answers the gateway")
        return jsonify(S.store.docs.get(int(ref)) if ref.isdigit() and int(ref) in S.store.docs else {"error": "not_found"})

    # ------------------------------------------------------------------ data lake (ABAC on top of RBAC)
    def lake_args():
        b = body()
        purpose = b.get("purpose")
        if not isinstance(purpose, str):
            raise Refuse(400, "bad_input", "purpose is required")
        g.purpose = purpose[:30]
        return purpose, b.get("query", {}), b

    def make_plan(purpose, query):
        try:
            return policy.plan_query(pub(), purpose, policy.zone_of(g.ip), query, pepper=policy.PEPPER)
        except policy.PolicyError as e:
            raise Refuse(400, e.reason, str(e))

    def plan_view(p):
        keep = ("subject", "role", "purpose", "zone", "allowed", "reason", "columns_denied", "row_filter", "constraints",
                "explain", "sql", "limit", "aggregate")
        v = {k: p.get(k) for k in keep}
        try:
            v["original_sql"] = policy.original_sql(p["query"])
        except Exception:
            v["original_sql"] = None
        return v

    @app.get("/lake/info")
    @guard("lake:policy")
    def lake_info():
        return jsonify(subject=pub(), zone=policy.zone_of(g.ip), engines={"python": True, "spark": engines.spark_available()},
                       rows=len(S.lake_rows), rules=policy.RULES, constraints=policy.CONSTRAINTS,
                       columns=[dict(c, sensitivity_name=SENSITIVITY_NAMES[c["sensitivity"]]) for c in COLUMNS.values()])

    @app.post("/lake/explain")
    @guard("lake:explain")
    def lake_explain():
        purpose, query, _ = lake_args()
        g.object = "lake"
        p = make_plan(purpose, query)
        if not p["allowed"]:
            g.reason = p["reason"]
        return jsonify(plan_view(p)), 200

    @app.post("/lake/query")
    @guard("lake:query")
    def lake_query():
        purpose, query, b = lake_args()
        g.object, g.rows = "lake", 0
        p = make_plan(purpose, query)
        if not p["allowed"]:
            g.reason = p["reason"]
            return jsonify(error="forbidden", reason=p["reason"], plan=plan_view(p)), 403
        eng = b.get("engine", "python")
        if eng == "spark":
            if not engines.spark_available():
                raise Refuse(400, "spark_unavailable", "PySpark or Java is not installed")
            res = S.spark().run(p)
        elif eng == "python":
            res = S.py_engine.run(p)
        else:
            raise Refuse(400, "bad_engine", "engine must be python or spark")
        g.rows = res["row_count"]
        return jsonify(result=res, plan=plan_view(p))

    @app.get("/lake/policy")
    @guard("lake:policy")
    def lake_policy():
        return jsonify(rules=policy.RULES, constraints=policy.CONSTRAINTS)

    # ------------------------------------------------------------------ administrator: audit and keys
    @app.get("/admin/audit")
    @guard("audit:read")
    def admin_audit():
        try:
            since, limit = int(request.args.get("since", 0)), min(int(request.args.get("limit", 200)), 1000)
        except ValueError:
            raise Refuse(400, "bad_input", "since and limit are integers")
        return jsonify(entries=S.audit.since(since, limit, request.args.get("type")), head=S.audit.head())

    @app.get("/admin/stream")
    @guard("audit:stream")
    def admin_stream():
        since = int(request.args.get("since", 0) or 0)
        once = request.args.get("once") == "1"
        q = None if once else S.audit.subscribe()

        def gen():
            try:
                last = since
                for e in S.audit.since(since, 1000):
                    last = e["id"]
                    yield "data: %s\n\n" % json.dumps(e)
                if once:
                    return
                while True:
                    try:
                        e = q.get(timeout=10)
                        if e["id"] > last:
                            last = e["id"]
                            yield "data: %s\n\n" % json.dumps(e)
                    except Exception:
                        yield ": ping\n\n"
            finally:
                if q:
                    S.audit.unsubscribe(q)
        return Response(gen(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/admin/verify-chain")
    @guard("audit:verify")
    def verify_chain():
        return jsonify(dict(S.audit.verify(), head=S.audit.head()))

    @app.get("/admin/stats")
    @guard("audit:read")
    def stats():
        es = S.audit.entries
        req = [e for e in es if e["type"] == "request"]
        al = [e for e in es if e["type"] == "alert"]
        by_rule = {}
        for a in al:
            by_rule[a["rule"]] = by_rule.get(a["rule"], 0) + 1
        return jsonify(requests=len(req), allowed=sum(1 for e in req if e["status"] < 400),
                       refused=sum(1 for e in req if e["status"] >= 400), alerts=len(al), by_rule=by_rule,
                       head=S.audit.head())

    @app.post("/admin/rotate-key")
    @guard("keys:rotate")
    def rotate():
        kid = S.keyring.rotate()
        return jsonify(active=kid, keys=S.keyring.public_info()["keys"])

    @app.get("/admin/users")
    @guard("users:list")
    def users():
        return jsonify(users=[S.store.public_user(u) for u in S.store.users])

    # ------------------------------------------------------------------ lab: pure-math RSA and token inspector (no data access)
    @app.post("/lab/rsa/toy")
    def rsa_toy():
        b = body()
        try:
            k = rsa.toy_keys(int(b["p"]), int(b["q"]), int(b["e"]))
            m = int(b["m"])
            if not 0 <= m < k["n"]:
                raise ValueError("message must satisfy 0 <= m < n = %d" % k["n"])
            s = rsa.textbook_sign(k["n"], k["d"], m)
            return jsonify(keys=k, m=m, signature=s, verifies=rsa.textbook_verify(k["n"], k["e"], m, s))
        except (KeyError, ValueError, TypeError) as e:
            raise Refuse(400, "bad_input", str(e))

    @app.post("/lab/rsa/forge")
    def rsa_forge():
        b = body()
        try:
            k = rsa.toy_keys(int(b["p"]), int(b["q"]), int(b["e"]))
            m1, m2 = int(b["m1"]), int(b["m2"])
            s1, s2 = rsa.textbook_sign(k["n"], k["d"], m1), rsa.textbook_sign(k["n"], k["d"], m2)
            mf, sf = rsa.forge_multiplicative(k["n"], m1, s1, m2, s2)
            return jsonify(n=k["n"], m1=m1, s1=s1, m2=m2, s2=s2, forged_message=mf, forged_signature=sf,
                           verifies=rsa.textbook_verify(k["n"], k["e"], mf, sf),
                           note="nobody signed %d, yet the signature verifies: that is why padding is mandatory" % mf)
        except (KeyError, ValueError, TypeError) as e:
            raise Refuse(400, "bad_input", str(e))

    @app.post("/lab/rsa/factor")
    def rsa_factor():
        b = body()
        try:
            n, e = int(b["n"]), int(b["e"])
            f = rsa.factor_small(n)
        except (KeyError, ValueError, TypeError) as ex:
            raise Refuse(400, "bad_input", str(ex))
        if not f:
            return jsonify(n=n, factors=None)
        p, q = f
        return jsonify(n=n, factors=[p, q], d=pow(e, -1, (p - 1) * (q - 1)),
                       note="a %d-bit modulus falls to trial division in microseconds; real keys use 2048 bits or more" % n.bit_length())

    @app.post("/lab/inspect")
    def inspect_token():
        t = str(body().get("token", ""))
        out = {}
        try:
            h, p, sig = tokens.decode_unverified(t)
            out.update(header=h, payload=p, signature_bytes=len(sig))
        except TokenError as e:
            return jsonify(valid=False, reason=e.reason, message=str(e))
        try:
            tokens.verify(S.keyring, t, now=now(), revoked=S.revoked)
            out.update(valid=True, reason="ok")
        except TokenError as e:
            out.update(valid=False, reason=e.reason, message=str(e))
        return jsonify(out)

    @app.get("/lab/rsa/compare-openssl")
    def compare_openssl():
        binary = os.environ.get("OPENSSL_BIN") or shutil.which("openssl")
        if not binary:
            return jsonify(available=False, message="OpenSSL not found (set OPENSSL_BIN)")
        key = S.keyring.keys[S.keyring.active]["key"]
        msg = b"securehub openssl comparison"
        sig = rsa.sign(key, msg)
        with tempfile.TemporaryDirectory() as d:
            for name, data in (("m", msg), ("s", sig)):
                with open(os.path.join(d, name), "wb") as f:
                    f.write(data)
            with open(os.path.join(d, "pub.pem"), "w") as f:
                f.write(rsa.public_pem(key.n, key.e))
            r = subprocess.run([binary, "dgst", "-sha256", "-verify", os.path.join(d, "pub.pem"), "-signature",
                                os.path.join(d, "s"), os.path.join(d, "m")], capture_output=True, text=True, timeout=20)
        return jsonify(available=True, openssl_says=(r.stdout + r.stderr).strip(), verified=r.returncode == 0,
                       bits=key.bits, note="our pure-Python signature was verified by OpenSSL")

    # ------------------------------------------------------------------ lab: attacks (administrator only)
    from . import lab
    lab.register(app, S, cfg, guard, Refuse, body)
    return app
