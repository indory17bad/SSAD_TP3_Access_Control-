import json
import os
import tempfile
import unittest

from securehub import tokens
from securehub.app import create_app
from lake import engines

SPARK = engines.spark_available()
PW = {"alice": "alice-pass-1", "bob": "bob-pass-2", "carol": "carol-pass-3", "dave": "dave-pass-4", "root": "root-pass-5",
      "dr_amine": "amine-pass-6", "dr_sofia": "sofia-pass-7", "lina": "lina-pass-8"}


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class Base(unittest.TestCase):
    cfg = {}

    def setUp(self):
        self.clock = Clock()
        self.app = create_app(dict({"KEY_BITS": 512, "PBKDF2_ITER": 1000, "LAKE_ROWS": 3000, "CLOCK": self.clock}, **self.cfg))
        self.c = self.app.test_client()
        self.S = self.app.sh

    def login(self, user, password=None, ip=None):
        h = {"X-Sim-IP": ip} if ip else {}
        r = self.c.post("/auth/login", json={"username": user, "password": password or PW[user]}, headers=h)
        return r

    def tok(self, user, ip=None):
        return self.login(user, ip=ip).get_json()["token"]

    def H(self, user, ip=None):
        h = {"Authorization": "Bearer " + self.tok(user, ip)}
        if ip:
            h["X-Sim-IP"] = ip
        return h

    def alerts(self):
        return [e["rule"] for e in self.S.audit.entries if e["type"] == "alert"]

    def last(self):
        return [e for e in self.S.audit.entries if e["type"] == "request"][-1]


class TestAuth(Base):
    def test_login_success_returns_signed_token(self):
        r = self.login("alice")
        j = r.get_json()
        self.assertEqual(r.status_code, 200)
        c = tokens.verify(self.S.keyring, j["token"], now=self.clock())
        self.assertEqual((c["sub"], c["role"]), ("alice", "student"))
        self.assertEqual(j["user"]["role"], "student")

    def test_wrong_password_and_unknown_user_look_identical(self):
        a = self.login("alice", "nope")
        b = self.c.post("/auth/login", json={"username": "ghost", "password": "nope"})
        self.assertEqual((a.status_code, a.get_json()), (b.status_code, b.get_json()))
        self.assertEqual(a.status_code, 401)

    def test_lockout_after_five_failures_then_release(self):
        for _ in range(5):
            self.assertEqual(self.login("alice", "bad").status_code, 401)
        r = self.login("alice")                       # even the right password is refused while locked
        self.assertEqual(r.status_code, 429)
        self.assertIn("retry_after", r.get_json())
        self.clock.t += 61
        self.assertEqual(self.login("alice").status_code, 200)

    def test_lockout_is_per_username(self):
        for _ in range(5):
            self.login("alice", "bad")
        self.assertEqual(self.login("bob").status_code, 200)

    def test_successful_login_clears_failures(self):
        for _ in range(4):
            self.login("alice", "bad")
        self.login("alice")
        for _ in range(4):
            self.login("alice", "bad")
        self.assertEqual(self.login("alice").status_code, 200)

    def test_bad_bodies(self):
        for body in (None, {}, {"username": 5}, {"username": "alice"}, []):
            r = self.c.post("/auth/login", json=body)
            self.assertIn(r.status_code, (400, 401, 415), body)

    def test_password_not_in_log(self):
        self.login("alice", "super-secret-guess")
        self.assertNotIn("super-secret-guess", json.dumps(self.S.audit.entries))

    def test_logout_revokes_the_token(self):
        h = self.H("alice")
        self.assertEqual(self.c.get("/api/documents", headers=h).status_code, 200)
        self.assertEqual(self.c.post("/auth/logout", headers=h).status_code, 204)
        r = self.c.get("/api/documents", headers=h)
        self.assertEqual((r.status_code, r.get_json()["error"]), (401, "revoked"))

    def test_me_and_public_key(self):
        self.assertEqual(self.c.get("/auth/me", headers=self.H("bob")).get_json()["claims"]["sub"], "bob")
        k = self.c.get("/auth/public-key").get_json()
        self.assertEqual(k["alg"], "RS256")
        self.assertNotIn("d", k["keys"][0])
        self.assertIn("BEGIN PUBLIC KEY", k["keys"][0]["pem"])

    def test_token_expires_with_the_clock(self):
        h = self.H("alice")
        self.clock.t += 901
        self.assertEqual(self.c.get("/api/documents", headers=h).get_json()["error"], "expired")

    def test_no_token_and_bad_scheme(self):
        self.assertEqual(self.c.get("/api/documents").get_json()["error"], "no_token")
        self.assertEqual(self.c.get("/api/documents", headers={"Authorization": "Basic abc"}).status_code, 401)

    def test_edited_token_refused_and_logged(self):
        t = self.tok("alice")
        h, p, s = t.split(".")
        pl = json.loads(tokens.unb64u(p))
        pl["role"] = "administrator"
        forged = ".".join([h, tokens.b64u(json.dumps(pl).encode()), s])
        r = self.c.get("/admin/stats", headers={"Authorization": "Bearer " + forged})
        self.assertEqual((r.status_code, r.get_json()["error"]), (401, "bad_signature"))
        self.assertIn("token_tampering", self.alerts())

    def test_role_change_in_store_invalidates_token(self):
        h = self.H("alice")
        self.S.store.users["alice"]["role"] = "teacher"
        self.assertEqual(self.c.get("/api/documents", headers=h).get_json()["error"], "unknown_subject")

    def test_key_rotation_refuses_old_tokens(self):
        old = self.H("alice")
        adm = self.H("root")
        self.assertEqual(self.c.post("/admin/rotate-key", headers=adm).status_code, 200)
        self.assertEqual(self.c.get("/api/documents", headers=old).get_json()["error"], "retired_key")
        self.assertEqual(self.c.get("/api/documents", headers=self.H("alice")).status_code, 200)


class TestDocuments(Base):
    def get(self, user, path, **kw):
        return self.c.get(path, headers=self.H(user), **kw)

    def test_list_is_filtered_per_role(self):
        ids = lambda u: {d["id"] for d in self.get(u, "/api/documents").get_json()["documents"]}
        self.assertEqual(ids("alice"), {1, 2, 4, 6, 8, 11, 12})
        self.assertEqual(ids("bob"), {1, 2, 5, 11})
        self.assertEqual(len(ids("root")), 12)

    def test_list_metadata_has_no_body(self):
        for d in self.get("alice", "/api/documents").get_json()["documents"]:
            self.assertNotIn("body", d)

    def test_allowed_and_forbidden_reads(self):
        self.assertEqual(self.get("alice", "/api/documents/4").status_code, 200)
        r = self.get("alice", "/api/documents/5")
        self.assertEqual((r.status_code, r.get_json()["reason"]), (403, "not_owner"))
        self.assertEqual(self.get("alice", "/api/documents/3").get_json()["reason"], "kind_not_allowed")
        self.assertEqual(self.get("carol", "/api/documents/7").get_json()["reason"], "not_your_course")
        self.assertEqual(self.get("root", "/api/documents/4").get_json()["reason"], "separation_of_duties")

    def test_missing_and_malformed_ids(self):
        self.assertEqual(self.get("alice", "/api/documents/999").status_code, 404)
        self.assertEqual(self.get("alice", "/api/documents/abc").status_code, 400)
        self.assertEqual(self.get("alice", "/api/documents/1%27%20OR%201=1").status_code, 400)

    def test_every_role_vs_every_endpoint_matrix(self):
        # (user, method, path, expected status)
        cases = [("alice", "POST", "/api/documents", 403), ("alice", "DELETE", "/api/documents/1", 403), ("alice", "GET", "/admin/audit", 403),
                 ("alice", "GET", "/lab/attacks", 403), ("alice", "POST", "/admin/rotate-key", 403), ("alice", "GET", "/lake/info", 403),
                 ("carol", "DELETE", "/api/documents/1", 403), ("carol", "GET", "/admin/stats", 403), ("carol", "GET", "/lake/info", 403),
                 ("root", "POST", "/api/documents", 403), ("root", "GET", "/api/documents", 200), ("root", "GET", "/admin/stats", 200),
                 ("dr_amine", "GET", "/api/documents", 403), ("dr_amine", "GET", "/admin/audit", 403), ("lina", "DELETE", "/api/documents/1", 403),
                 ("root", "DELETE", "/api/documents/12", 200), ("root", "DELETE", "/api/documents/12", 404)]
        for user, method, path, want in cases:
            r = self.c.open(path, method=method, headers=self.H(user), json={"title": "t", "course": "SSAD", "kind": "lecture", "body": ""})
            self.assertEqual(r.status_code, want, (user, method, path))

    def test_teacher_creates_only_in_own_course(self):
        h = self.H("carol")
        ok = self.c.post("/api/documents", headers=h, json={"title": "N", "course": "SSAD", "kind": "lecture", "body": "x"})
        self.assertEqual(ok.status_code, 201)
        self.assertEqual(ok.get_json()["owner"], "carol")
        no = self.c.post("/api/documents", headers=h, json={"title": "N", "course": "NET", "kind": "lecture", "body": "x"})
        self.assertEqual((no.status_code, no.get_json()["reason"]), (403, "not_your_course"))

    def test_create_validation(self):
        h = self.H("carol")
        for body in ({}, {"title": "", "course": "SSAD", "kind": "lecture"}, {"title": "x" * 200, "course": "SSAD", "kind": "lecture"},
                     {"title": "t", "course": "SSAD", "kind": "grades"}, {"title": "t", "course": "SSAD", "kind": "lecture", "body": "y" * 3000}):
            self.assertEqual(self.c.post("/api/documents", headers=h, json=body).status_code, 400, body)

    def test_hide_existence_mode_returns_404_for_forbidden(self):
        app = create_app({"KEY_BITS": 512, "PBKDF2_ITER": 1000, "LAKE_ROWS": 100, "HIDE_EXISTENCE": True})
        c = app.test_client()
        t = c.post("/auth/login", json={"username": "alice", "password": PW["alice"]}).get_json()["token"]
        h = {"Authorization": "Bearer " + t}
        self.assertEqual(c.get("/api/documents/5", headers=h).status_code, 404)
        self.assertEqual(c.get("/api/documents/999", headers=h).status_code, 404)
        self.assertEqual([e for e in app.sh.audit.entries if e["type"] == "request"][-2]["reason"], "not_owner")   # the log keeps the truth

    def test_bola_flaw_appears_when_object_check_is_removed(self):
        h = self.H("alice")
        self.assertEqual(self.c.get("/api/documents/5", headers=h).status_code, 403)
        self.S.docs.vulnerable_bola = True
        r = self.c.get("/api/documents/5", headers=h)
        self.assertEqual(r.status_code, 200)
        self.assertIn("bob", r.get_json()["body"])

    def test_direct_call_to_document_service_is_refused(self):
        r = self.c.get("/internal/docs/5")
        self.assertEqual((r.status_code, r.get_json()["error"]), (401, "no_gateway_proof"))
        r = self.c.get("/internal/docs/5", headers={"X-Proof-Sub": "alice", "X-Proof-Role": "administrator", "X-Proof-Ts": str(int(self.clock())), "X-Gateway-Proof": "00" * 32})
        self.assertEqual(r.status_code, 401)
        self.assertIn("token_tampering", self.alerts())

    def test_valid_proof_is_accepted_and_expires(self):
        d = self.S.docs
        ts = int(self.clock())
        proof = d.make_proof("alice", "student", "read", "4", ts)
        h = {"X-Proof-Sub": "alice", "X-Proof-Role": "student", "X-Proof-Ts": str(ts), "X-Gateway-Proof": proof}
        self.assertEqual(self.c.get("/internal/docs/4", headers=h).status_code, 200)
        self.clock.t += 120
        self.assertEqual(self.c.get("/internal/docs/4", headers=h).status_code, 401)
        # the proof is bound to its fields: changing the object breaks it
        self.clock.t -= 120
        self.assertEqual(self.c.get("/internal/docs/5", headers=h).status_code, 401)


class TestAuditing(Base):
    def test_every_request_is_logged_allowed_or_refused(self):
        h = self.H("alice")
        before = len([e for e in self.S.audit.entries if e["type"] == "request"])
        for path in ("/api/documents", "/api/documents/5", "/api/documents/999", "/admin/audit", "/nothing-here", "/api/nothing"):
            self.c.get(path, headers=h)
        reqs = [e for e in self.S.audit.entries if e["type"] == "request"][before:]
        self.assertEqual(len(reqs), 5)                                          # /nothing-here is a static path, not an API one
        self.assertEqual([e["decision"] for e in reqs], ["allowed", "refused", "refused", "refused", "refused"])
        self.assertEqual(reqs[1]["reason"], "not_owner")
        self.assertEqual(reqs[1]["user"], "alice")

    def test_failed_login_is_logged_with_attempted_name(self):
        self.login("ghost", "x")
        e = self.last()
        self.assertEqual((e["path"], e["status"], e["user"], e["reason"]), ("/auth/login", 401, "ghost", "bad_credentials"))

    def test_log_has_ip_and_sim_ip_header(self):
        self.c.get("/api/documents", headers={"X-Sim-IP": "198.51.100.7"})
        self.assertEqual(self.last()["ip"], "198.51.100.7")

    def test_sim_ip_can_be_disabled(self):
        app = create_app({"KEY_BITS": 512, "PBKDF2_ITER": 1000, "LAKE_ROWS": 10, "ALLOW_SIM_IP": False})
        app.test_client().get("/api/documents", headers={"X-Sim-IP": "198.51.100.7"})
        self.assertNotEqual(app.sh.audit.entries[-1]["ip"], "198.51.100.7")

    def test_chain_valid_after_traffic(self):
        for u in ("alice", "bob", "carol"):
            self.c.get("/api/documents", headers=self.H(u))
        r = self.c.get("/admin/verify-chain", headers=self.H("root")).get_json()
        self.assertTrue(r["ok"])
        self.assertGreater(r["checked"], 5)

    def test_tampering_detected_through_the_api(self):
        adm = self.H("root")
        self.c.get("/api/documents", headers=self.H("alice"))
        r = self.c.post("/lab/tamper-log", headers=adm, json={}).get_json()
        self.assertTrue(r["tampered"])
        self.assertFalse(r["verify"]["ok"])
        self.assertEqual(r["verify"]["first_bad"], r["id"])

    def test_audit_endpoint_filters_and_pages(self):
        adm = self.H("root")
        for _ in range(3):
            self.c.get("/api/documents", headers=self.H("alice"))
        j = self.c.get("/admin/audit?limit=5", headers=adm).get_json()
        self.assertLessEqual(len(j["entries"]), 5)
        last = j["entries"][-1]["id"]
        self.assertEqual(self.c.get("/admin/audit?since=%d" % last, headers=adm).get_json()["entries"][0]["id"], last + 1)
        self.assertEqual(self.c.get("/admin/audit?since=x", headers=adm).status_code, 400)
        self.assertTrue(all(e["type"] == "alert" for e in self.c.get("/admin/audit?type=alert", headers=adm).get_json()["entries"]))

    def test_stream_once_returns_backlog_as_sse(self):
        adm = self.H("root")
        self.c.get("/api/documents", headers=self.H("alice"))
        r = self.c.get("/admin/stream?once=1", headers=adm)
        self.assertEqual(r.mimetype, "text/event-stream")
        lines = [l for l in r.get_data(as_text=True).split("\n\n") if l.startswith("data: ")]
        self.assertGreaterEqual(len(lines), 3)
        self.assertEqual(json.loads(lines[0][6:])["id"], 1)

    def test_stream_requires_admin(self):
        self.assertEqual(self.c.get("/admin/stream?once=1", headers=self.H("alice")).status_code, 403)

    def test_stats(self):
        self.c.get("/api/documents/5", headers=self.H("alice"))
        s = self.c.get("/admin/stats", headers=self.H("root")).get_json()
        self.assertGreaterEqual(s["refused"], 1)
        self.assertGreaterEqual(s["requests"], s["allowed"] + s["refused"] - 1)

    def test_persistence_with_data_dir(self):
        with tempfile.TemporaryDirectory() as d:
            app = create_app({"KEY_BITS": 512, "PBKDF2_ITER": 1000, "LAKE_ROWS": 10, "DATA_DIR": d})
            app.test_client().get("/api/documents")
            self.assertTrue(os.path.exists(os.path.join(d, "audit.jsonl")))
            self.assertTrue(os.path.exists(os.path.join(d, "keys.json")))
            again = create_app({"KEY_BITS": 512, "PBKDF2_ITER": 1000, "LAKE_ROWS": 10, "DATA_DIR": d})
            self.assertEqual(again.sh.keyring.active, app.sh.keyring.active)
            self.assertEqual(len(again.sh.audit.entries), len(app.sh.audit.entries))

    def test_errors_are_json_and_logged(self):
        self.assertEqual(self.c.post("/api/info").status_code, 405)
        r = self.c.get("/api/does-not-exist")
        self.assertEqual((r.status_code, r.get_json()["error"]), (404, "not_found"))
        self.assertEqual(self.last()["status"], 404)

    def test_body_size_limit(self):
        r = self.c.post("/auth/login", data="x" * 70000, content_type="application/json")
        self.assertEqual(r.status_code, 413)


class TestLakeApi(Base):
    def q(self, user, purpose, query, engine="python", ip=None):
        return self.c.post("/lake/query", headers=self.H(user, ip), json={"purpose": purpose, "query": query, "engine": engine})

    def test_doctor_query_internal(self):
        r = self.q("dr_amine", "care", {"columns": ["record_id", "full_name", "diagnosis_label"], "limit": 5}, ip="127.0.0.1")
        j = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(j["result"]["row_count"], 5)
        self.assertEqual(j["plan"]["row_filter"]["value"], "cardiology")
        self.assertIn("FROM (SELECT", j["plan"]["sql"])

    def test_zone_comes_from_the_address(self):
        a = self.q("dr_amine", "care", {"columns": ["full_name"], "limit": 1}, ip="127.0.0.1").get_json()["result"]["rows"][0][0]
        b = self.q("dr_amine", "care", {"columns": ["full_name"], "limit": 1}, ip="203.0.113.9").get_json()["result"]["rows"][0][0]
        self.assertGreater(len(a), 5)
        self.assertRegex(b, r"^[A-Z]\.( [A-Z]\.)*$")

    def test_refusals_carry_the_reason_and_the_plan(self):
        r = self.q("dr_amine", "care", {"columns": ["treatment_cost"]})
        j = r.get_json()
        self.assertEqual((r.status_code, j["reason"]), (403, "column_denied"))
        self.assertTrue(any(x["conflict"] for x in j["plan"]["explain"]))
        self.assertEqual(self.last()["reason"], "column_denied")
        self.assertEqual(self.last()["object"], "lake")

    def test_analyst_flow(self):
        self.assertEqual(self.q("lina", "research", {"columns": "*"}).get_json()["reason"], "aggregate_only")
        r = self.q("lina", "research", {"group_by": ["service"], "metrics": [{"fn": "count"}, {"fn": "avg", "col": "treatment_cost"}]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["result"]["row_count"], 6)

    def test_admin_sees_masked_aggregates_only(self):
        r = self.q("root", "maintenance", {"group_by": ["service", "diagnosis_code"], "metrics": [{"fn": "count"}]})
        self.assertTrue(all(row[1] == "***" for row in r.get_json()["result"]["rows"]))

    def test_function_level_gate_before_abac(self):
        r = self.c.post("/lake/query", headers=self.H("alice"), json={"purpose": "care", "query": {"columns": ["city"]}})
        self.assertEqual((r.status_code, r.get_json()["error"]), (403, "role_lacks_permission"))

    def test_bad_requests_are_400_not_500(self):
        for body in ({}, {"purpose": 5}, {"purpose": "care", "query": 5}, {"purpose": "care", "query": {"columns": ["nope"]}},
                     {"purpose": "care", "query": {"columns": ["city"]}, "engine": "mysql"}):
            r = self.c.post("/lake/query", headers=self.H("dr_amine"), json=body)
            self.assertEqual(r.status_code, 400, body)

    def test_injection_attempt_is_400_and_logged(self):
        r = self.q("lina", "research", {"group_by": ["city"], "metrics": [{"fn": "count"}], "where": [{"col": "city", "op": "=", "value": "x' OR '1'='1"}]})
        self.assertEqual((r.status_code, r.get_json()["error"]), (400, "bad_value"))
        self.assertEqual(self.last()["status"], 400)

    def test_explain_does_not_touch_data(self):
        r = self.c.post("/lake/explain", headers=self.H("lina"), json={"purpose": "research", "query": {"group_by": ["patient_id"], "metrics": [{"fn": "count"}]}})
        j = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["allowed"])
        self.assertNotIn("result", j)
        self.assertIn("sha2(", j["sql"])
        self.assertIn("SELECT patient_id", j["original_sql"])

    def test_rows_are_recorded_for_mass_access_detection(self):
        self.q("dr_amine", "care", {"columns": ["record_id"], "limit": 100})
        self.assertEqual(self.last()["rows"], 100)

    def test_info_lists_policy(self):
        j = self.c.get("/lake/info", headers=self.H("dr_amine")).get_json()
        self.assertEqual(len(j["columns"]), 13)
        self.assertTrue(any(r["id"] == "D2" for r in j["rules"]))
        self.assertFalse(isinstance(j["subject"].get("hash"), str))

    @unittest.skipUnless(SPARK, "PySpark / Java not installed")
    def test_spark_engine_through_the_api_matches_python(self):
        for user, purpose, query in (("lina", "research", {"group_by": ["service"], "metrics": [{"fn": "count"}, {"fn": "avg", "col": "treatment_cost"}], "order_by": [{"col": "service"}]}),
                                     ("dr_amine", "care", {"columns": ["record_id", "full_name"], "order_by": [{"col": "record_id"}], "limit": 8})):
            a = self.q(user, purpose, query, "python", ip="127.0.0.1").get_json()["result"]
            b = self.q(user, purpose, query, "spark", ip="127.0.0.1").get_json()["result"]
            self.assertEqual(b["engine"], "spark")
            self.assertEqual(len(a["rows"]), len(b["rows"]))
            for ra, rb in zip(a["rows"], b["rows"]):
                for va, vb in zip(ra, rb):
                    self.assertAlmostEqual(float(va), float(vb), places=2) if isinstance(va, float) else self.assertEqual(va, vb)


class TestLab(Base):
    def test_all_attacks_are_detected_or_blocked(self):
        adm = self.H("root")
        j = self.c.post("/lab/attack/all", headers=adm).get_json()
        failed = [r["name"] for r in j["results"] if not r["passed"]]
        self.assertEqual(failed, [])
        self.assertEqual(j["total"], 12)

    def test_each_attack_fires_its_expected_rule(self):
        adm = self.H("root")
        for name, rule in (("brute_force", "brute_force"), ("token_tamper", "token_tampering"), ("alg_none", "token_tampering"),
                           ("expired_reuse", "expired_reuse"), ("priv_esc", "privilege_escalation"), ("enumeration", "object_enumeration"),
                           ("burst", "request_burst"), ("direct_call", "token_tampering"), ("lake_overreach", "repeated_denied"), ("lake_mass", "mass_access")):
            r = self.c.post("/lab/attack/" + name, headers=adm).get_json()
            self.assertIn(rule, r["alerts_fired"], name)

    def test_blocked_attacks_leak_nothing(self):
        adm = self.H("root")
        r = self.c.post("/lab/attack/lake_inference", headers=adm).get_json()
        self.assertEqual([t["status"] for t in r["trace"] if "filter" in t["call"]], [403, 403, 400])
        r = self.c.post("/lab/attack/bola", headers=adm).get_json()
        self.assertEqual([t["status"] for t in r["trace"] if "/api/documents/5" in t["call"]], [403, 200])
        self.assertFalse(self.S.docs.vulnerable_bola)                     # the flaw is switched back off

    def test_attacks_are_flagged_lab_in_the_log(self):
        adm = self.H("root")
        self.c.post("/lab/attack/burst", headers=adm)
        self.assertTrue(any(e.get("lab") for e in self.S.audit.entries))

    def test_attacks_need_admin(self):
        for u in ("alice", "carol", "dr_amine", "lina"):
            self.assertEqual(self.c.post("/lab/attack/all", headers=self.H(u)).status_code, 403, u)
        self.assertEqual(self.c.post("/lab/attack/all").status_code, 401)

    def test_unknown_attack(self):
        self.assertEqual(self.c.post("/lab/attack/nope", headers=self.H("root")).status_code, 404)

    def test_benign_traffic_gives_no_false_positive(self):
        r = self.c.post("/lab/benign", headers=self.H("root")).get_json()
        self.assertEqual(r["false_positives"], [])
        self.assertGreater(r["requests"], 40)

    def test_benign_then_attacks_then_chain_still_valid(self):
        adm = self.H("root")
        self.c.post("/lab/benign", headers=adm)
        self.c.post("/lab/attack/all", headers=adm)
        self.assertTrue(self.c.get("/admin/verify-chain", headers=adm).get_json()["ok"])

    def test_lake_views_show_three_different_answers(self):
        j = self.c.post("/lab/lake-views", headers=self.H("root"), json={}).get_json()
        by = {v["role"]: v for v in j["views"]}
        self.assertEqual(by["doctor"]["attempt_status"], 403)            # billing column denied to the doctor
        self.assertEqual(by["analyst"]["attempt"]["reason"], "aggregate_only")
        self.assertEqual(by["analyst"]["fallback_status"], 200)
        self.assertEqual(by["administrator"]["fallback_status"], 200)

    def test_reset_restores_documents_and_clears_log(self):
        adm = self.H("root")
        self.c.delete("/api/documents/1", headers=adm)
        self.assertEqual(self.c.post("/lab/reset", headers=adm).status_code, 200)
        self.assertEqual(self.c.get("/api/documents/1", headers=self.H("alice")).status_code, 200)
        self.assertLess(len(self.S.audit.entries), 6)


class TestRsaLab(Base):
    def test_toy_endpoint_matches_the_theory(self):
        j = self.c.post("/lab/rsa/toy", json={"p": 61, "q": 53, "e": 17, "m": 65}).get_json()
        self.assertEqual((j["keys"]["n"], j["keys"]["d"], j["signature"], j["verifies"]), (3233, 2753, 588, True))

    def test_toy_bad_input(self):
        for body in ({}, {"p": 60, "q": 53, "e": 17, "m": 1}, {"p": 61, "q": 53, "e": 17, "m": 99999}, {"p": "x", "q": 1, "e": 1, "m": 1}):
            self.assertEqual(self.c.post("/lab/rsa/toy", json=body).status_code, 400, body)

    def test_forge_endpoint(self):
        j = self.c.post("/lab/rsa/forge", json={"p": 61, "q": 53, "e": 17, "m1": 5, "m2": 7}).get_json()
        self.assertEqual((j["forged_message"], j["verifies"]), (35, True))

    def test_factor_endpoint(self):
        j = self.c.post("/lab/rsa/factor", json={"n": 3233, "e": 17}).get_json()
        self.assertEqual((j["factors"], j["d"]), ([53, 61], 2753))
        self.assertEqual(self.c.post("/lab/rsa/factor", json={"n": 2 ** 70, "e": 17}).status_code, 400)

    def test_inspect_reports_reason(self):
        t = self.tok("alice")
        self.assertTrue(self.c.post("/lab/inspect", json={"token": t}).get_json()["valid"])
        h, p, s = t.split(".")
        self.assertEqual(self.c.post("/lab/inspect", json={"token": h + "." + p + ".AAAA"}).get_json()["reason"], "bad_signature")
        self.assertEqual(self.c.post("/lab/inspect", json={"token": "junk"}).get_json()["reason"], "malformed")

    def test_openssl_compare(self):
        j = self.c.get("/lab/rsa/compare-openssl").get_json()
        if j["available"]:
            self.assertTrue(j["verified"])

    def test_static_pages(self):
        for path in ("/", "/static/app.js", "/static/style.css"):
            self.assertEqual(self.c.get(path).status_code, 200, path)
        self.assertEqual(self.c.get("/static/../server.py").status_code, 404)
        self.assertEqual(self.c.get("/static/%2e%2e/server.py").status_code, 404)


if __name__ == "__main__":
    unittest.main()
