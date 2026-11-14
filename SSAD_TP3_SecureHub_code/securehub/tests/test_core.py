import json
import os
import shutil
import subprocess
import tempfile
import unittest

from securehub import audit, detect, passwords, rbac, rsa, tokens
from securehub.store import Store


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class TestRSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate(512)

    def test_miller_rabin_primes_and_composites(self):
        for p in (2, 3, 5, 97, 7919, 2 ** 31 - 1, 2 ** 61 - 1):
            self.assertTrue(rsa.is_probable_prime(p), p)
        for c in (0, 1, 4, 100, 7917, 2 ** 31 + 1):
            self.assertFalse(rsa.is_probable_prime(c), c)

    def test_carmichael_numbers_are_rejected(self):
        for c in (561, 1105, 1729, 41041, 825265):       # fool the Fermat test, not Miller-Rabin
            self.assertFalse(rsa.is_probable_prime(c), c)

    def test_generated_prime_has_exact_size(self):
        p = rsa.gen_prime(128)
        self.assertEqual(p.bit_length(), 128)
        self.assertTrue(rsa.is_probable_prime(p))

    def test_key_relations(self):
        k = self.key
        self.assertEqual(k.p * k.q, k.n)
        self.assertEqual(k.n.bit_length(), 512)
        self.assertEqual((k.e * k.d) % ((k.p - 1) * (k.q - 1)), 1)

    def test_toy_example_from_the_theory(self):
        t = rsa.toy_keys(61, 53, 17)
        self.assertEqual((t["n"], t["phi"], t["d"]), (3233, 3120, 2753))
        self.assertEqual(rsa.textbook_sign(3233, 2753, 65), 588)
        self.assertTrue(rsa.textbook_verify(3233, 17, 65, 588))
        self.assertFalse(rsa.textbook_verify(3233, 17, 66, 588))

    def test_toy_keys_validation(self):
        with self.assertRaises(ValueError):
            rsa.toy_keys(60, 53, 17)
        with self.assertRaises(ValueError):
            rsa.toy_keys(61, 61, 17)
        with self.assertRaises(ValueError):
            rsa.toy_keys(61, 53, 15)       # gcd(15, 3120) != 1

    def test_sign_verify_roundtrip(self):
        s = rsa.sign(self.key, b"hello")
        self.assertTrue(rsa.verify(self.key.n, self.key.e, b"hello", s))

    def test_modified_message_or_signature_fails(self):
        s = rsa.sign(self.key, b"hello")
        self.assertFalse(rsa.verify(self.key.n, self.key.e, b"hellO", s))
        bad = bytearray(s)
        bad[10] ^= 1
        self.assertFalse(rsa.verify(self.key.n, self.key.e, b"hello", bytes(bad)))
        self.assertFalse(rsa.verify(self.key.n, self.key.e, b"hello", s[:-1]))
        self.assertFalse(rsa.verify(self.key.n, self.key.e, b"hello", b"\xff" * len(s)))

    def test_other_key_does_not_verify(self):
        other = rsa.generate(512)
        s = rsa.sign(self.key, b"x")
        self.assertFalse(rsa.verify(other.n, other.e, b"x", s))

    def test_textbook_multiplicative_forgery_works(self):
        t = rsa.toy_keys(61, 53, 17)
        s5, s7 = rsa.textbook_sign(t["n"], t["d"], 5), rsa.textbook_sign(t["n"], t["d"], 7)
        m, s = rsa.forge_multiplicative(t["n"], 5, s5, 7, s7)
        self.assertEqual(m, 35)
        self.assertTrue(rsa.textbook_verify(t["n"], t["e"], 35, s))      # never signed, yet valid

    def test_padding_blocks_the_same_forgery(self):
        k = self.key
        s1, s2 = int.from_bytes(rsa.sign(k, b"a"), "big"), int.from_bytes(rsa.sign(k, b"b"), "big")
        forged = ((s1 * s2) % k.n).to_bytes(64, "big")
        self.assertFalse(rsa.verify(k.n, k.e, b"ab", forged))

    def test_factoring_tiny_modulus_recovers_the_key(self):
        self.assertEqual(rsa.factor_small(3233), (53, 61))
        with self.assertRaises(ValueError):
            rsa.factor_small(2 ** 60)

    def test_small_key_size_is_refused_for_real_keys(self):
        with self.assertRaises(ValueError):
            rsa.generate(256)

    @unittest.skipUnless(shutil.which("openssl") or os.environ.get("OPENSSL_BIN"), "openssl not installed")
    def test_openssl_verifies_our_signature_and_signs_ours(self):
        binary = os.environ.get("OPENSSL_BIN") or shutil.which("openssl")
        k = self.key
        with tempfile.TemporaryDirectory() as d:
            m, s, pem = (os.path.join(d, x) for x in ("m", "s", "pub.pem"))
            open(m, "wb").write(b"interop")
            open(s, "wb").write(rsa.sign(k, b"interop"))
            open(pem, "w").write(rsa.public_pem(k.n, k.e))
            r = subprocess.run([binary, "dgst", "-sha256", "-verify", pem, "-signature", s, m], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            open(m, "wb").write(b"interoP")
            r = subprocess.run([binary, "dgst", "-sha256", "-verify", pem, "-signature", s, m], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)


class TestTokens(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ring = tokens.Keyring(512)

    def tok(self, **kw):
        return tokens.issue(self.ring, "alice", "student", now=1000, **kw)[0]

    def err(self, token, **kw):
        with self.assertRaises(tokens.TokenError) as cm:
            tokens.verify(self.ring, token, **dict(dict(now=1100), **kw))
        return cm.exception.reason

    def test_valid_token(self):
        c = tokens.verify(self.ring, self.tok(), now=1100)
        self.assertEqual((c["sub"], c["role"], c["aud"], c["iss"]), ("alice", "student", "securehub-api", "securehub-auth"))
        self.assertEqual(c["exp"] - c["iat"], 900)

    def test_three_parts_and_header(self):
        h, p, s = tokens.decode_unverified(self.tok())
        self.assertEqual((h["alg"], h["kid"]), ("RS256", self.ring.active))

    def test_payload_is_readable_not_secret(self):
        _, p, _ = tokens.decode_unverified(self.tok())
        self.assertEqual(p["sub"], "alice")

    def test_edited_payload_is_refused(self):
        h, p, s = self.tok().split(".")
        pl = json.loads(tokens.unb64u(p))
        pl["role"] = "administrator"
        forged = ".".join([h, tokens.b64u(json.dumps(pl).encode()), s])
        self.assertEqual(self.err(forged), "bad_signature")

    def test_alg_none_is_refused(self):
        h, p, s = self.tok().split(".")
        hn = tokens.b64u(json.dumps({"alg": "none", "kid": self.ring.active}).encode())
        self.assertEqual(self.err(hn + "." + p + "."), "alg_not_allowed")

    def test_hs256_confusion_is_refused(self):
        h, p, s = self.tok().split(".")
        hh = tokens.b64u(json.dumps({"alg": "HS256", "kid": self.ring.active}).encode())
        self.assertEqual(self.err(hh + "." + p + "." + s), "alg_not_allowed")

    def test_expired(self):
        self.assertEqual(self.err(self.tok(ttl=10), now=2000), "expired")

    def test_expiry_boundary(self):
        t = self.tok(ttl=100)
        tokens.verify(self.ring, t, now=1099)
        self.assertEqual(self.err(t, now=1100), "expired")

    def test_wrong_audience(self):
        self.assertEqual(self.err(self.tok(aud="other-api")), "wrong_audience")

    def test_future_iat(self):
        t = tokens.issue(self.ring, "alice", "student", now=5000)[0]
        self.assertEqual(self.err(t, now=1000), "not_yet_valid")

    def test_unknown_kid(self):
        h, p, s = self.tok().split(".")
        hh = tokens.b64u(json.dumps({"alg": "RS256", "kid": "zz"}).encode())
        self.assertEqual(self.err(hh + "." + p + "." + s), "unknown_kid")

    def test_malformed_variants(self):
        for t in ("", "a.b", "a.b.c.d", "!!.!!.!!", None, "x" * 5000, "e30.e30.e30"):
            self.assertIn(self.err(t), ("malformed", "alg_not_allowed"), t)

    def test_missing_claim(self):
        h, p, s = self.tok().split(".")
        pl = json.loads(tokens.unb64u(p))
        del pl["jti"]
        t = tokens.issue.__globals__["b64u"](json.dumps(pl).encode())
        # re-sign properly so only the claim is missing
        signing = h + "." + t
        sig = rsa.sign(self.ring.keys[self.ring.active]["key"], signing.encode())
        self.assertEqual(self.err(signing + "." + tokens.b64u(sig)), "malformed")

    def test_revoked_jti(self):
        t, c = tokens.issue(self.ring, "alice", "student", now=1000)
        self.assertEqual(self.err(t, revoked={c["jti"]}), "revoked")

    def test_two_tokens_have_different_jti(self):
        a = tokens.issue(self.ring, "alice", "student", now=1000)[1]
        b = tokens.issue(self.ring, "alice", "student", now=1000)[1]
        self.assertNotEqual(a["jti"], b["jti"])

    def test_key_rotation_retires_old_tokens(self):
        ring = tokens.Keyring(512)
        old = tokens.issue(ring, "a", "student", now=1000)[0]
        ring.rotate()
        with self.assertRaises(tokens.TokenError) as cm:
            tokens.verify(ring, old, now=1100)
        self.assertEqual(cm.exception.reason, "retired_key")
        new = tokens.issue(ring, "a", "student", now=1000)[0]
        tokens.verify(ring, new, now=1100)

    def test_keyring_roundtrip(self):
        ring2 = tokens.Keyring(512, keys=self.ring.to_dict())
        tokens.verify(ring2, self.tok(), now=1100)


class TestPasswords(unittest.TestCase):
    def test_hash_format_and_verify(self):
        h = passwords.hash_password("secret", 1000)
        self.assertTrue(h.startswith("pbkdf2_sha256$1000$"))
        self.assertTrue(passwords.verify_password("secret", h))
        self.assertFalse(passwords.verify_password("Secret", h))

    def test_same_password_different_hash(self):
        self.assertNotEqual(passwords.hash_password("x", 1000), passwords.hash_password("x", 1000))

    def test_md5_is_identical_for_identical_passwords(self):
        self.assertEqual(passwords.md5_unsalted("x"), passwords.md5_unsalted("x"))

    def test_garbage_stored_value(self):
        for bad in ("", "a$b", "md5$1$00$00", "pbkdf2_sha256$x$zz$zz"):
            self.assertFalse(passwords.verify_password("x", bad))

    def test_store_never_keeps_plaintext(self):
        st = Store(1000)
        for u in st.users.values():
            self.assertNotIn("pass", u["hash"].split("$")[3])
            self.assertTrue(u["hash"].startswith("pbkdf2_sha256$"))


class TestRBAC(unittest.TestCase):
    def setUp(self):
        self.st = Store(1000)
        self.alice, self.bob = self.st.public_user("alice"), self.st.public_user("bob")
        self.carol, self.root = self.st.public_user("carol"), self.st.public_user("root")

    def d(self, role, user, perm, doc=None, **kw):
        return rbac.decide(role, user, perm, doc=self.st.docs.get(doc) if doc else None, **kw)

    def test_function_level_matrix(self):
        cases = {"student": {"doc:list", "doc:read"}, "teacher": {"doc:list", "doc:read", "doc:create"}}
        for role, allowed in cases.items():
            for perm in ("doc:list", "doc:read", "doc:create", "doc:delete", "audit:read", "lab:attack"):
                self.assertEqual(rbac.has_permission(role, perm), perm in allowed, (role, perm))
        self.assertTrue(rbac.has_permission("administrator", "audit:read"))
        self.assertFalse(rbac.has_permission("administrator", "doc:create"))
        self.assertFalse(rbac.has_permission("ghost", "doc:list"))

    def test_student_reads_enrolled_lecture(self):
        self.assertTrue(self.d("student", self.alice, "doc:read", 1).allowed)

    def test_student_not_enrolled(self):
        r = self.d("student", self.bob, "doc:read", 6)
        self.assertEqual((r.allowed, r.reason), (False, "not_enrolled"))

    def test_student_own_grades_only(self):
        self.assertTrue(self.d("student", self.alice, "doc:read", 4).allowed)
        self.assertEqual(self.d("student", self.alice, "doc:read", 5).reason, "not_owner")

    def test_student_never_reads_exams_or_admin_docs(self):
        self.assertEqual(self.d("student", self.alice, "doc:read", 3).reason, "kind_not_allowed")
        self.assertEqual(self.d("student", self.alice, "doc:read", 9).reason, "kind_not_allowed")

    def test_teacher_own_course_only(self):
        self.assertTrue(self.d("teacher", self.carol, "doc:read", 3).allowed)
        self.assertTrue(self.d("teacher", self.carol, "doc:read", 4).allowed)
        self.assertEqual(self.d("teacher", self.carol, "doc:read", 7).reason, "not_your_course")

    def test_teacher_create_only_in_own_course(self):
        self.assertTrue(self.d("teacher", self.carol, "doc:create", course="SSAD").allowed)
        self.assertEqual(self.d("teacher", self.carol, "doc:create", course="NET").reason, "not_your_course")

    def test_separation_of_duties_for_admin(self):
        self.assertTrue(self.d("administrator", self.root, "doc:read", 9).allowed)
        self.assertEqual(self.d("administrator", self.root, "doc:read", 3).reason, "separation_of_duties")
        self.assertEqual(self.d("administrator", self.root, "doc:read", 4).reason, "separation_of_duties")

    def test_default_deny_for_unknown_role_and_action(self):
        self.assertFalse(self.d("ghost", self.alice, "doc:read", 1).allowed)
        self.assertFalse(self.d("student", self.alice, "doc:fly").allowed)

    def test_list_filtering(self):
        docs = list(self.st.docs.values())
        ids = {d["id"] for d in rbac.visible_documents("student", self.alice, docs)}
        self.assertEqual(ids, {1, 2, 4, 6, 8, 11, 12})
        ids = {d["id"] for d in rbac.visible_documents("student", self.bob, docs)}
        self.assertEqual(ids, {1, 2, 5, 11})
        self.assertEqual(len(rbac.visible_documents("administrator", self.root, docs)), 12)


class TestAudit(unittest.TestCase):
    def make(self, n=6, **kw):
        log = audit.AuditLog(clock=Clock(), **kw)
        for i in range(n):
            log.record(user="u%d" % i, status=200, path="/x")
        return log

    def test_empty_and_full_chain_verify(self):
        self.assertTrue(audit.AuditLog().verify()["ok"])
        self.assertTrue(self.make().verify()["ok"])

    def test_first_entry_links_to_genesis(self):
        self.assertEqual(self.make(1).entries[0]["prev"], audit.GENESIS)

    def test_edited_entry_is_found(self):
        log = self.make()
        log.tamper(3, "user", "nobody")
        v = log.verify()
        self.assertEqual((v["ok"], v["first_bad"]), (False, 3))

    def test_deleted_middle_entry_is_found(self):
        log = self.make()
        del log.entries[2]
        for i, e in enumerate(log.entries):
            e["id"] = i + 1
        self.assertFalse(log.verify()["ok"])

    def test_inserted_entry_is_found(self):
        log = self.make()
        fake = dict(log.entries[2], user="mallory")
        log.entries.insert(3, fake)
        self.assertFalse(log.verify()["ok"])

    def test_recomputing_one_hash_breaks_the_next(self):
        log = self.make()
        e = log.entries[1]
        e["user"] = "x"
        e["hash"] = audit._hash(e["prev"], e)
        self.assertEqual(log.verify()["first_bad"], 3)

    def test_deleting_the_last_entry_is_NOT_detected_without_the_head(self):
        log = self.make()
        head = log.head()
        log.entries.pop()
        self.assertTrue(log.verify()["ok"])                 # documented limit
        self.assertNotEqual(log.head(), head)               # the written-down head reveals it

    def test_persistence_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            self.make(4, path=p)
            again = audit.AuditLog(p, Clock())
            self.assertEqual(len(again.entries), 4)
            self.assertTrue(again.verify()["ok"])
            again.record(user="z")
            self.assertTrue(audit.AuditLog(p).verify()["ok"])

    def test_subscribers_receive_entries(self):
        log = audit.AuditLog(clock=Clock())
        q = log.subscribe()
        log.record(user="a")
        self.assertEqual(q.get_nowait()["user"], "a")
        log.unsubscribe(q)
        log.record(user="b")
        self.assertTrue(q.empty())


def req(ts, **kw):
    e = {"id": req.n, "ts": ts, "type": "request", "ip": "1.1.1.1", "user": "alice", "status": 200, "path": "/api/documents"}
    req.n += 1
    e.update(kw)
    return e


req.n = 1


class TestDocService(unittest.TestCase):
    """The document service must refuse calls that do not carry the gateway's proof (second line of defence)."""

    def setUp(self):
        from securehub.docsvc import DocumentService, ProofError
        self.ProofError = ProofError
        self.clock = Clock()
        self.svc = DocumentService(Store(), b"k" * 32, self.clock)

    def test_call_without_proof_is_refused(self):
        with self.assertRaises(self.ProofError):
            self.svc.call("list", "alice", "student")

    def test_call_with_wrong_proof_or_stale_timestamp_is_refused(self):
        ts = int(self.clock())
        with self.assertRaises(self.ProofError):
            self.svc.call("read", "alice", "student", 1, proof="00" * 32, ts=ts)
        good = self.svc.make_proof("alice", "student", "read", 1, ts - 120)
        with self.assertRaises(self.ProofError):
            self.svc.call("read", "alice", "student", 1, proof=good, ts=ts - 120)

    def test_call_with_valid_proof_is_served(self):
        ts = int(self.clock())
        proof = self.svc.make_proof("alice", "student", "list", None, ts)
        status, body, _ = self.svc.call("list", "alice", "student", proof=proof, ts=ts)
        self.assertEqual(status, 200)


class TestDetect(unittest.TestCase):
    def feed(self, d, es):
        out = []
        for e in es:
            out += d.feed(e)
        return [a["rule"] for a in out]

    def login_fail(self, t, n=1, **kw):
        return [req(t + i, path="/auth/login", status=401, user="alice", **kw) for i in range(n)]

    def test_brute_force_boundary(self):
        self.assertEqual(self.feed(detect.Detector(), self.login_fail(0, 4)), [])
        self.assertIn("brute_force", self.feed(detect.Detector(), self.login_fail(0, 5)))

    def test_brute_force_window_expires(self):
        es = self.login_fail(0, 4) + self.login_fail(100, 1)
        self.assertEqual(self.feed(detect.Detector(), es), [])

    def test_token_tampering_single_event(self):
        for r in ("bad_signature", "alg_not_allowed", "malformed", "unknown_kid", "no_gateway_proof"):
            self.assertIn("token_tampering", self.feed(detect.Detector(), [req(0, status=401, reason=r)]), r)
        self.assertEqual(self.feed(detect.Detector(), [req(0, status=401, reason="expired")]), [])

    def test_privilege_escalation_boundary(self):
        es = [req(i, status=403, reason="role_lacks_permission") for i in range(2)]
        self.assertEqual(self.feed(detect.Detector(), es), [])
        es.append(req(3, status=403, reason="role_lacks_permission"))
        self.assertIn("privilege_escalation", self.feed(detect.Detector(), es))

    def test_object_level_refusals_do_not_count_as_privilege_escalation(self):
        es = [req(i, status=403, reason="not_owner", path="/api/documents/%d" % i, object=str(i)) for i in range(5)]
        self.assertNotIn("privilege_escalation", self.feed(detect.Detector(), es))

    def test_enumeration_counts_distinct_ids(self):
        mk = lambda ids: [req(i, status=403, reason="not_owner", path="/api/documents/%d" % x, object=str(x)) for i, x in enumerate(ids)]
        self.assertNotIn("object_enumeration", self.feed(detect.Detector(), mk(range(1, 8))))
        self.assertIn("object_enumeration", self.feed(detect.Detector(), mk(range(1, 9))))
        self.assertNotIn("object_enumeration", self.feed(detect.Detector(), mk([5] * 20)))     # same id again and again

    def test_burst_boundary(self):
        self.assertNotIn("request_burst", self.feed(detect.Detector(), [req(i * 0.1) for i in range(29)]))
        self.assertIn("request_burst", self.feed(detect.Detector(), [req(i * 0.1) for i in range(30)]))
        self.assertNotIn("request_burst", self.feed(detect.Detector(), [req(i * 1.0) for i in range(30)]))   # same count over 30 s

    def test_expired_reuse(self):
        es = [req(i, status=401, reason="expired") for i in range(3)]
        self.assertIn("expired_reuse", self.feed(detect.Detector(), es))

    def test_mass_access_counts_rows(self):
        mk = lambda n, rows: [req(i, object="lake", path="/lake/query", rows=rows) for i in range(n)]
        self.assertNotIn("mass_access", self.feed(detect.Detector(), mk(4, 100)))
        self.assertIn("mass_access", self.feed(detect.Detector(), mk(5, 100)))

    def test_repeated_denied_lake(self):
        es = [req(i, object="lake", path="/lake/query", status=403, reason="column_denied") for i in range(3)]
        self.assertIn("repeated_denied", self.feed(detect.Detector(), es))

    def test_cooldown_prevents_alert_flood(self):
        d = detect.Detector()
        out = self.feed(d, [req(i, status=401, reason="bad_signature") for i in range(10)])
        self.assertEqual(out.count("token_tampering"), 1)
        out = self.feed(d, [req(100, status=401, reason="bad_signature")])
        self.assertEqual(out, ["token_tampering"])

    def test_alert_entries_are_ignored(self):
        self.assertEqual(detect.Detector().feed({"id": 1, "ts": 0, "type": "alert", "status": 0}), [])

    def test_threshold_can_be_configured(self):
        d = detect.Detector({"brute_force": {"count": 2}})
        self.assertIn("brute_force", self.feed(d, self.login_fail(0, 2)))

    def test_normal_traffic_raises_nothing(self):
        es = []
        for i in range(20):
            es.append(req(i * 5, user="u%d" % (i % 4), ip="9.9.9.%d" % (i % 4)))
        es += [req(30, status=403, reason="not_owner", path="/api/documents/3", object="3")]
        self.assertEqual(self.feed(detect.Detector(), es), [])


if __name__ == "__main__":
    unittest.main()
