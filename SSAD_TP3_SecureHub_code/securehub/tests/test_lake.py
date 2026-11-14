import os
import tempfile
import unittest

from lake import data, engines, policy, spark_detect as sd
from lake.catalog import COLUMNS

DOC = {"username": "dr_amine", "role": "doctor", "service": "cardiology", "purposes": ["care"]}
DOC2 = {"username": "dr_sofia", "role": "doctor", "service": "oncology", "purposes": ["care"]}
AN = {"username": "lina", "role": "analyst", "service": None, "purposes": ["research", "statistics"]}
ADM = {"username": "root", "role": "administrator", "service": None, "purposes": ["maintenance"]}
SPARK = engines.spark_available()


def plan(subject, purpose, zone, q):
    return policy.plan_query(subject, purpose, zone, q)


class TestDecisions(unittest.TestCase):
    def out(self, subject, purpose, zone, col):
        return policy.column_decision(subject, purpose, zone, COLUMNS[col])["outcome"]

    def test_doctor_internal_sees_clear_except_billing(self):
        for c in ("full_name", "national_id", "birth_date", "diagnosis_label", "notes", "service"):
            self.assertEqual(self.out(DOC, "care", "internal", c), "clear", c)
        self.assertEqual(self.out(DOC, "care", "internal", "treatment_cost"), "deny")

    def test_deny_overrides_permit(self):
        d = policy.column_decision(DOC, "care", "internal", COLUMNS["treatment_cost"])
        self.assertEqual((d["outcome"], d["denies"], d["conflict"]), ("deny", ["D2"], True))
        self.assertIn("P1", d["permits"])

    def test_doctor_external_gets_less(self):
        self.assertEqual(self.out(DOC, "care", "external", "city"), "clear")
        self.assertEqual(self.out(DOC, "care", "external", "full_name"), "mask")
        self.assertEqual(self.out(DOC, "care", "external", "national_id"), "deny")        # default deny
        self.assertEqual(self.out(DOC, "care", "external", "notes"), "deny")

    def test_restricted_columns_need_purpose_care(self):
        for p in ("research", "statistics", "maintenance"):
            self.assertEqual(self.out(DOC, p, "internal", "national_id"), "deny")

    def test_analyst_view(self):
        self.assertEqual(self.out(AN, "research", "internal", "patient_id"), "hash")
        self.assertEqual(self.out(AN, "research", "internal", "full_name"), "hash")
        self.assertEqual(self.out(AN, "research", "internal", "birth_date"), "mask")
        self.assertEqual(self.out(AN, "research", "internal", "diagnosis_code"), "clear")
        self.assertEqual(self.out(AN, "research", "internal", "treatment_cost"), "clear")
        self.assertEqual(self.out(AN, "research", "internal", "national_id"), "deny")
        self.assertEqual(self.out(AN, "research", "internal", "notes"), "deny")

    def test_admin_sees_only_public_columns_in_clear(self):
        self.assertEqual(self.out(ADM, "maintenance", "internal", "service"), "clear")
        self.assertEqual(self.out(ADM, "maintenance", "internal", "record_id"), "clear")
        for c in ("full_name", "city", "treatment_cost", "diagnosis_code"):
            self.assertEqual(self.out(ADM, "maintenance", "internal", c), "mask", c)
        self.assertEqual(self.out(ADM, "maintenance", "internal", "national_id"), "deny")

    def test_unknown_role_gets_nothing(self):
        ghost = {"username": "g", "role": "student", "service": None, "purposes": ["care"]}
        for c in COLUMNS:
            self.assertEqual(self.out(ghost, "care", "internal", c), "deny", c)

    def test_most_protective_permit_wins(self):
        rules = [{"id": "A", "effect": "permit", "role": None, "columns": {}, "obligation": "clear"},
                 {"id": "B", "effect": "permit", "role": None, "columns": {}, "obligation": "hash"}]
        d = policy.column_decision(DOC, "care", "internal", COLUMNS["city"], rules)
        self.assertEqual((d["outcome"], d["deciding"], d["conflict"]), ("hash", "B", True))

    def test_zone_of(self):
        self.assertEqual(policy.zone_of("127.0.0.1"), "internal")
        self.assertEqual(policy.zone_of("10.1.2.3"), "internal")
        self.assertEqual(policy.zone_of("10.66.0.1"), "external")
        self.assertEqual(policy.zone_of("203.0.113.9"), "external")


class TestPlans(unittest.TestCase):
    def test_wrong_purpose_refused(self):
        p = plan(DOC, "research", "internal", {"columns": ["city"]})
        self.assertEqual((p["allowed"], p["reason"]), (False, "purpose_not_allowed"))

    def test_analyst_raw_rows_refused(self):
        self.assertEqual(plan(AN, "research", "internal", {"columns": "*"})["reason"], "aggregate_only")

    def test_named_denied_column_refuses_whole_query(self):
        p = plan(DOC, "care", "internal", {"columns": ["record_id", "treatment_cost"]})
        self.assertEqual((p["reason"], p["columns_denied"]), ("column_denied", ["treatment_cost"]))

    def test_star_silently_drops_denied_columns(self):
        p = plan(DOC, "care", "internal", {"columns": "*"})
        self.assertTrue(p["allowed"])
        self.assertNotIn("treatment_cost", p["used"])
        self.assertEqual(len(p["used"]), 12)

    def test_row_filter_for_doctor_only(self):
        self.assertEqual(plan(DOC, "care", "internal", {"columns": ["record_id"]})["row_filter"],
                         {"col": "service", "op": "=", "value": "cardiology"})
        self.assertIsNone(plan(AN, "research", "internal", {"group_by": ["service"], "metrics": [{"fn": "count"}]})["row_filter"])

    def test_filter_on_hashed_or_masked_column_refused(self):
        for col, val in (("patient_id", "P0000001"), ("birth_date", "1980-01-01")):
            p = plan(AN, "research", "internal", {"group_by": ["city"], "metrics": [{"fn": "count"}], "where": [{"col": col, "op": "=", "value": val}]})
            self.assertEqual(p["reason"], "filter_on_protected_column", col)

    def test_filter_on_denied_column_refused(self):
        p = plan(AN, "research", "internal", {"group_by": ["city"], "metrics": [{"fn": "count"}], "where": [{"col": "national_id", "op": "=", "value": "1"}]})
        self.assertEqual(p["reason"], "filter_on_protected_column")

    def test_metric_rules(self):
        self.assertEqual(plan(AN, "research", "internal", {"metrics": [{"fn": "avg", "col": "full_name"}]})["reason"], "metric_needs_clear_numeric_column")
        self.assertEqual(plan(ADM, "maintenance", "internal", {"metrics": [{"fn": "sum", "col": "treatment_cost"}]})["reason"], "metric_needs_clear_numeric_column")
        self.assertTrue(plan(AN, "research", "internal", {"metrics": [{"fn": "count_distinct", "col": "patient_id"}]})["allowed"])

    def test_k_anonymity_clause_in_sql(self):
        p = plan(AN, "research", "internal", {"group_by": ["city"], "metrics": [{"fn": "count"}]})
        self.assertIn("HAVING COUNT(*) >= 5", p["sql"])
        self.assertNotIn("HAVING", plan(ADM, "maintenance", "internal", {"group_by": ["service"], "metrics": [{"fn": "count"}]})["sql"])

    def test_row_cap_is_enforced(self):
        p = plan(DOC, "care", "internal", {"columns": ["record_id"], "limit": 99999})
        self.assertEqual(p["limit"], 100)
        self.assertTrue(p["sql"].endswith("LIMIT 100"))

    def test_rewritten_sql_masks_and_hashes(self):
        p = plan(AN, "research", "internal", {"group_by": ["patient_id", "birth_date"], "metrics": [{"fn": "count"}]})
        self.assertIn("sha2(concat('lake-pepper-demo'", p["sql"])
        self.assertIn("substring(CAST(birth_date AS STRING), 1, 4) AS birth_date", p["sql"])

    def test_user_filter_goes_inside_the_secure_view(self):
        p = plan(DOC, "care", "internal", {"columns": ["record_id"], "where": [{"col": "city", "op": "=", "value": "Alger"}]})
        inner = p["sql"].split("FROM (", 1)[1]
        self.assertIn("WHERE service = 'cardiology' AND city = 'Alger'", inner)

    def test_order_by_must_use_output_names(self):
        self.assertEqual(plan(AN, "research", "internal", {"group_by": ["city"], "metrics": [{"fn": "count"}], "order_by": [{"col": "diagnosis_code"}]})["reason"], "order_by_not_in_output")

    def test_zone_changes_the_plan(self):
        a = plan(DOC, "care", "internal", {"columns": ["full_name"]})
        b = plan(DOC, "care", "external", {"columns": ["full_name"]})
        self.assertEqual((a["columns"]["full_name"], b["columns"]["full_name"]), ("clear", "mask"))

    def test_explain_lists_every_used_column(self):
        p = plan(DOC, "care", "internal", {"columns": ["record_id", "city"], "where": [{"col": "service", "op": "=", "value": "cardiology"}]})
        self.assertEqual({x["column"] for x in p["explain"]}, {"record_id", "city", "service"})


class TestValidation(unittest.TestCase):
    def bad(self, q, reason):
        with self.assertRaises(policy.PolicyError) as cm:
            plan(AN, "research", "internal", q)
        self.assertEqual(cm.exception.reason, reason, q)

    def test_sql_injection_values_are_rejected(self):
        for v in ("x' OR '1'='1", "a'; DROP TABLE lake; --", "a\\'", "a) OR (1=1", "x\nUNION SELECT", "é\u0000"):
            self.bad({"group_by": ["city"], "metrics": [{"fn": "count"}], "where": [{"col": "city", "op": "=", "value": v}]}, "bad_value")

    def test_injection_in_in_list(self):
        self.bad({"group_by": ["city"], "metrics": [{"fn": "count"}], "where": [{"col": "city", "op": "in", "value": ["ok", "x' OR 1=1 --"]}]}, "bad_value")

    def test_unknown_column_operator_function_key(self):
        self.bad({"group_by": ["nope"], "metrics": [{"fn": "count"}]}, "unknown_column")
        self.bad({"group_by": ["city"], "metrics": [{"fn": "count"}], "where": [{"col": "city", "op": "like", "value": "A"}]}, "bad_query")
        self.bad({"group_by": ["city"], "metrics": [{"fn": "median", "col": "treatment_cost"}]}, "bad_query")
        self.bad({"group_by": ["city"], "sql": "select 1"}, "bad_query")
        self.bad("select * from lake", "bad_query")

    def test_type_checks(self):
        self.bad({"group_by": ["city"], "metrics": [{"fn": "count"}], "where": [{"col": "treatment_cost", "op": ">", "value": "10"}]}, "bad_value")
        self.bad({"group_by": ["city"], "metrics": [{"fn": "count"}], "where": [{"col": "city", "op": "=", "value": 5}]}, "bad_value")
        self.bad({"group_by": ["city"], "metrics": [{"fn": "count"}], "where": [{"col": "treatment_cost", "op": "=", "value": True}]}, "bad_value")

    def test_limit_and_alias_checks(self):
        self.bad({"group_by": ["city"], "metrics": [{"fn": "count"}], "limit": 0}, "bad_query")
        self.bad({"group_by": ["city"], "metrics": [{"fn": "count", "as": "x; drop"}]}, "bad_query")

    def test_safe_values_accepted(self):
        q = policy.normalise_query({"group_by": ["city"], "metrics": [{"fn": "count"}], "where": [{"col": "city", "op": "=", "value": "Sétif"}]})
        self.assertEqual(q["where"][0]["value"], "Sétif")

    def test_original_sql_for_explanations(self):
        self.assertEqual(policy.original_sql({"columns": ["city"], "where": [{"col": "city", "op": "=", "value": "Oran"}]}),
                         "SELECT city FROM lake WHERE city = 'Oran'")


ROWS = list(data.generate_rows(4000, seed=11))
QUERIES = [
    (DOC, "care", "internal", {"columns": ["record_id", "full_name", "national_id", "birth_date", "diagnosis_code", "notes"], "where": [{"col": "diagnosis_code", "op": "=", "value": "I10"}], "order_by": [{"col": "record_id"}], "limit": 25}),
    (DOC2, "care", "internal", {"columns": "*", "order_by": [{"col": "record_id", "dir": "desc"}], "limit": 10}),
    (DOC, "care", "external", {"columns": ["record_id", "full_name", "birth_date", "city"], "order_by": [{"col": "record_id"}], "limit": 20}),
    (AN, "research", "external", {"group_by": ["service", "diagnosis_code"], "metrics": [{"fn": "count"}, {"fn": "avg", "col": "treatment_cost"}, {"fn": "count_distinct", "col": "patient_id"}, {"fn": "max", "col": "treatment_cost"}, {"fn": "min", "col": "treatment_cost"}, {"fn": "sum", "col": "treatment_cost"}], "order_by": [{"col": "service"}, {"col": "diagnosis_code"}]}),
    (AN, "research", "internal", {"group_by": ["birth_date"], "metrics": [{"fn": "count"}], "order_by": [{"col": "birth_date"}]}),
    (AN, "research", "internal", {"group_by": ["patient_id"], "metrics": [{"fn": "sum", "col": "treatment_cost"}], "order_by": [{"col": "sum_treatment_cost", "dir": "desc"}, {"col": "patient_id"}], "limit": 7}),
    (AN, "statistics", "internal", {"metrics": [{"fn": "count"}, {"fn": "count_distinct", "col": "full_name"}]}),
    (AN, "research", "internal", {"group_by": ["city"], "metrics": [{"fn": "count"}], "where": [{"col": "treatment_cost", "op": ">=", "value": 300000}, {"col": "service", "op": "in", "value": ["cardiology", "oncology"]}], "order_by": [{"col": "city"}]}),
    (ADM, "maintenance", "internal", {"group_by": ["service", "city"], "metrics": [{"fn": "count"}], "order_by": [{"col": "service"}, {"col": "city"}]}),
    (ADM, "maintenance", "internal", {"group_by": ["admission_date"], "metrics": [{"fn": "count"}], "order_by": [{"col": "admission_date"}], "limit": 5}),
]


class TestPyEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.py = engines.PyEngine(ROWS)

    def run_q(self, i):
        s, p, z, q = QUERIES[i]
        return self.py.run(plan(s, p, z, q))

    def test_doctor_sees_only_own_department(self):
        r = self.run_q(0)
        self.assertGreater(r["row_count"], 0)
        ids = {row[0] for row in r["rows"]}
        by_id = {x["record_id"]: x for x in ROWS}
        self.assertTrue(all(by_id[i]["service"] == "cardiology" and by_id[i]["diagnosis_code"] == "I10" for i in ids))

    def test_doctor_external_masks_names_and_birth_dates(self):
        r = self.run_q(2)
        by_id = {x["record_id"]: x for x in ROWS}
        for rid, name, birth, city in r["rows"]:
            self.assertRegex(name, r"^([A-Z]\.)( [A-Z]\.)*$")
            self.assertEqual(birth, by_id[rid]["birth_date"][:4])

    def test_national_id_never_leaves_for_analyst_or_admin(self):
        for i in (3, 4, 5, 6, 7, 8, 9):
            blob = str(self.run_q(i)["rows"])
            for x in ROWS[:200]:
                self.assertNotIn(x["national_id"], blob)

    def test_analyst_pseudonyms_are_stable_and_not_the_original(self):
        r = self.run_q(5)
        ids = [row[0] for row in r["rows"]]
        self.assertTrue(all(len(i) == 12 and not i.startswith("P0") for i in ids))
        self.assertEqual(r["rows"], self.run_q(5)["rows"])

    def test_small_groups_are_suppressed(self):
        s, p, z, q = QUERIES[4]
        r = self.py.run(plan(s, p, z, q))
        self.assertTrue(all(row[1] >= 5 for row in r["rows"]))
        raw = {}
        for x in ROWS:
            raw[x["birth_date"][:4]] = raw.get(x["birth_date"][:4], 0) + 1
        self.assertLess(r["row_count"], len(raw) + 1)

    def test_limit_applied(self):
        self.assertEqual(self.run_q(5)["row_count"], 7)
        self.assertLessEqual(self.run_q(1)["row_count"], 10)

    def test_aggregate_values_match_plain_python(self):
        r = self.run_q(3)
        row = dict(zip(r["columns"], r["rows"][0]))
        sub = [x for x in ROWS if x["service"] == row["service"] and x["diagnosis_code"] == row["diagnosis_code"]]
        self.assertEqual(row["n"], len(sub))
        self.assertEqual(row["sum_treatment_cost"], sum(x["treatment_cost"] for x in sub))
        self.assertAlmostEqual(row["avg_treatment_cost"], sum(x["treatment_cost"] for x in sub) / len(sub), places=2)

    def test_bucket_masking_hides_exact_cost(self):
        p = plan(ADM, "maintenance", "internal", {"group_by": ["treatment_cost"], "metrics": [{"fn": "count"}], "limit": 5})
        r = self.py.run(p)
        self.assertTrue(all("-" in str(row[0]) for row in r["rows"]))

    def test_global_count_below_k_returns_nothing(self):
        few = engines.PyEngine(ROWS[:3])
        s, p, z, q = QUERIES[6]
        self.assertEqual(few.run(plan(s, p, z, q))["rows"], [])


@unittest.skipUnless(SPARK, "PySpark / Java not installed")
class TestSparkMatchesPython(unittest.TestCase):
    """The same plan must give identical results on both engines."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        path = os.path.join(cls.tmp, "lake.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            import csv
            w = csv.DictWriter(f, fieldnames=data.HEADER)
            w.writeheader()
            w.writerows(ROWS)
        cls.spark = engines.SparkEngine(path)
        cls.py = engines.PyEngine(ROWS)

    def test_every_query_identical(self):
        for i, (s, p, z, q) in enumerate(QUERIES):
            pl = plan(s, p, z, q)
            a, b = self.py.run(pl), self.spark.run(pl)
            self.assertEqual(a["columns"], b["columns"], i)
            self.assertEqual(len(a["rows"]), len(b["rows"]), i)
            for ra, rb in zip(a["rows"], b["rows"]):
                for va, vb in zip(ra, rb):
                    if isinstance(va, float) or isinstance(vb, float):
                        self.assertAlmostEqual(float(va), float(vb), places=2, msg=str(i))
                    else:
                        self.assertEqual(va, vb, i)

    def test_spark_parquet_roundtrip(self):
        out = os.path.join(self.tmp, "lake.parquet")
        self.spark.df.write.mode("overwrite").parquet(out)
        pq = engines.SparkEngine(out, "parquet", view="lake_pq")
        s, p, z, q = QUERIES[3]
        pl = plan(s, p, z, q)
        self.assertEqual(len(pq.run(pl)["rows"]), len(self.py.run(pl)["rows"]))

    def test_spark_rewrite_does_not_leak_original_columns(self):
        pl = plan(AN, "research", "internal", {"group_by": ["patient_id"], "metrics": [{"fn": "count"}], "limit": 50})
        res = self.spark.run(pl)
        originals = {x["patient_id"] for x in ROWS}
        self.assertFalse(originals & {r[0] for r in res["rows"]})


def synthetic_with_attackers():
    es = sd.synthetic_entries(5000, seed=3)
    es += [{"id": 90000 + i, "ts": 1_800_000_100.0 + i, "user": "mallory", "object": "lake", "status": 403, "rows": 0, "type": "request"} for i in range(4)]
    es += [{"id": 91000 + i, "ts": 1_800_000_200.0 + i * 5, "user": "eve", "object": "lake", "status": 200, "rows": 300, "type": "request"} for i in range(4)]
    es += [{"id": 92000 + i, "ts": 1_800_000_300.0 + i * 70, "user": "slow", "object": "lake", "status": 200, "rows": 300, "type": "request"} for i in range(6)]
    return es


class TestWindowDetection(unittest.TestCase):
    def test_python_finds_planted_attackers_only(self):
        found = sd.detect_python(synthetic_with_attackers())
        self.assertIn(("repeated_denied", "mallory"), found)
        self.assertIn(("mass_access", "eve"), found)
        self.assertNotIn("slow", {u for _, u in found})               # same rows spread over 6 minutes: no alert

    def test_normal_users_do_not_alert(self):
        self.assertEqual(sd.detect_python(sd.synthetic_entries(5000, seed=3)), [])

    def test_boundary_exactly_at_threshold(self):
        mk = lambda n: [{"ts": 1_800_000_000.0 + i, "user": "u", "object": "lake", "status": 200, "rows": 100} for i in range(n)]
        self.assertEqual(sd.detect_python(mk(4)), [])
        self.assertEqual(sd.detect_python(mk(5)), [("mass_access", "u")])

    @unittest.skipUnless(SPARK, "PySpark / Java not installed")
    def test_spark_equals_python(self):
        es = synthetic_with_attackers()
        self.assertEqual(sd.detect_spark(es), sd.detect_python(es))

    @unittest.skipUnless(SPARK, "PySpark / Java not installed")
    def test_spark_reads_jsonl_file(self):
        es = synthetic_with_attackers()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            sd.write_jsonl(p, es)
            self.assertEqual(sd.detect_spark(p), sd.detect_python_file(p))


class TestGenerator(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(list(data.generate_rows(50, 5)), list(data.generate_rows(50, 5)))
        self.assertNotEqual(list(data.generate_rows(50, 5)), list(data.generate_rows(50, 6)))

    def test_csv_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = data.write_csv(os.path.join(d, "x.csv"), 100, 9)
            self.assertEqual(data.read_csv(p), list(data.generate_rows(100, 9)))

    def test_diagnoses_fit_the_service(self):
        for r in data.generate_rows(500, 1):
            self.assertIn((r["diagnosis_code"], r["diagnosis_label"]), data.SERVICES[r["service"]])

    def test_rows_for_bytes_is_close(self):
        n = data.rows_for_bytes(200_000)
        with tempfile.TemporaryDirectory() as d:
            size = os.path.getsize(data.write_csv(os.path.join(d, "x.csv"), n))
        self.assertLess(abs(size - 200_000) / 200_000, 0.1)


if __name__ == "__main__":
    unittest.main()
