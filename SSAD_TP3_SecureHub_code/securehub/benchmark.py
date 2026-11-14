"""Measurements for the report. Every number in the report comes from results/benchmark.json.

    python benchmark.py --only rsa,pbkdf2,gateway,policy,window,fp,attacks
    python benchmark.py --only lake --sizes 1,10,100,1000      (sizes in MB of CSV; needs PySpark + Java)

Honest limits: one machine, local[2] Spark (no cluster), synthetic data, a handful of repeats.
"""
import argparse
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results", "benchmark.json")
BENCH = os.path.join(HERE, "data", "bench")


def load():
    return json.load(open(RES)) if os.path.exists(RES) else {}


def save(R):
    os.makedirs(os.path.dirname(RES), exist_ok=True)
    with open(RES, "w") as f:
        json.dump(R, f, indent=1)


def timeit(fn, n):
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        ts.append(time.perf_counter() - t)
    return statistics.median(ts)


def meta():
    m = {"python": platform.python_version(), "platform": platform.platform(), "cpus": os.cpu_count(),
         "date": time.strftime("%Y-%m-%d")}
    try:
        import pyspark
        m["pyspark"] = pyspark.__version__
        m["java"] = subprocess.run(["java", "-version"], capture_output=True, text=True).stderr.split("\"")[1] if shutil.which("java") else None
    except Exception:
        pass
    return m


# ------------------------------------------------------------------------------------------ RSA / tokens
def bench_rsa():
    from securehub import rsa, tokens
    out = {"keygen": [], "sign_verify": []}
    for bits, runs in ((512, 8), (1024, 8), (2048, 3)):
        ts = []
        for _ in range(runs):
            t = time.perf_counter()
            k = rsa.generate(bits)
            ts.append(time.perf_counter() - t)
        sig = rsa.sign(k, b"m")
        sign_ms = timeit(lambda: rsa.sign(k, b"m"), 50) * 1000
        ver_ms = timeit(lambda: rsa.verify(k.n, k.e, b"m", sig), 200) * 1000
        out["keygen"].append({"bits": bits, "median_s": statistics.median(ts), "runs": runs})
        out["sign_verify"].append({"bits": bits, "sign_ms": sign_ms, "verify_ms": ver_ms})
    ob = shutil.which("openssl")
    if ob:
        ssl = []
        for bits in (512, 1024, 2048):
            ts = []
            for _ in range(3):
                t = time.perf_counter()
                subprocess.run([ob, "genrsa", str(bits)], capture_output=True)
                ts.append(time.perf_counter() - t)
            ssl.append({"bits": bits, "median_s": statistics.median(ts)})
        out["openssl_genrsa"] = ssl
        out["openssl_version"] = subprocess.run([ob, "version"], capture_output=True, text=True).stdout.strip()
    ring = tokens.Keyring(1024)
    tok, _ = tokens.issue(ring, "alice", "student")
    out["token"] = {"issue_ms": timeit(lambda: tokens.issue(ring, "alice", "student"), 50) * 1000,
                    "verify_ms": timeit(lambda: tokens.verify(ring, tok), 200) * 1000, "bits": 1024}
    return out


def bench_pbkdf2():
    from securehub import passwords
    return [{"iterations": it, "ms": timeit(lambda: passwords.hash_password("correct horse", it), 3 if it > 200000 else 8) * 1000}
            for it in (1000, 10000, 100000, 600000, 1000000)] + [{"md5_us": timeit(lambda: passwords.md5_unsalted("correct horse"), 20000) * 1e6}]


def bench_gateway():
    from securehub.app import create_app
    app = create_app({"KEY_BITS": 1024, "PBKDF2_ITER": 1000, "LAKE_ROWS": 1000})
    c = app.test_client()
    tok = c.post("/auth/login", json={"username": "alice", "password": "alice-pass-1"}).get_json()["token"]
    H = {"Authorization": "Bearer " + tok}
    n = 300
    public = timeit(lambda: c.get("/api/info"), n) * 1000
    app.sh.audit.entries.clear()
    authed = timeit(lambda: c.get("/api/documents/1", headers=H), n) * 1000
    return {"public_ms": public, "authenticated_ms": authed, "extra_ms": authed - public, "requests": n,
            "note": "authenticated = RSA-1024 verify + RBAC + HMAC proof + doc service + audit entry + 8 detection rules"}


def bench_policy():
    from lake import policy
    sub = {"username": "lina", "role": "analyst", "service": None, "purposes": ["research"]}
    q = {"group_by": ["service", "diagnosis_code"], "metrics": [{"fn": "count"}, {"fn": "avg", "col": "treatment_cost"}, {"fn": "count_distinct", "col": "patient_id"}]}
    t = timeit(lambda: [policy.plan_query(sub, "research", "internal", q) for _ in range(200)], 5) / 200
    return {"plan_ms": t * 1000, "rules": len(policy.RULES), "columns": 13}


# ------------------------------------------------------------------------------------------ window detection
def bench_window(sizes=(10_000, 100_000, 1_000_000)):
    from lake import spark_detect as sd
    from lake.engines import get_spark
    sp = get_spark()
    sp.range(10).count()
    out = []
    os.makedirs(BENCH, exist_ok=True)
    for n in sizes:
        es = sd.synthetic_entries(n, users=max(500, n // 200))
        es += [{"id": n + 1 + i, "ts": 1_800_000_000.0 + n * 0.05 / 2 + i, "user": "mallory", "object": "lake", "status": 403, "rows": 0, "type": "request"} for i in range(4)]
        es += [{"id": n + 10 + i, "ts": 1_800_000_000.0 + n * 0.05 / 3 + i * 5, "user": "eve", "object": "lake", "status": 200, "rows": 300, "type": "request"} for i in range(4)]
        p = os.path.join(BENCH, "audit_%d.jsonl" % n)
        sd.write_jsonl(p, es)
        a = b = None
        ts_py, ts_sp = [], []
        for _ in range(3 if n < 1_000_000 else 2):
            t = time.perf_counter()
            a = sd.detect_python_file(p)
            ts_py.append(time.perf_counter() - t)
        sd.detect_spark(p)                                           # warm-up
        for _ in range(3 if n < 1_000_000 else 2):
            t = time.perf_counter()
            b = sd.detect_spark(p)
            ts_sp.append(time.perf_counter() - t)
        out.append({"entries": len(es), "file_mb": round(os.path.getsize(p) / 1e6, 1), "python_s": statistics.median(ts_py),
                    "spark_s": statistics.median(ts_sp), "same_alerts": a == b, "alerts": [list(x) for x in a]})
        os.remove(p)
        print("window", n, out[-1], flush=True)
    return out


# ------------------------------------------------------------------------------------------ false positives
def bench_fp():
    """Simulated normal traffic (labelled synthetic): how often do rules fire on honest users as thresholds drop?"""
    from securehub.detect import Detector
    rnd = random.Random(5)
    users, hours = 300, 1

    def traffic():
        ev, i = [], 1
        for u in range(users):
            ip = "10.1.%d.%d" % (u // 250, u % 250)
            sess = [rnd.uniform(0, 3600 * hours) for _ in range(rnd.randint(1, 3))]
            for st in sess:
                t = st
                for k in range(rnd.randint(0, 2)):                    # honest typos at login
                    if rnd.random() < 0.25:
                        ev.append({"id": i, "ts": t, "ip": ip, "user": "u%d" % u, "path": "/auth/login", "status": 401, "reason": "bad_credentials"}); i += 1; t += rnd.uniform(3, 15)
                ev.append({"id": i, "ts": t, "ip": ip, "user": "u%d" % u, "path": "/auth/login", "status": 200}); i += 1
                for k in range(rnd.randint(8, 60)):
                    t += rnd.expovariate(1 / 6.0)
                    did = rnd.randint(1, 12)
                    if rnd.random() < 0.06:                              # clicking a document that is not theirs
                        ev.append({"id": i, "ts": t, "ip": ip, "user": "u%d" % u, "path": "/api/documents/%d" % did, "object": str(did), "status": 403, "reason": "not_owner"})
                    elif rnd.random() < 0.01:
                        ev.append({"id": i, "ts": t, "ip": ip, "user": "u%d" % u, "path": "/admin/stats", "status": 403, "reason": "role_lacks_permission"})
                    else:
                        ev.append({"id": i, "ts": t, "ip": ip, "user": "u%d" % u, "path": "/api/documents", "status": 200})
                    i += 1
        ev.sort(key=lambda e: e["ts"])
        for n, e in enumerate(ev):
            e["id"] = n + 1
            e["type"] = "request"
        return ev
    ev = traffic()
    out = {"requests": len(ev), "users": users, "sweeps": []}
    for rule, key, values in (("brute_force", "count", (2, 3, 4, 5, 8)), ("privilege_escalation", "count", (1, 2, 3, 5)), ("object_enumeration", "count", (2, 3, 4, 6, 8)), ("request_burst", "count", (5, 8, 12, 20, 30))):
        for v in values:
            d = Detector({rule: {key: v}, "cooldown": 0})
            fired = 0
            for e in ev:
                fired += sum(1 for a in d.feed(e) if a["rule"] == rule)
            out["sweeps"].append({"rule": rule, "threshold": v, "false_alerts": fired, "per_10k_requests": round(fired * 10000.0 / len(ev), 1)})
    return out


def bench_attacks():
    from securehub.app import create_app
    app = create_app({"KEY_BITS": 512, "PBKDF2_ITER": 1000, "LAKE_ROWS": 3000})
    c = app.test_client()
    tok = c.post("/auth/login", json={"username": "root", "password": "root-pass-5"}).get_json()["token"]
    H = {"Authorization": "Bearer " + tok}
    res = c.post("/lab/attack/all", headers=H).get_json()
    ben = c.post("/lab/benign", headers=H).get_json()
    chain = c.get("/admin/verify-chain", headers=H).get_json()
    return {"attacks": [{"name": r["name"], "title": r["title"], "expected": r["expected_rule"], "fired": r["alerts_fired"], "passed": r["passed"]} for r in res["results"]],
            "passed": res["passed"], "total": res["total"], "benign": ben, "log_entries": chain["checked"], "chain_ok": chain["ok"]}


# ------------------------------------------------------------------------------------------ data lake vs size
def lake_queries():
    D = {"username": "dr_amine", "role": "doctor", "service": "cardiology", "purposes": ["care"]}
    A = {"username": "lina", "role": "analyst", "service": None, "purposes": ["research"]}
    M = {"username": "root", "role": "administrator", "service": None, "purposes": ["maintenance"]}
    return [
        ("Q1", "doctor: 100 rows of one diagnosis, sorted", D, "care",
         {"columns": ["record_id", "full_name", "diagnosis_label"], "where": [{"col": "diagnosis_code", "op": "=", "value": "I10"}], "order_by": [{"col": "record_id"}], "limit": 100},
         "SELECT record_id, full_name, diagnosis_label FROM lake WHERE diagnosis_code = 'I10' ORDER BY record_id LIMIT 100"),
        ("Q2", "analyst: statistics by service and diagnosis", A, "research",
         {"group_by": ["service", "diagnosis_code"], "metrics": [{"fn": "count"}, {"fn": "avg", "col": "treatment_cost"}, {"fn": "count_distinct", "col": "patient_id"}]},
         "SELECT service, diagnosis_code, COUNT(*) AS n, ROUND(AVG(treatment_cost), 2) AS avg_treatment_cost, COUNT(DISTINCT patient_id) AS count_distinct_patient_id FROM lake GROUP BY service, diagnosis_code LIMIT 1000"),
        ("Q3", "analyst: visits per pseudonym (hash on every row)", A, "research",
         {"group_by": ["patient_id"], "metrics": [{"fn": "count"}], "order_by": [{"col": "n", "dir": "desc"}, {"col": "patient_id"}], "limit": 10},
         "SELECT patient_id, COUNT(*) AS n FROM lake GROUP BY patient_id ORDER BY n DESC, patient_id LIMIT 10"),
        ("Q4", "administrator: count by service (no transformation needed)", M, "maintenance",
         {"group_by": ["service"], "metrics": [{"fn": "count"}], "order_by": [{"col": "service"}]},
         "SELECT service, COUNT(*) AS n FROM lake GROUP BY service ORDER BY service LIMIT 50"),
    ]


def bench_lake(sizes):
    from lake import data, engines, policy
    spark = engines.get_spark(os.cpu_count() or 2, "4g")
    spark.range(10).count()
    os.makedirs(BENCH, exist_ok=True)
    R = load()
    R.setdefault("lake", {"sizes": []})
    done = {s["mb"] for s in R["lake"]["sizes"]}
    for mb in sizes:
        if mb in done:
            continue
        rows = data.rows_for_bytes(mb * 1_000_000)
        csv_path = os.path.join(BENCH, "lake_%dmb.csv" % mb)
        t = time.perf_counter()
        data.write_csv(csv_path, rows)
        gen_s = time.perf_counter() - t
        csv_bytes = os.path.getsize(csv_path)
        from lake.catalog import SCHEMA_DDL
        pq = os.path.join(BENCH, "lake_%dmb.parquet" % mb)
        t = time.perf_counter()
        spark.read.csv(csv_path, header=True, schema=SCHEMA_DDL).write.mode("overwrite").parquet(pq)
        conv_s = time.perf_counter() - t
        pq_bytes = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fs in os.walk(pq) for f in fs)
        eng = engines.SparkEngine(pq, "parquet", view="lake_%d" % mb, spark=spark)
        entry = {"mb": mb, "rows": rows, "csv_bytes": csv_bytes, "parquet_bytes": pq_bytes, "gen_s": gen_s, "convert_s": conv_s, "queries": {}}
        reps = 5 if mb <= 100 else 3
        for qid, label, subj, purpose, q, base_sql in lake_queries():
            tp = time.perf_counter()
            plan = policy.plan_query(subj, purpose, "internal", q)
            plan_ms = (time.perf_counter() - tp) * 1000
            assert plan["allowed"], (qid, plan["reason"])
            base_df = lambda: eng.run_sql(base_sql).collect()
            ctrl = lambda: eng.run(plan)
            base_df(); ctrl()                                                  # warm-up
            rb, rc = [], []
            for _ in range(reps):                                              # interleaved: no order bias
                t0 = time.perf_counter(); base_df(); rb.append(time.perf_counter() - t0)
                t0 = time.perf_counter(); ctrl(); rc.append(time.perf_counter() - t0)
            tb, tc = statistics.median(rb), statistics.median(rc)
            nb, nc = len(base_df()), ctrl()["row_count"]
            entry["queries"][qid] = {"label": label, "baseline_ms": tb * 1000, "controlled_ms": tc * 1000, "overhead_pct": (tc - tb) / tb * 100.0,
                                     "plan_ms": plan_ms, "rows_baseline": nb, "rows_controlled": nc, "repeats": reps,
                                     "baseline_runs_ms": [round(x * 1000, 1) for x in rb], "controlled_runs_ms": [round(x * 1000, 1) for x in rc]}
            print(mb, qid, round(tb * 1000), round(tc * 1000), "%+.0f%%" % ((tc - tb) / tb * 100), flush=True)
        if mb <= 100:                                                           # pure-Python engine, same plan, for contrast
            t = time.perf_counter()
            rowsl = data.read_csv(csv_path)
            load_s = time.perf_counter() - t
            py = engines.PyEngine(rowsl)
            qid, label, subj, purpose, q, _ = lake_queries()[1]
            plan = policy.plan_query(subj, purpose, "internal", q)
            t = time.perf_counter()
            py.run(plan)
            entry["python_engine"] = {"load_s": load_s, "q2_s": time.perf_counter() - t}
            del rowsl, py
        R["lake"]["sizes"].append(entry)
        R["lake"]["sizes"].sort(key=lambda s: s["mb"])
        save(R)
        os.remove(csv_path)
        shutil.rmtree(pq, ignore_errors=True)
    return R["lake"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="rsa,pbkdf2,gateway,policy,window,fp,attacks,lake")
    ap.add_argument("--sizes", default="1,10,100,1000")
    a = ap.parse_args()
    sys.path.insert(0, HERE)
    R = load()
    R["meta"] = meta()
    for part in a.only.split(","):
        t = time.time()
        if part == "lake":
            R["lake"] = bench_lake([int(x) for x in a.sizes.split(",")])
        elif part == "window":
            R["window"] = bench_window()
        else:
            R[part] = globals()["bench_" + part]()
        save(R) if part != "lake" else None
        print("done", part, round(time.time() - t, 1), "s", flush=True)
    save(R)


if __name__ == "__main__":
    main()
