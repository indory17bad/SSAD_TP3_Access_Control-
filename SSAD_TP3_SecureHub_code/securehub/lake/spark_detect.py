"""Detection over the audit log with TIME-WINDOW aggregations, in Spark and in plain Python.

Rules (per user, sliding window of `window` seconds that moves every `slide` seconds):
  mass_access     : rows returned by ALLOWED lake queries in one window  >= max_rows
  repeated_denied : lake queries REFUSED in one window                    >= max_denied
The Python version enumerates windows exactly as Spark does (epoch-aligned), so results can be compared.
"""
import json
import math
import time
from collections import defaultdict

DEFAULTS = {"window": 60, "slide": 10, "max_rows": 500, "max_denied": 3}


def detect_python(entries, cfg=None):
    c = dict(DEFAULTS, **(cfg or {}))
    w, s = c["window"], c["slide"]
    rows, denied = defaultdict(int), defaultdict(int)
    for e in entries:
        if e.get("object") != "lake" or e.get("type", "request") != "request":
            continue
        t = float(e["ts"])
        first = math.floor(t / s) * s
        for k in range(w // s):
            start = first - k * s
            if start <= t < start + w:
                key = (e["user"], start)
                if e["status"] < 400:
                    rows[key] += int(e.get("rows") or 0)
                elif e["status"] == 403:
                    denied[key] += 1
    alerts = {}
    for (u, st), v in rows.items():
        if v >= c["max_rows"]:
            alerts.setdefault(("mass_access", u), (st, v))
    for (u, st), v in denied.items():
        if v >= c["max_denied"]:
            alerts.setdefault(("repeated_denied", u), (st, v))
    return sorted(alerts)


def detect_spark(source, cfg=None, spark=None):
    """source: path of a JSON-lines audit export (or a list of dict entries)."""
    from pyspark.sql import functions as F
    from .engines import get_spark
    spark = spark or get_spark()
    c = dict(DEFAULTS, **(cfg or {}))
    if isinstance(source, str):
        df = spark.read.json(source)
    else:
        import json as _j
        df = spark.read.json(spark.sparkContext.parallelize([_j.dumps(e) for e in source]))
    if "rows" not in df.columns:
        df = df.withColumn("rows", F.lit(0))
    if "object" not in df.columns:
        df = df.withColumn("object", F.lit(None).cast("string"))
    df = (df.filter((F.col("object") == "lake") & (F.coalesce(F.col("type"), F.lit("request")) == "request"))
            .withColumn("t", F.col("ts").cast("double").cast("timestamp")))
    win = F.window("t", "%d seconds" % c["window"], "%d seconds" % c["slide"])
    agg = (df.groupBy("user", win)
             .agg(F.sum(F.when(F.col("status") < 400, F.coalesce(F.col("rows"), F.lit(0))).otherwise(0)).alias("rows_out"),
                  F.sum(F.when(F.col("status") == 403, 1).otherwise(0)).alias("denied")))
    mass = agg.filter(F.col("rows_out") >= c["max_rows"]).select(F.lit("mass_access").alias("rule"), "user").distinct()
    rep = agg.filter(F.col("denied") >= c["max_denied"]).select(F.lit("repeated_denied").alias("rule"), "user").distinct()
    return sorted((r["rule"], r["user"]) for r in mass.union(rep).collect())


def write_jsonl(path, entries):
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, separators=(",", ":")) + "\n")


def detect_python_file(path, cfg=None):
    with open(path, encoding="utf-8") as f:
        return detect_python((json.loads(line) for line in f), cfg)


def synthetic_entries(n, users=500, seed=7, t0=1_800_000_000.0):
    """Mostly normal traffic plus a few planted attackers (for benchmark and tests)."""
    import random
    r = random.Random(seed)
    out = []
    for i in range(n):
        u = "user%d" % r.randrange(users)
        ok = r.random() > 0.01
        out.append({"id": i + 1, "ts": round(t0 + i * 0.05 + r.random() * 0.01, 3), "user": u, "object": "lake",
                    "status": 200 if ok else 403, "rows": r.randint(1, 20) if ok else 0, "type": "request"})
    return out
