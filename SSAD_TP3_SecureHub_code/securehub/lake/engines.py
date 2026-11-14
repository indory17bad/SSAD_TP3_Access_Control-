"""Two executors for the SAME plan: PyEngine (pure Python, always available) and SparkEngine
(PySpark). Tests check that both return identical results."""
import hashlib
import os
import threading
import time

from .catalog import COLUMNS, SCHEMA_DDL
from .policy import PEPPER


def _mask(col, v):
    k = col["mask"]
    s = str(v)
    if k == "last4":
        return "*******" + s[-4:]
    if k == "initials":
        return " ".join(w[:1] + "." for w in s.split(" "))
    if k == "year":
        return s[:4]
    if k == "bucket":
        lo = (int(v) // 10000) * 10000
        return "%d-%d" % (lo, lo + 9999)
    return "***"


def _hash(v, pepper):
    return hashlib.sha256((pepper + str(v)).encode()).hexdigest()[:12]


def _cmp(op, a, b):
    return {"=": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]


class PyEngine:
    name = "python"

    def __init__(self, rows):
        self.rows = rows

    def run(self, plan):
        t0 = time.perf_counter()
        q, outc, pepper = plan["query"], plan["columns"], plan.get("pepper", PEPPER)
        preds = ([plan["row_filter"]] if plan["row_filter"] else []) + q["where"]

        def ok(r):
            for w in preds:
                if w["op"] == "in":
                    if r[w["col"]] not in w["value"]:
                        return False
                elif not _cmp(w["op"], r[w["col"]], w["value"]):
                    return False
            return True

        def proj(r):
            out = {}
            for c in plan["used"]:
                o = outc[c]
                out[c] = r[c] if o == "clear" else _mask(COLUMNS[c], r[c]) if o == "mask" else _hash(r[c], pepper)
            return out

        view = [proj(r) for r in self.rows if ok(r)]
        if plan["aggregate"]:
            groups = {}
            for r in view:
                groups.setdefault(tuple(r[g] for g in q["group_by"]), []).append(r)
            if not q["group_by"]:
                groups = {(): view}
            out = []
            for key, rs in groups.items():
                if plan["constraints"]["k_min"] > 1 and len(rs) < plan["constraints"]["k_min"]:
                    continue
                if not q["group_by"] and not rs and plan["constraints"]["k_min"] > 1:
                    continue
                row = dict(zip(q["group_by"], key))
                for m in q["metrics"]:
                    vals = [r[m["col"]] for r in rs] if m["col"] else None
                    fn = m["fn"]
                    if fn == "count":
                        v = len(rs) if m["col"] is None else len(vals)
                    elif fn == "count_distinct":
                        v = len(set(vals))
                    elif fn == "sum":
                        v = sum(vals)
                    elif fn == "avg":
                        v = round(sum(vals) / len(vals), 2) if vals else None
                    elif fn == "min":
                        v = min(vals) if vals else None
                    else:
                        v = max(vals) if vals else None
                    row[m["as"]] = v
                out.append(row)
            cols = plan["out_names"]
        else:
            out, cols = view, plan["used"]
        for o in reversed(q["order_by"]):
            out.sort(key=lambda r: (r[o["col"]] is None, r[o["col"]]), reverse=(o["dir"] == "desc"))
        out = out[:plan["limit"]]
        return {"engine": self.name, "columns": cols, "rows": [[r[c] for c in cols] for r in out],
                "row_count": len(out), "ms": round((time.perf_counter() - t0) * 1000, 1)}


_spark = None
_spark_lock = threading.Lock()


def spark_available():
    try:
        import pyspark  # noqa: F401
    except Exception:
        return False
    import shutil
    return bool(shutil.which("java") or os.environ.get("JAVA_HOME"))


def get_spark(cores=2, memory="2g"):
    global _spark
    with _spark_lock:
        if _spark is None:
            from pyspark.sql import SparkSession
            _spark = (SparkSession.builder.master("local[%d]" % cores).appName("securehub-lake")
                      .config("spark.ui.enabled", "false").config("spark.sql.shuffle.partitions", "8")
                      .config("spark.driver.memory", memory).config("spark.sql.session.timeZone", "UTC")
                      .getOrCreate())
            _spark.sparkContext.setLogLevel("ERROR")
        return _spark


def stop_spark():
    global _spark
    with _spark_lock:
        if _spark is not None:
            _spark.stop()
            _spark = None


class SparkEngine:
    name = "spark"

    def __init__(self, path, fmt="csv", view="lake", spark=None):
        from pathlib import Path
        self.spark = spark or get_spark()
        self.view = view
        uri = Path(path).resolve().as_uri()               # file:///... also works for Windows paths
        if fmt == "csv":
            df = self.spark.read.csv(uri, header=True, schema=SCHEMA_DDL)
        else:
            df = self.spark.read.parquet(uri)
        df.createOrReplaceTempView(view)
        self.df = df

    def run_sql(self, sql):
        return self.spark.sql(sql.replace(" FROM lake", " FROM " + self.view))

    def run(self, plan):
        t0 = time.perf_counter()
        res = self.run_sql(plan["sql"])
        rows = res.collect()
        cols = res.columns
        return {"engine": self.name, "columns": cols, "rows": [[r[c] for c in cols] for r in rows],
                "row_count": len(rows), "ms": round((time.perf_counter() - t0) * 1000, 1)}
