"""ABAC policy engine for the data lake.

Inputs : subject attributes (role, service, allowed purposes), resource attributes (column
         sensitivity and tags), context (declared purpose, network zone).
Output : a PLAN - per-column outcome (clear / mask / hash / deny), a row filter, query constraints
         (aggregate-only, minimum group size k, row cap) and the rewritten SQL.

Conflict resolution: DENY-OVERRIDES. If any applicable rule denies a column, the column is denied.
Among permits the most protective obligation wins (hash > mask > clear). No applicable rule =
default deny. Everything here is data + pure functions: no Spark needed to decide.
"""
import re

from .catalog import COLUMNS

PEPPER = "lake-pepper-demo"          # secret salt for pseudonyms (in a real system: a secret store)
RANK = {"clear": 0, "mask": 1, "hash": 2, "deny": 3}
OPS = {"=": "=", "!=": "<>", "<": "<", "<=": "<=", ">": ">", ">=": ">=", "in": "IN"}
FNS = {"count", "count_distinct", "sum", "avg", "min", "max"}
SAFE_VALUE = re.compile(r"^[\w .:/@\-]{0,64}$")
INTERNAL_PREFIXES = ("127.", "10.1.", "192.168.")

RULES = [
    {"id": "P1", "effect": "permit", "role": ["doctor"], "purpose": ["care"], "zone": ["internal"],
     "columns": {}, "obligation": "clear", "rows": "own_service",
     "desc": "Doctors read clear data of their own department, for care, from the hospital network"},
    {"id": "P2", "effect": "permit", "role": ["doctor"], "purpose": ["care"], "zone": ["external"],
     "columns": {"sens_max": 1}, "obligation": "clear", "rows": "own_service",
     "desc": "From outside the network a doctor still sees public and internal columns"},
    {"id": "P3", "effect": "permit", "role": ["doctor"], "purpose": ["care"], "zone": ["external"],
     "columns": {"sens_min": 2, "sens_max": 2}, "obligation": "mask", "rows": "own_service",
     "desc": "...and confidential columns only masked; restricted columns get no permit (default deny)"},
    {"id": "P4", "effect": "permit", "role": ["analyst"], "purpose": ["research", "statistics"], "zone": ["internal", "external"],
     "columns": {"sens_max": 2, "tags_any": ["identifier"]}, "obligation": "hash", "rows": None,
     "desc": "Analysts receive identifiers only as pseudonyms (salted SHA-256)"},
    {"id": "P5", "effect": "permit", "role": ["analyst"], "purpose": ["research", "statistics"], "zone": ["internal", "external"],
     "columns": {"sens_max": 2, "tags_none": ["identifier", "pii"]}, "obligation": "clear", "rows": None,
     "desc": "Analysts read non-identifying columns in clear"},
    {"id": "P6", "effect": "permit", "role": ["analyst"], "purpose": ["research", "statistics"], "zone": ["internal", "external"],
     "columns": {"sens_max": 2, "tags_any": ["pii"], "tags_none": ["identifier"]}, "obligation": "mask", "rows": None,
     "desc": "Analysts see quasi-identifiers (birth date) generalised to the year"},
    {"id": "P7", "effect": "permit", "role": ["administrator"], "purpose": ["maintenance"], "zone": ["internal", "external"],
     "columns": {"sens_max": 0}, "obligation": "clear", "rows": None,
     "desc": "The lake administrator reads public columns"},
    {"id": "P8", "effect": "permit", "role": ["administrator"], "purpose": ["maintenance"], "zone": ["internal", "external"],
     "columns": {"sens_min": 1, "sens_max": 2}, "obligation": "mask", "rows": None,
     "desc": "...and everything else only masked: the administrator runs the lake but does not read patients"},
    {"id": "D1", "effect": "deny", "role": None, "purpose": None, "purpose_not": ["care"], "zone": None,
     "columns": {"sens_min": 3}, "obligation": None, "rows": None,
     "desc": "Restricted columns (national id, clinical notes) are only ever served for the purpose 'care'"},
    {"id": "D2", "effect": "deny", "role": ["doctor"], "purpose": None, "zone": None,
     "columns": {"tags_any": ["financial"]}, "obligation": None, "rows": None,
     "desc": "Doctors do not receive billing data (overrides P1 and P2: deny-overrides)"},
]

CONSTRAINTS = {
    "doctor": {"aggregate_only": False, "k_min": 1, "max_rows": 100},
    "analyst": {"aggregate_only": True, "k_min": 5, "max_rows": 1000},
    "administrator": {"aggregate_only": True, "k_min": 1, "max_rows": 50},
}

SUBJECT_PURPOSES = {"doctor": ["care"], "analyst": ["research", "statistics"], "administrator": ["maintenance"]}


class PolicyError(Exception):
    def __init__(self, reason, message="", columns=None):
        super().__init__(message or reason)
        self.reason = reason
        self.columns = columns or []


def zone_of(ip):
    return "internal" if str(ip).startswith(INTERNAL_PREFIXES) else "external"


def _col_match(spec, col):
    if "sens_min" in spec and col["sensitivity"] < spec["sens_min"]:
        return False
    if "sens_max" in spec and col["sensitivity"] > spec["sens_max"]:
        return False
    if "tags_any" in spec and not set(spec["tags_any"]) & set(col["tags"]):
        return False
    if "tags_none" in spec and set(spec["tags_none"]) & set(col["tags"]):
        return False
    return True


def applicable(rule, subject, purpose, zone, col):
    if rule.get("role") and subject["role"] not in rule["role"]:
        return False
    if rule.get("purpose") and purpose not in rule["purpose"]:
        return False
    if rule.get("purpose_not") and purpose in rule["purpose_not"]:
        return False
    if rule.get("zone") and zone not in rule["zone"]:
        return False
    return _col_match(rule["columns"], col)


def column_decision(subject, purpose, zone, col, rules=RULES):
    """-> dict(outcome, permits, denies, deciding) for one column."""
    hits = [r for r in rules if applicable(r, subject, purpose, zone, col)]
    denies = [r["id"] for r in hits if r["effect"] == "deny"]
    permits = [r for r in hits if r["effect"] == "permit"]
    if denies:
        return {"outcome": "deny", "permits": [r["id"] for r in permits], "denies": denies,
                "deciding": denies[0], "conflict": bool(permits),
                "why": "deny-overrides: %s beats %s" % (",".join(denies), ",".join(r["id"] for r in permits) or "no permit")}
    if not permits:
        return {"outcome": "deny", "permits": [], "denies": [], "deciding": None, "conflict": False,
                "why": "default deny: no rule permits this column"}
    best = max(permits, key=lambda r: RANK[r["obligation"]])
    return {"outcome": best["obligation"], "permits": [r["id"] for r in permits], "denies": [],
            "deciding": best["id"], "conflict": len({r["obligation"] for r in permits}) > 1,
            "why": "most protective permit wins: %s (%s)" % (best["id"], best["obligation"]), "_rules": permits}


# ---------------------------------------------------------------- query validation
def _lit(value, col):
    if col["type"] == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise PolicyError("bad_value", "column %s expects an integer" % col["name"])
        return str(value)
    if not isinstance(value, str) or not SAFE_VALUE.match(value):
        raise PolicyError("bad_value", "value for %s contains forbidden characters" % col["name"])
    return "'" + value + "'"


def normalise_query(q):
    """Validate a structured query (allow-lists everywhere) and return a clean copy."""
    if not isinstance(q, dict):
        raise PolicyError("bad_query", "query must be an object")
    unknown = set(q) - {"columns", "where", "group_by", "metrics", "order_by", "limit"}
    if unknown:
        raise PolicyError("bad_query", "unknown keys: %s" % ", ".join(sorted(unknown)))

    def names(lst, what):
        if not isinstance(lst, list) or not all(isinstance(x, str) for x in lst):
            raise PolicyError("bad_query", "%s must be a list of column names" % what)
        for x in lst:
            if x not in COLUMNS:
                raise PolicyError("unknown_column", "unknown column %r" % x)
        return list(lst)

    cols = q.get("columns", "*")
    cols = "*" if cols == "*" else names(cols, "columns")
    group_by = names(q.get("group_by", []), "group_by")
    metrics = []
    for m in q.get("metrics", []) or []:
        if not isinstance(m, dict) or m.get("fn") not in FNS:
            raise PolicyError("bad_query", "metric needs fn in %s" % sorted(FNS))
        col = m.get("col")
        if m["fn"] != "count" or col is not None:
            if col not in COLUMNS:
                raise PolicyError("unknown_column", "unknown column %r" % (col,))
        alias = m.get("as") or ("n" if m["fn"] == "count" and col is None else "%s_%s" % (m["fn"], col))
        if not re.match(r"^[a-z][a-z0-9_]{0,30}$", alias):
            raise PolicyError("bad_query", "bad alias")
        metrics.append({"fn": m["fn"], "col": col, "as": alias})
    where = []
    for w in q.get("where", []) or []:
        if not isinstance(w, dict) or w.get("col") not in COLUMNS or w.get("op") not in OPS:
            raise PolicyError("bad_query", "each filter needs col and op in %s" % sorted(OPS))
        col = COLUMNS[w["col"]]
        if w["op"] == "in":
            vals = w.get("value")
            if not isinstance(vals, list) or not 1 <= len(vals) <= 20:
                raise PolicyError("bad_query", "'in' needs a list of 1 to 20 values")
            where.append({"col": col["name"], "op": "in", "value": list(vals)})
            [_lit(v, col) for v in vals]
        else:
            _lit(w.get("value"), col)
            where.append({"col": col["name"], "op": w["op"], "value": w["value"]})
    order = []
    for o in q.get("order_by", []) or []:
        if not isinstance(o, dict) or not isinstance(o.get("col"), str) or o.get("dir", "asc") not in ("asc", "desc"):
            raise PolicyError("bad_query", "order_by items need col and dir asc|desc")
        order.append({"col": o["col"], "dir": o.get("dir", "asc")})
    limit = q.get("limit")
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100000):
        raise PolicyError("bad_query", "limit must be an integer from 1 to 100000")
    return {"columns": cols, "where": where, "group_by": group_by, "metrics": metrics, "order_by": order, "limit": limit}


# ---------------------------------------------------------------- SQL pieces (shared by both engines' docs)
def mask_sql(col):
    c, k = col["name"], col["mask"]
    s = "CAST(%s AS STRING)" % c
    return {"last4": "concat('*******', right(%s, 4))" % s,
            "initials": "array_join(transform(split(%s, ' '), x -> concat(substring(x, 1, 1), '.')), ' ')" % s,
            "year": "substring(%s, 1, 4)" % s,
            "bucket": "concat(CAST((%s DIV 10000) * 10000 AS STRING), '-', CAST((%s DIV 10000) * 10000 + 9999 AS STRING))" % (c, c),
            "redact": "'***'"}[k]


def hash_sql(col, pepper=PEPPER):
    return "substring(sha2(concat('%s', CAST(%s AS STRING)), 256), 1, 12)" % (pepper, col["name"])


def project_sql(name, outcome, pepper=PEPPER):
    col = COLUMNS[name]
    if outcome == "clear":
        return name
    if outcome == "mask":
        return "%s AS %s" % (mask_sql(col), name)
    if outcome == "hash":
        return "%s AS %s" % (hash_sql(col, pepper), name)
    raise ValueError(outcome)


# ---------------------------------------------------------------- the plan
def plan_query(subject, purpose, zone, query, rules=RULES, pepper=PEPPER):
    """subject = {username, role, service, purposes}. Returns a plan dict; never touches data.
    plan['allowed'] False -> plan['reason'] and plan['columns_denied'] explain why."""
    q = normalise_query(query)
    role = subject["role"]
    cons = dict(CONSTRAINTS.get(role, {"aggregate_only": True, "k_min": 5, "max_rows": 10}))
    aggregate = bool(q["metrics"] or q["group_by"])
    base = {"subject": subject["username"], "role": role, "purpose": purpose, "zone": zone, "query": q,
            "constraints": cons, "aggregate": aggregate, "columns": {}, "explain": [], "allowed": False,
            "reason": None, "columns_denied": [], "row_filter": None, "sql": None}

    def refuse(reason, cols=()):
        base["reason"], base["columns_denied"] = reason, list(cols)
        return base

    if purpose not in subject.get("purposes", []):
        return refuse("purpose_not_allowed")
    if cons["aggregate_only"] and not aggregate:
        return refuse("aggregate_only")

    # which columns does this query touch?
    star = q["columns"] == "*"
    if aggregate:
        used = list(dict.fromkeys(q["group_by"] + [m["col"] for m in q["metrics"] if m["col"]]))
    else:
        used = list(COLUMNS) if star else list(dict.fromkeys(q["columns"]))
    where_cols = [w["col"] for w in q["where"]]
    decisions = {c: column_decision(subject, purpose, zone, COLUMNS[c], rules) for c in list(dict.fromkeys(used + where_cols))}
    if star and not aggregate:                                  # SELECT * quietly drops columns the user may not see
        used = [c for c in used if decisions[c]["outcome"] != "deny"]
    for c, d in decisions.items():
        base["explain"].append({"column": c, "sensitivity": COLUMNS[c]["sensitivity"], "outcome": d["outcome"],
                                "permits": d["permits"], "denies": d["denies"], "conflict": d["conflict"], "why": d["why"],
                                "role_in_query": "filter" if c in where_cols and c not in used else "output"})
        base["columns"][c] = d["outcome"]
    denied = [c for c in used if decisions[c]["outcome"] == "deny"]
    if denied:
        return refuse("column_denied", denied)
    for w in q["where"]:                                        # a filter on a masked column would leak by inference
        if decisions[w["col"]]["outcome"] != "clear":
            return refuse("filter_on_protected_column", [w["col"]])
    for m in q["metrics"]:
        if m["fn"] in ("sum", "avg"):
            if COLUMNS[m["col"]]["type"] != "int" or decisions[m["col"]]["outcome"] != "clear":
                return refuse("metric_needs_clear_numeric_column", [m["col"]])
        if m["fn"] in ("min", "max") and decisions[m["col"]]["outcome"] != "clear":
            return refuse("metric_needs_clear_column", [m["col"]])
    # output names allowed in ORDER BY
    out_names = (q["group_by"] + [m["as"] for m in q["metrics"]]) if aggregate else used
    for o in q["order_by"]:
        if o["col"] not in out_names:
            return refuse("order_by_not_in_output")
    if not aggregate and not used:
        return refuse("no_visible_column")

    # row filter: AND of the distinct filters that the contributing permit rules require
    filters = []
    for c in used + where_cols:
        for r in decisions[c].get("_rules", []):
            if r.get("rows") == "own_service" and "own_service" not in filters:
                filters.append("own_service")
    base["row_filter"] = None
    if "own_service" in filters:
        if not subject.get("service"):
            return refuse("subject_has_no_service")
        base["row_filter"] = {"col": "service", "op": "=", "value": subject["service"]}
    limit = min(q["limit"] or cons["max_rows"], cons["max_rows"])
    base.update(limit=limit, used=used, allowed=True, reason="ok", out_names=out_names)
    base["sql"] = build_sql(base, pepper)
    base["pepper"] = pepper
    return base


def _pred(w, col):
    if w["op"] == "in":
        return "%s IN (%s)" % (w["col"], ", ".join(_lit(v, COLUMNS[w["col"]]) for v in w["value"]))
    return "%s %s %s" % (w["col"], OPS[w["op"]], _lit(w["value"], COLUMNS[w["col"]]))


def build_sql(plan, pepper=PEPPER):
    """Query rewriting. The user's query is NEVER run as written: it is wrapped around a protected
    projection of the table (the 'secure view') with the row filter and user filters inside."""
    q, used = plan["query"], plan["used"]
    inner_cols = list(used)
    proj = ", ".join(project_sql(c, plan["columns"][c], pepper) for c in inner_cols)
    preds = []
    if plan["row_filter"]:
        preds.append(_pred(plan["row_filter"], None))
    preds += [_pred(w, None) for w in q["where"]]
    where = (" WHERE " + " AND ".join(preds)) if preds else ""
    inner = "SELECT %s FROM lake%s" % (proj, where)
    order = ""
    if q["order_by"]:
        order = " ORDER BY " + ", ".join("%s %s" % (o["col"], o["dir"].upper()) for o in q["order_by"])
    if plan["aggregate"]:
        parts = list(q["group_by"])
        for m in q["metrics"]:
            if m["fn"] == "count":
                e = "COUNT(*)" if m["col"] is None else "COUNT(%s)" % m["col"]
            elif m["fn"] == "count_distinct":
                e = "COUNT(DISTINCT %s)" % m["col"]
            elif m["fn"] == "avg":
                e = "ROUND(AVG(%s), 2)" % m["col"]
            else:
                e = "%s(%s)" % (m["fn"].upper(), m["col"])
            parts.append("%s AS %s" % (e, m["as"]))
        sql = "SELECT %s FROM (%s) v" % (", ".join(parts), inner)
        if q["group_by"]:
            sql += " GROUP BY " + ", ".join(q["group_by"])
        if plan["constraints"]["k_min"] > 1:
            sql += " HAVING COUNT(*) >= %d" % plan["constraints"]["k_min"]
    else:
        sql = "SELECT %s FROM (%s) v" % (", ".join(used), inner)
    return "%s%s LIMIT %d" % (sql, order, plan["limit"])


def original_sql(query):
    """What the user asked, as plain SQL, for the side-by-side explanation (not executed)."""
    q = normalise_query(query)
    if q["metrics"] or q["group_by"]:
        sel = ", ".join(q["group_by"] + ["%s(%s)" % (m["fn"].upper(), m["col"] or "*") for m in q["metrics"]])
    else:
        sel = "*" if q["columns"] == "*" else ", ".join(q["columns"])
    sql = "SELECT %s FROM lake" % sel
    if q["where"]:
        sql += " WHERE " + " AND ".join(_pred(w, None) for w in q["where"])
    if q["group_by"]:
        sql += " GROUP BY " + ", ".join(q["group_by"])
    return sql
