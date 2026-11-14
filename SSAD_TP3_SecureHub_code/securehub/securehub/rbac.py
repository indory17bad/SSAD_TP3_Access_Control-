"""Authorization: role-based permissions (function level) + object rules (object level).

decide() is the policy decision point. Default deny: anything not explicitly allowed is refused.
Two levels, because both are needed:
  1. function level : may this ROLE perform this ACTION at all?   (RBAC table)
  2. object level   : may THIS USER touch THIS DOCUMENT?          (owner / course / kind rules, ABAC flavour)
Skipping level 2 is the classic BOLA/IDOR flaw (OWASP API Security #1).
"""
from collections import namedtuple

Decision = namedtuple("Decision", "allowed reason level")

LAKE = {"lake:query", "lake:explain", "lake:policy"}
PERMISSIONS = {
    "student": {"doc:list", "doc:read"},
    "teacher": {"doc:list", "doc:read", "doc:create"},
    "administrator": {"doc:list", "doc:read", "doc:delete", "audit:read", "audit:stream", "audit:verify",
                      "lab:attack", "keys:rotate", "users:list"} | LAKE,
    "doctor": set(LAKE),
    "analyst": set(LAKE),
}


def has_permission(role, perm):
    return perm in PERMISSIONS.get(role, ())


def decide(role, user, perm, doc=None, course=None):
    """role/user come from the VERIFIED token + store; doc is the target object when there is one."""
    if not has_permission(role, perm):
        return Decision(False, "role_lacks_permission", 1)
    if perm == "doc:read" and doc is not None:
        return _read_rule(role, user, doc)
    if perm == "doc:create":
        if course not in (user or {}).get("courses", []):
            return Decision(False, "not_your_course", 2)
    return Decision(True, "ok", 1)


def _read_rule(role, user, doc):
    name = user["username"]
    if role == "student":
        if doc["kind"] == "lecture":
            return Decision(True, "ok", 2) if doc["course"] in user["courses"] else Decision(False, "not_enrolled", 2)
        if doc["kind"] == "grades":
            return Decision(True, "ok", 2) if doc["owner"] == name else Decision(False, "not_owner", 2)
        return Decision(False, "kind_not_allowed", 2)
    if role == "teacher":
        if doc["course"] in user["courses"] and doc["kind"] in ("lecture", "exam", "grades"):
            return Decision(True, "ok", 2)
        return Decision(False, "not_your_course", 2)
    if role == "administrator":
        # separation of duties: the administrator runs the system but cannot read exams or grades
        if doc["kind"] in ("lecture", "admin"):
            return Decision(True, "ok", 2)
        return Decision(False, "separation_of_duties", 2)
    return Decision(False, "unknown_role", 2)


def visible_documents(role, user, docs):
    """API-side filtering: the list endpoint only ever returns what decide() allows."""
    out = []
    for d in docs:
        if role == "administrator":                     # may LIST everything (metadata), read only some
            out.append(d)
        elif decide(role, user, "doc:read", doc=d).allowed:
            out.append(d)
    return out
