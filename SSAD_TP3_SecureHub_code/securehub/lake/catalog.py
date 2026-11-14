"""The table 'lake' (hospital records) and what each column is. Sensitivity: 0 public, 1 internal,
2 confidential, 3 restricted. `mask` is the transformation used when a policy says 'mask'."""
from collections import OrderedDict

COLUMNS = OrderedDict()
for name, typ, sens, tags, mask, desc in [
    ("record_id", "int", 0, [], "redact", "technical row number"),
    ("patient_id", "str", 1, ["identifier"], "redact", "internal patient code"),
    ("full_name", "str", 2, ["identifier", "pii"], "initials", "patient name"),
    ("national_id", "str", 3, ["identifier", "pii"], "last4", "national identity number"),
    ("birth_date", "str", 2, ["pii"], "year", "date of birth (YYYY-MM-DD)"),
    ("city", "str", 1, [], "redact", "city of residence"),
    ("service", "str", 0, [], "redact", "hospital department"),
    ("diagnosis_code", "str", 2, ["health"], "redact", "diagnosis code"),
    ("diagnosis_label", "str", 2, ["health"], "redact", "diagnosis text"),
    ("treatment_cost", "int", 1, ["financial"], "bucket", "billed cost in DZD"),
    ("doctor", "str", 1, [], "redact", "treating doctor"),
    ("admission_date", "str", 1, [], "year", "admission date (YYYY-MM-DD)"),
    ("notes", "str", 3, ["health", "free_text"], "redact", "free-text clinical notes"),
]:
    COLUMNS[name] = {"name": name, "type": typ, "sensitivity": sens, "tags": tags, "mask": mask, "desc": desc}

SCHEMA_DDL = ", ".join("%s %s" % (c["name"], "INT" if c["type"] == "int" else "STRING") for c in COLUMNS.values())
SENSITIVITY_NAMES = {0: "public", 1: "internal", 2: "confidential", 3: "restricted"}
