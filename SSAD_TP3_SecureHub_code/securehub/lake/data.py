"""Synthetic hospital data (no real person). Deterministic for a given seed. Pure Python."""
import csv
import random

from .catalog import COLUMNS

SERVICES = {
    "cardiology": [("I10", "hypertension"), ("I25", "coronary disease")],
    "oncology": [("C34", "lung cancer"), ("C50", "breast cancer")],
    "neurology": [("G40", "epilepsy"), ("G43", "migraine")],
    "pediatrics": [("J45", "asthma"), ("A09", "gastroenteritis")],
    "emergency": [("S72", "hip fracture"), ("A09", "gastroenteritis")],
    "radiology": [("C34", "lung cancer"), ("S72", "hip fracture"), ("N18", "kidney disease")],
}
CITIES = ["Alger", "Oran", "Constantine", "Annaba", "Blida", "Setif", "Tlemcen", "Batna"]
FIRST = ["Amine", "Sarah", "Yacine", "Lina", "Karim", "Nour", "Rania", "Walid", "Imane", "Sofiane",
         "Meriem", "Hakim", "Asma", "Rachid", "Selma", "Farid", "Dounia", "Anis", "Hadjer", "Ilyes"]
LAST = ["Benali", "Boudiaf", "Cherif", "Djerad", "Haddad", "Khelifi", "Mansouri", "Naili", "Ouali",
        "Rahmani", "Saidi", "Taleb", "Zerrouki", "Amrani", "Belkacem", "Ferhat", "Hamidi", "Kaci"]
NOTES = ["stable, follow-up in 3 months", "allergic to penicillin", "family history noted",
         "patient anxious, explained procedure", "transferred after observation", "no complications"]
HEADER = list(COLUMNS)


def generate_rows(n, seed=2026, start_id=1):
    rnd = random.Random(seed)
    services = list(SERVICES)
    for i in range(n):
        rid = start_id + i
        svc = services[rnd.randrange(len(services))]
        code, label = SERVICES[svc][rnd.randrange(len(SERVICES[svc]))]
        y, m, d = rnd.randint(1935, 2023), rnd.randint(1, 12), rnd.randint(1, 28)
        yield {
            "record_id": rid,
            "patient_id": "P%07d" % rnd.randint(1, max(10, n // 2)),
            "full_name": FIRST[rnd.randrange(len(FIRST))] + " " + LAST[rnd.randrange(len(LAST))],
            "national_id": "%012d" % rnd.randrange(10 ** 12),
            "birth_date": "%04d-%02d-%02d" % (y, m, d),
            "city": CITIES[rnd.randrange(len(CITIES))],
            "service": svc,
            "diagnosis_code": code,
            "diagnosis_label": label,
            "treatment_cost": rnd.randrange(2000, 400000, 50),
            "doctor": "doc_%s_%d" % (svc[:4], rnd.randint(1, 5)),
            "admission_date": "%04d-%02d-%02d" % (rnd.randint(2022, 2026), rnd.randint(1, 12), rnd.randint(1, 28)),
            "notes": NOTES[rnd.randrange(len(NOTES))],
        }


def write_csv(path, n, seed=2026):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=HEADER)
        w.writeheader()
        for row in generate_rows(n, seed):
            w.writerow(row)
    return path


def read_csv(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            for c in COLUMNS.values():
                if c["type"] == "int":
                    r[c["name"]] = int(r[c["name"]])
            rows.append(r)
    return rows


def rows_for_bytes(target_bytes, seed=2026):
    """How many rows give roughly `target_bytes` of CSV."""
    import io
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=HEADER)
    for r in generate_rows(2000, seed):
        w.writerow(r)
    return max(1, int(target_bytes / (len(buf.getvalue().encode()) / 2000.0)))
