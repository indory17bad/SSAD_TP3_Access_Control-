"""Do the tests really protect the security rules? Break one rule at a time and count failing tests.
    python mutation_check.py      -> results/mutation.json   (code is restored after each run)"""
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MUTANTS = [
    ("object-level owner check removed", "securehub/rbac.py", 'if doc["owner"] == name else Decision(False, "not_owner", 2)', 'if True else Decision(False, "not_owner", 2)'),
    ("token signature not verified", "securehub/tokens.py", 'if not rsa.verify(rec["key"].n, rec["key"].e, signing_input, sig):', "if False:"),
    ("deny-overrides disabled", "lake/policy.py", "    if denies:", "    if False:"),
    ("filter on masked/hashed column allowed", "lake/policy.py", 'if decisions[w["col"]]["outcome"] != "clear":', "if False:"),
    ("minimum group size (k) removed", "lake/policy.py", 'if plan["constraints"]["k_min"] > 1:', "if False:"),
    ("audit hash ignores entry content", "securehub/audit.py", "return hashlib.sha256((prev + _canon(entry)).encode()).hexdigest()", "return hashlib.sha256(prev.encode()).hexdigest()"),
    ("gateway proof not checked by document service", "securehub/docsvc.py", "        self.check_proof(sub, role, action, ref, ts, proof)\n        user =", "        user ="),
    ("lockout disabled", "securehub/app.py", 'if len(fl) >= cfg["LOCK_FAILS"]:', "if False:"),
]


def run_tests():
    r = subprocess.run([sys.executable, "-m", "unittest", "tests.test_core", "tests.test_api", "tests.test_lake"], cwd=HERE, capture_output=True, text=True)
    out = r.stderr
    ran = int(re.search(r"Ran (\d+) tests", out).group(1))
    bad = sum(int(x) for x in re.findall(r"(?:failures|errors)=(\d+)", out))
    return ran, bad


def main():
    res = []
    for name, rel, old, new in MUTANTS:
        path = os.path.join(HERE, rel)
        src = open(path, encoding="utf-8").read()
        assert old in src, (name, "pattern not found")
        shutil.copy(path, path + ".orig")
        try:
            open(path, "w", encoding="utf-8").write(src.replace(old, new, 1))
            ran, bad = run_tests()
        finally:
            shutil.move(path + ".orig", path)
        res.append({"mutant": name, "file": rel, "tests_run": ran, "tests_failing": bad, "caught": bad > 0})
        print(res[-1], flush=True)
    ran, bad = run_tests()
    res.append({"mutant": "original code (control)", "file": "-", "tests_run": ran, "tests_failing": bad, "caught": bad == 0})
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(HERE, "results", "mutation.json"), "w"), indent=1)
    print(res[-1])


if __name__ == "__main__":
    main()
