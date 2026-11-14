# SecureHub — TP3 Access Control (Group E, SSAD, USTHB 2026-2027)

One platform that chains the three classic access-control topics:

| Step | What | Where |
|---|---|---|
| Authenticate | PBKDF2 passwords, lockout, RSA-signed tokens (own RSA implementation) | `securehub/rsa.py`, `tokens.py`, `passwords.py` |
| Authorize | RBAC + object rules + separation of duties, then ABAC with deny-overrides on a Big Data lake | `securehub/rbac.py`, `lake/policy.py` |
| Account | Hash-chained audit log, 8 detection rules, live dashboard, Spark window detection | `securehub/audit.py`, `detect.py`, `lake/spark_detect.py` |

Everything goes through one gateway (reference monitor). The document service only answers the gateway (HMAC proof).

## Requirements
- Python 3.9+ and Flask: `pip install flask`
- Optional: `pyspark==4.0.1` + Java 17/21 (Spark engine and Spark detection). **Without Spark everything still works**: a pure-Python engine runs the same query plan.
- Optional: `playwright` (browser tests), `reportlab` + `matplotlib` (rebuild the report).

## Run
```
python server.py --open          # http://127.0.0.1:8767
```
Options: `--port`, `--data-dir`, `--rows` (lake size).

## Demo accounts (lab only)
| User | Password | Role |
|---|---|---|
| alice | alice-pass-1 | student |
| bob | bob-pass-2 | student |
| carol | carol-pass-3 | teacher |
| dave | dave-pass-4 | teacher |
| root | root-pass-5 | administrator |
| dr_amine | amine-pass-6 | doctor (cardiology) |
| dr_sofia | sofia-pass-7 | doctor (oncology) |
| lina | lina-pass-8 | analyst |

## 5-minute walkthrough
1. **Home**: log in as `alice`. **Token** tab: see header/payload/signature; change one character in the payload and send it → rejected (`bad_signature`).
2. **Documents**: alice sees only her own; the administrator cannot read exams/grades (separation of duties).
3. **Data lake**: pick a preset; the page shows the per-column decision (clear / mask / hash / deny), the original SQL and the rewritten SQL. Use "same query as three identities" to compare doctor, analyst, administrator.
4. **Dashboard** (log in as `root`): press **Run all** in the **Attack lab** and watch alerts arrive live (SSE). Then "Verify chain", "Tamper log", "Verify chain" again → the break is located.
5. **RSA lab**: toy example (p=61, q=53), textbook forgery, factoring a tiny n, OpenSSL cross-check.

## Tests and benchmark
```
python -m unittest discover -s tests          # ~200 tests (frontend tests need playwright, skipped otherwise)
python benchmark.py --only lake --sizes 1,10,100   # needs PySpark; results/benchmark.json
python mutation_check.py                      # injects 8 deliberate bugs, checks tests catch them
python report/make_charts.py && python report/make_report.py
```

## Layout
```
server.py        entry point          securehub/  gateway, auth, RBAC, audit, detection, RSA
lake/            ABAC policy, engines (Python + Spark), Spark detection, data generator
web/             single-page UI (no CDN)       tests/   unit, API, differential, browser
results/         measured numbers     report/   charts + report generator
```

## Settings (in `create_app` config)
`KEY_BITS` (1024), `PBKDF2_ITER`, `TOKEN_TTL`, `LAKE_ROWS`, `ALLOW_SIM_IP` (lets the attack lab simulate source IPs with `X-Sim-IP`; **turn off outside the lab**), `SHOW_DEMO_USERS`. `OPENSSL_BIN` env var points to openssl for the interop check.

## Troubleshooting
- Port busy → `--port 8800`.
- "Spark unavailable" in the UI → Java or pyspark missing; the Python engine is used instead.
- Browser tests fail → `pip install playwright && playwright install chromium`.

## Known limits (honest list)
- RSA is a teaching implementation (not constant-time); real systems should use a vetted library.
- Deleting the *last* audit entries is not detected unless the head hash is stored elsewhere.
- Demo passwords, simulated IPs and synthetic data are for the lab only.
- Benchmarks are from a single 2-core machine; Spark gave no speed-up over Python for window detection up to 1 M entries.
