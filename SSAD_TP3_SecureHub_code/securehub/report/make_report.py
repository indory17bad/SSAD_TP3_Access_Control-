"""Builds report/Full_Report.pdf (black and white, no screenshots).

    python benchmark.py ; python mutation_check.py ; python report/make_charts.py ; python report/make_report.py
Every measured number is read from results/*.json; tables of rules, thresholds and views are generated from the code.
"""
import html
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (Image, KeepTogether, PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle)

from lake import policy
from lake.catalog import COLUMNS
from securehub import detect

R = json.load(open(os.path.join(ROOT, "results", "benchmark.json")))
M = json.load(open(os.path.join(ROOT, "results", "mutation.json")))
BLACK = colors.black
base = ParagraphStyle("base", fontName="Helvetica", fontSize=10.3, leading=14.2, textColor=BLACK, spaceAfter=4)
title = ParagraphStyle("title", parent=base, fontName="Helvetica-Bold", fontSize=16, leading=20, alignment=1)
sub = ParagraphStyle("sub", parent=base, fontSize=11, alignment=1)
h1 = ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=13.5, leading=17, spaceBefore=9, spaceAfter=6, keepWithNext=1)
h2 = ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=11.3, leading=15, spaceBefore=8, spaceAfter=3, keepWithNext=1)
bul = ParagraphStyle("bul", parent=base, leftIndent=14, bulletIndent=2, spaceAfter=2)
cell = ParagraphStyle("cell", parent=base, fontSize=8.8, leading=11.2, spaceAfter=0)
cellb = ParagraphStyle("cellb", parent=cell, fontName="Helvetica-Bold")
cap = ParagraphStyle("cap", parent=base, fontSize=9, leading=11.5, alignment=1)
code = ParagraphStyle("code", fontName="Courier", fontSize=7.9, leading=10, textColor=BLACK)
note = ParagraphStyle("note", parent=base, fontSize=9.3, leading=12.5, leftIndent=8, borderPadding=4)


def esc(t):
    return html.escape(str(t), quote=False)


def K(t):
    return '<font face="Courier" size="8.8">%s</font>' % esc(t)


def P(t, s=base):
    return Paragraph(t, s)


def H1(t):
    return P(esc(t), h1)


def H2(t):
    return P(esc(t), h2)


def B(items):
    return [Paragraph(i, bul, bulletText="-") for i in items]


def C(text):
    return Preformatted(text, code)


def table(rows, widths, raw=False):
    data = [[P(str(c) if raw else esc(c), cellb if r == 0 else cell) for c in row] for r, row in enumerate(rows)]
    t = Table(data, colWidths=[w * cm for w in widths], repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.7, BLACK), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]))
    return [t, Spacer(1, 6)]


def figure(name, width_cm, caption):
    from PIL import Image as PILImage
    path = os.path.join(ROOT, "results", name)
    w, h = PILImage.open(path).size
    return [KeepTogether([Image(path, width=width_cm * cm, height=width_cm * cm * h / w), P(esc(caption), cap)]), Spacer(1, 6)]


def ms(x):
    return "%.0f ms" % x if x < 1000 else "%.1f s" % (x / 1000.0)


def tsec(s):
    return "%.1f us" % (s * 1e6) if s < 1e-3 else ("%.2f ms" % (s * 1e3) if s < 1 else "%.2f s" % s)


def counts():
    out = {}
    for mod in ("test_core", "test_lake", "test_api", "test_frontend"):
        suite = unittest.defaultTestLoader.loadTestsFromName("tests." + mod)
        out[mod] = suite.countTestCases()
    return out


NT = counts()
TOTAL = sum(NT.values())

MEMBERS = ["Bensalma Feriel Imane (team lead)", "Ammi Said Hadjer", "Nour fedoua Djeghali", "Daghor Sarra", "Abid Ibrahim"]


def cover(subtitle):
    s = [P("<b>SSAD course</b>", ParagraphStyle("l", parent=base, spaceAfter=0)),
         P("Prof NACER - University year: 2026-2027 - U.S.T.H.B"), Spacer(1, 6),
         P("Practical work no3 (Access control)", title),
         P("SecureHub: documents and a data lake protected by RBAC, ABAC, RSA-signed tokens and an audit trail", sub),
         P("<b>%s</b>" % subtitle, sub)]
    s.append(P("Team: " + MEMBERS[0], sub))
    s += [P(m, sub) for m in MEMBERS[1:]]
    s += [Spacer(1, 8), P("Group: E", sub), Spacer(1, 8)]
    return s


def build(filename, story, label):
    def footer(c, d):
        c.saveState()
        c.setFont("Helvetica", 8.5)
        c.drawString(2 * cm, 1.2 * cm, label)
        c.drawRightString(A4[0] - 2 * cm, 1.2 * cm, "page %d" % d.page)
        c.restoreState()
    SimpleDocTemplate(os.path.join(HERE, filename), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.8 * cm,
                      bottomMargin=2 * cm, title=label).build(story, onFirstPage=footer, onLaterPages=footer)
    print("wrote", filename)


def story():
    kg = {k["bits"]: k for k in R["rsa"]["keygen"]}
    sv = {k["bits"]: k for k in R["rsa"]["sign_verify"]}
    pb = {r["iterations"]: r["ms"] for r in R["pbkdf2"] if "iterations" in r}
    md5_us = [r for r in R["pbkdf2"] if "md5_us" in r][0]["md5_us"]
    L = R["lake"]["sizes"]
    A = R["attacks"]
    s = cover("Full report")

    # ------------------------------------------------------------------ 1
    s.append(H1("1. Introduction and objective"))
    s.append(P("Access control answers three questions: <b>who are you</b> (authentication), <b>what may you do</b> (authorization) and "
               "<b>what did you do</b> (accountability). The practical work offered three web projects; we built them as the three steps of one "
               "platform, <b>SecureHub</b>, so that a single request can be followed from the login to the alarm. Because the course is Big Data, "
               "we added a fourth layer: fine-grained access control (ABAC) on a <b>data lake</b>, enforced on Apache Spark, with a benchmark "
               "from 1 MB to 1 GB."))
    s += table([["Project of the assignment", "Where it lives in SecureHub", "Section"],
                ["1. Secure portal: document management with RBAC and hashing; the API filters access to documents", "Login with salted PBKDF2; roles student, teacher, administrator; document list filtered by the API; object-level check", "3, 4"],
                ["2. Audit log web: every HTTP request, allowed or refused, recorded and shown in real time to the administrator", "Hash-chained log, 8 detection rules, live dashboard over server-sent events, attack lab", "6"],
                ["3. Crypto token API: the authentication server signs a token, the API verifies the signature", "RSA key generation (Miller-Rabin), PKCS#1 v1.5 signature, RS256-style token, checked by the gateway", "3"],
                ["Added for Big Data: access control on a data lake", "ABAC policy engine, row filtering, masking, hashing, query rewriting, Spark and pure-Python engines, Spark window detection, benchmark", "5"]],
               [6.3, 8.2, 2.5])
    s.append(P("Everything runs on one local machine with one command. Every number in this report comes from a run of the code (benchmark.py, "
               "mutation_check.py, the test suite) on a %d-core machine with Python %s, PySpark %s and Java %s; nothing was typed in by hand. "
               "<b>Important limit:</b> the RSA code is a teaching implementation and the Spark engine is a single machine, not a cluster; "
               "section 9 lists what the work does not prove." % (R["meta"]["cpus"], R["meta"]["python"], R["meta"].get("pyspark", "-"), R["meta"].get("java", "-"))))
    s += figure("chart_architecture.png", 15.2, "Figure 1 - Architecture: one gateway in front of the document service and the data lake; every decision is logged.")

    # ------------------------------------------------------------------ 2
    s.append(H1("2. Access control: the ideas we rely on"))
    s.append(P("<b>Reference monitor.</b> A single component that mediates every access (<i>complete mediation</i>), cannot be bypassed or tampered "
               "with, and is small enough to be checked. In SecureHub this is the gateway; the document service even refuses any call that does not "
               "carry an HMAC proof that only the gateway can compute, so a direct call is not a way around it (test: direct call returns 401 and raises an alert)."))
    s += table([["Principle", "Meaning", "How the platform applies it"],
                ["Default deny", "what is not explicitly allowed is refused", "unknown role, unknown column and unknown action are all refused"],
                ["Least privilege", "give the minimum needed", "a student sees only enrolled lectures and own grades; a doctor only own department"],
                ["Separation of duties", "the one who runs the system does not read the data", "the administrator cannot read exams, grades or patients"],
                ["Defence in depth", "several independent checks", "gateway check, then document-service re-check, then audit and detection"],
                ["Accountability", "every action leaves a trace that cannot be silently changed", "hash-chained audit log"]],
               [3.3, 5.7, 8.0])
    s.append(P("<b>Models.</b> <i>DAC</i> lets owners grant rights (not used). <i>MAC</i> uses labels and clearances (we borrow the idea in the column "
               "sensitivity levels). <b>RBAC</b> grants rights to roles and roles to users: simple, auditable, but too coarse when two people of the same role "
               "must see different things. <b>ABAC</b> decides from attributes of the user, the resource and the context; we use it where RBAC is not "
               "enough (documents: owner and course; data lake: department, purpose, column sensitivity, network zone). <b>BOLA</b> (broken object-level "
               "authorization, number one in the OWASP API Security list) is the flaw of checking the role but not the object: an authenticated student "
               "asks for <i>/api/documents/5</i>, which is another student's grade, and the server answers because the role is valid. The attack lab shows "
               "both the refusal and, with the object check deliberately removed, the leak."))

    # ------------------------------------------------------------------ 3
    s.append(H1("3. Authentication: passwords, RSA and signed tokens"))
    s.append(H2("3.1 Passwords: salted, slow, constant-time"))
    s.append(P("The user file never stores a password. It stores <font face='Courier' size='8.8'>pbkdf2_sha256$iterations$salt$hash</font>: a random 16-byte "
               "salt (two users with the same password get different hashes) and PBKDF2-HMAC-SHA256 with 100 000 iterations. Verification compares in constant time. "
               "Login answers the same message for an unknown user and a wrong password, and a dummy hash is verified for unknown users so that both cost the same time. "
               "After 5 failures in 60 s the account is locked (HTTP 429), also for names that do not exist, so the lock does not reveal which names exist."))
    s += table([["Hash", "Time for one password (measured)"],
                ["MD5, no salt (the weak way, shown in the lab for contrast)", "%.2f us" % md5_us],
                ["PBKDF2 1 000 iterations", ms(pb[1000])], ["PBKDF2 10 000", ms(pb[10000])],
                ["PBKDF2 100 000 (our default)", ms(pb[100000])], ["PBKDF2 600 000", ms(pb[600000])], ["PBKDF2 1 000 000", ms(pb[1000000])]],
               [11.0, 6.0])
    s.append(P("An attacker who steals the file pays this time for <i>every guess</i>: at 100 000 iterations one guess costs about %.0f thousand times what an MD5 guess costs, "
               "which is the whole point of slow hashing. A login costs the honest user %s, which is acceptable." % (pb[100000] * 1000 / md5_us / 1000, ms(pb[100000]))))
    s.append(H2("3.2 RSA, step by step"))
    s += B(["Choose two large primes <i>p</i> and <i>q</i>; <i>n = p q</i> and <i>phi(n) = (p-1)(q-1)</i>.",
            "Choose <i>e</i> coprime with phi(n) (we use 65537); compute <i>d = e<super>-1</super> mod phi(n)</i>. Public key (n, e); private key d.",
            "Signing: <i>s = h<super>d</super> mod n</i>, where h is the padded hash of the message. Verifying: <i>s<super>e</super> mod n = h</i>.",
            "<b>Worked toy example</b> (checked by the code and by a test): p = 61, q = 53 gives n = 3233, phi = 3120; with e = 17 we get d = 2753. "
            "Message 65 is signed as 65<super>2753</super> mod 3233 = 588, and 588<super>17</super> mod 3233 = 65."])
    s.append(P("<b>Prime generation.</b> Candidates are tested with the Miller-Rabin test (40 rounds). Tests check that it rejects the Carmichael numbers "
               "561, 1105, 1729, 41041 and 825265, which fool the simpler Fermat test."))
    s.append(P("<b>Why textbook RSA is unsafe, and what we did about it.</b> Without padding, signatures are multiplicative: from the signatures of 5 and 7 anybody "
               "builds a valid signature of 35 that nobody signed (the RSA lab panel does it, and a test proves it). Tokens therefore use SHA-256 and PKCS#1 v1.5 padding "
               "(RFC 8017), and a second test proves that the same multiplication trick fails against the padded signature. Tiny keys fall to factoring: the lab factors "
               "n = 3233 and recovers d instantly. Our verifier re-encodes the expected padded block and compares it, instead of parsing the decrypted block, which avoids a family of "
               "parsing attacks."))
    s += figure("chart_rsa_cost.png", 15.2, "Figure 2 - Measured cost of key generation, signing and verification by key size (logarithmic axis).")
    s.append(P("Signing uses the large private exponent and is slow; verifying uses e = 65537 and is fast (%s against %s at 1024 bits). This asymmetry suits an API: "
               "the auth server signs once per login, the gateway verifies on every request. Key generation for 2048 bits took %s (median of %d runs), far above 1024 bits "
               "(%s), and our pure-Python code is slower than OpenSSL, which is why it is a teaching tool." % (tsec(sv[1024]["verify_ms"] / 1000), tsec(sv[1024]["sign_ms"] / 1000), tsec(kg[2048]["median_s"]), kg[2048]["runs"], tsec(kg[1024]["median_s"]))))
    s.append(P("<b>Interoperability with OpenSSL (link to TP2).</b> The server exports its public key as a PEM file (ASN.1 DER written by hand) and the lab asks OpenSSL "
               "(%s) to verify a signature produced by our Python code; the answer is <i>Verified OK</i>, and a test also checks that OpenSSL refuses a modified message. "
               "That is the strongest evidence that our implementation follows the standard." % esc(R["rsa"].get("openssl_version", "OpenSSL"))))
    s.append(H2("3.3 The token"))
    s += figure("chart_token.png", 15.2, "Figure 3 - Token structure and the order of the gateway's checks.")
    s.append(P("The payload is only <b>encoded</b> (base64url), not encrypted: anyone can read it, but nobody can change it without breaking the signature. "
               "Claims: <i>sub</i> (who), <i>role</i>, <i>iss</i>, <i>aud</i> (which service), <i>iat</i> and <i>exp</i> (validity, 15 minutes), <i>jti</i> (unique id, used to revoke at logout) and, "
               "in the header, <i>kid</i> (which key signed it, so keys can be rotated). Verification order matters: structure, then the algorithm from <b>our own allow-list</b> "
               "(never from the token), then the key, then the signature, then the claims."))
    s += table([["Attack on tokens", "What the attacker does", "Defence in the code", "Test result"],
                ["Edited payload", "student changes role to administrator, keeps old signature", "signature no longer matches", "401 bad_signature"],
                ["alg = none", "declares no algorithm, empty signature", "algorithm allow-list: only RS256", "401 alg_not_allowed"],
                ["Algorithm confusion", "declares HS256 hoping the public key is used as secret", "same allow-list", "401 alg_not_allowed"],
                ["Expired token reuse", "replays an old valid token", "exp checked against server clock", "401 expired (boundary tested)"],
                ["Wrong audience", "token meant for another service", "aud must equal securehub-api", "401 wrong_audience"],
                ["Stolen token", "uses a token copied from the victim", "short life, logout revokes jti, rotation retires keys", "401 revoked / retired_key"],
                ["Unknown key id", "invented kid", "key must be in the key ring", "401 unknown_kid"]],
               [3.0, 5.0, 5.0, 4.0])
    s.append(P("<b>RSA or HMAC for tokens?</b> With HMAC (HS256) every service that verifies a token also holds the secret that can create one. With RSA only the auth server holds "
               "the private key; the gateway needs only the public key. The price is speed and a bigger token (%d signature bytes at 1024 bits)." % 128))

    # ------------------------------------------------------------------ 4
    s.append(H1("4. Authorization: RBAC and object rules on documents"))
    s.append(P("Two levels are applied, and both are needed. <b>Level 1 (function)</b>: may this <i>role</i> perform this action at all? <b>Level 2 (object)</b>: may <i>this user</i> touch <i>this "
               "document</i>? The list endpoint is filtered by the same rules, so a student never even sees the titles of documents that are not theirs."))
    s += table([["Role", "List", "Read", "Create", "Delete", "Audit / lab"],
                ["student", "yes (filtered)", "lectures of own courses, own grades", "no", "no", "no"],
                ["teacher", "yes (filtered)", "lectures, exams, grades of own courses", "in own courses", "no", "no"],
                ["administrator", "all titles", "lectures and admin documents only", "no", "any document", "yes"]],
               [2.6, 2.4, 5.3, 2.4, 2.1, 2.2])
    s.append(P("The administrator <b>cannot</b> read exams or grades (separation of duties): a refusal with reason <i>separation_of_duties</i>. "
               "A forbidden object answers 403, a missing one 404; this lets an attacker tell the two apart and enumerate ids, so a configuration flag (HIDE_EXISTENCE) answers 404 "
               "for both while the log keeps the real reason. The enumeration attack of the lab (ids 1 to 30) triggers the rule <i>object_enumeration</i>."))

    # ------------------------------------------------------------------ 5
    s.append(H1("5. Big Data: fine-grained access control on a data lake"))
    s.append(P("A data lake holds large tables used by several teams. Our example is a hospital table of %d columns. RBAC answers only \"may a doctor use the lake?\"; "
               "ABAC answers \"which columns and which rows, for which purpose, from where?\"." % len(COLUMNS)))
    s.append(H2("5.1 Attributes and rules"))
    s += table([["Attribute family", "Attributes used"],
                ["Subject (user)", "role (doctor, analyst, administrator), department (service), allowed purposes"],
                ["Resource (column)", "sensitivity 0 public, 1 internal, 2 confidential, 3 restricted; tags identifier, pii, health, financial"],
                ["Context (request)", "declared purpose (care, research, statistics, maintenance); network zone (internal or external, from the source address)"]],
               [3.5, 13.5])
    rows = [["Rule", "Effect", "Who / purpose / zone", "Columns", "Then"]]
    for r in policy.RULES:
        who = "/".join(r.get("role") or ["anyone"]) + " / " + ("/".join(r["purpose"]) if r.get("purpose") else ("not " + "/".join(r["purpose_not"]) if r.get("purpose_not") else "any")) + " / " + "/".join(r.get("zone") or ["any"])
        rows.append([r["id"], r["effect"], who, ", ".join("%s %s" % (k, v) for k, v in r["columns"].items()) or "all", r["obligation"] or "deny"])
    s += table(rows, [1.2, 1.6, 6.0, 5.6, 2.6])
    s.append(P("<b>Conflict resolution.</b> (1) <b>Deny-overrides</b>: one applicable deny beats any number of permits; for example P1 would let a doctor read every column, but D2 denies billing columns to doctors, so "
               "<i>treatment_cost</i> is refused (the explanation panel marks this as a conflict). (2) Among permits, the <b>most protective obligation</b> wins (hash over mask over clear). (3) <b>Default deny</b>. "
               "Constraints per role: the analyst may only run <i>aggregate</i> queries, groups with fewer than k = 5 rows are removed, and every role has a row cap per query (doctor 100, analyst 1000, administrator 50)."))
    s.append(H2("5.2 One table, three views"))
    people = {"doctor": ({"username": "d", "role": "doctor", "service": "cardiology", "purposes": ["care"]}, "care", "internal"),
              "analyst": ({"username": "a", "role": "analyst", "service": None, "purposes": ["research"]}, "research", "internal"),
              "administrator": ({"username": "r", "role": "administrator", "service": None, "purposes": ["maintenance"]}, "maintenance", "internal")}
    rows = [["Column", "Sensitivity", "Doctor", "Analyst", "Administrator"]]
    for c in COLUMNS.values():
        rows.append([c["name"], c["sensitivity"]] + [policy.column_decision(sub, pur, z, c)["outcome"] for sub, pur, z in people.values()])
    s += table(rows, [3.6, 2.2, 3.4, 3.4, 4.0])
    s.append(P("The table is generated by running the policy engine, not typed. From outside the hospital network the doctor's confidential columns are masked and restricted ones denied (tested)."))
    s.append(H2("5.3 Enforcement on Spark: filtering, masking, hashing, rewriting"))
    s += B(["<b>Row filtering</b>: the doctor's query receives the predicate <i>service = 'cardiology'</i>.",
            "<b>Column masking</b>: names become initials, the national id keeps the last 4 digits, the birth date becomes the year, the cost becomes a range, free text becomes ***.",
            "<b>Hashing</b>: identifiers become <i>substring(sha2(concat(secret, value), 256), 1, 12)</i>, a stable pseudonym: counting distinct patients still works, identifying them does not.",
            "<b>Query rewriting</b>: the user's query is never executed as written. It is wrapped around a protected projection (a <i>secure view</i>) with the row filter, k-minimum and row cap added."])
    sub_a, pur_a, z_a = people["analyst"]
    q = {"group_by": ["service", "diagnosis_code"], "metrics": [{"fn": "count"}, {"fn": "count_distinct", "col": "patient_id"}], "limit": 20}
    pl = policy.plan_query(sub_a, pur_a, z_a, q)
    s.append(P("Example, analyst, purpose research. <b>The analyst asked:</b>"))
    s.append(C(policy.original_sql(q)))
    s.append(P("<b>The platform ran:</b>"))
    s.append(C(_wrap(pl["sql"]) if False else "\n".join(__import__("textwrap").wrap(pl["sql"], 118))))
    s.append(P("The same plan is executed by two engines: a pure-Python engine (always available) and PySpark. A differential test runs %d different plans through both and requires identical results "
               "(floating-point averages compared to 2 decimals); it also checks the Parquet path. This makes the pure-Python engine a reference for the Spark one." % 10))
    s.append(H2("5.4 Attacks specific to the data layer"))
    s += table([["Attack", "Defence", "Evidence"],
                ["Filter on a hidden column to test a guess (is there a patient with this national id?)", "filters are allowed only on columns returned in clear", "403 filter_on_protected_column (tests on hashed, masked and denied columns)"],
                ["Re-identification from tiny groups", "groups smaller than 5 are removed from aggregates", "test: every returned group has n >= 5; mutation 'k removed' is caught"],
                ["SQL injection through a filter value", "structured queries, allow-lists for columns, operators and functions, values limited to letters, digits and a few symbols", "6 injection strings rejected with 400 bad_value; none reaches Spark"],
                ["Dumping the table", "row cap per query; rule mass_access (500 rows in 60 s)", "attack 'mass access' detected"],
                ["Using the wrong purpose, or a restricted column", "purpose limitation; D1 and default deny", "attack 'analyst over-reach' detected"]],
               [5.2, 6.4, 5.4])
    s.append(H2("5.5 Benchmark: the cost of access control against data size"))
    s.append(P("<b>Method.</b> Synthetic records are generated, written as CSV of 1 MB, 10 MB, 100 MB and 1 GB (%s rows at 1 GB), converted to Parquet (%.0f MB on disk at 1 GB), and queried with Spark %s in local mode on %d cores. "
               "Four queries are run <i>without</i> access control (the same question on the raw table) and <i>with</i> it (policy plan, rewritten SQL), alternately, after a warm-up; the median of %d runs (3 at 1 GB) is reported. "
               "The policy decision itself takes about %.2f ms and does not depend on the data size." % (format(L[-1]["rows"], ","), L[-1]["parquet_bytes"] / 1e6, R["meta"].get("pyspark", ""), R["meta"]["cpus"], L[0]["queries"]["Q1"]["repeats"], R["policy"]["plan_ms"])))
    rows = [["Query", "Size", "Without control", "With control", "Overhead", "Rows out (without / with)"]]
    for qid in ("Q1", "Q2", "Q3", "Q4"):
        for sz in L:
            v = sz["queries"][qid]
            rows.append([qid + " " + v["label"] if sz is L[0] else qid, ("%d MB" % sz["mb"]) if sz["mb"] < 1000 else "1 GB", ms(v["baseline_ms"]), ms(v["controlled_ms"]), "%+.0f %%" % v["overhead_pct"], "%d / %d" % (v["rows_baseline"], v["rows_controlled"])])
    s += table(rows, [5.4, 1.5, 2.6, 2.6, 2.0, 2.9])
    s += figure("chart_lake_overhead.png", 15.4, "Figure 4 - Query time with and without access control (left) and relative overhead (right), by dataset size.")
    q2g, q3g, q1g, q4g = (L[-1]["queries"][k] for k in ("Q2", "Q3", "Q1", "Q4"))
    s.append(P("<b>Reading the results.</b> (1) At 1 MB and 10 MB every query takes about 0.1 to 0.4 s, which is almost entirely fixed Spark cost (planning and scheduling a job); "
               "differences of a few tens of milliseconds there are <b>noise</b>, and we do not interpret them (the individual runs are stored in the results file). "
               "(2) At 1 GB the queries that must transform every row pay for it: Q2 (hash of patient_id inside a distinct count) %+.0f %%, Q3 (grouping by the hash of every row) %+.0f %%. "
               "(3) Q1 and Q4, which need no per-row transformation, cost %+.0f %% and %+.0f %%: access control by row filter and projection is almost free. "
               "(4) The overhead is therefore a function of <i>what the policy makes the engine compute</i> (hashing is the expensive part), not of a fixed tax per query." % (q2g["overhead_pct"], q3g["overhead_pct"], q1g["overhead_pct"], q4g["overhead_pct"])))
    s.append(P("<b>Spark against plain Python.</b> On the 100 MB file the pure-Python engine needed %s to load the CSV and %s for Q2, against %s for Spark on Parquet; it was not run at 1 GB (the rows would not fit comfortably in memory). "
               "The comparison mixes two formats (CSV rows in memory against columnar Parquet), so it shows the direction, not a precise factor." % (tsec(L[2]["python_engine"]["load_s"]), tsec(L[2]["python_engine"]["q2_s"]), ms(L[2]["queries"]["Q2"]["controlled_ms"]))))

    # ------------------------------------------------------------------ 6
    s.append(H1("6. Accountability: audit log and intrusion detection"))
    s.append(P("Every request to the platform, <b>allowed or refused</b>, is written to the log with time, source address, user (or attempted name), role, method, path, status, decision, reason and, "
               "for the lake, the purpose and the number of rows returned. Each entry stores the hash of the previous one and its own hash over its content (SHA-256), forming a chain. "
               "The administrator dashboard receives entries as they happen (server-sent events), shows counters and alerts, and can verify the chain."))
    s += figure("chart_hashchain.png", 15.2, "Figure 5 - Hash chain: an edited entry is detected at the first broken link.")
    s.append(P("Tests: an edited entry, a deleted middle entry, an inserted entry and a recomputed single hash are all detected and the first bad entry is reported. <b>Known limit, tested and stated:</b> deleting the "
               "<i>last</i> entries leaves a valid chain; only a head hash written down elsewhere reveals it (the dashboard displays it for that purpose)."))
    s += figure("chart_sequence.png", 15.2, "Figure 6 - Life of one request: login, token, gateway checks, service call, log entry, detection.")
    s.append(H2("6.1 Detection rules"))
    d = detect.DEFAULTS
    rows = [["Rule", "Fires when (default)", "Why this rule"],
            ["brute_force", "%d failed logins in %d s from one address or for one name" % (d["brute_force"]["count"], d["brute_force"]["window"]), "password guessing"],
            ["token_tampering", "%d token or gateway proof failing its cryptographic check" % d["token_tampering"]["count"], "forged or edited credentials; one event is enough"],
            ["privilege_escalation", "%d role-level refusals by one user in %d s" % (d["privilege_escalation"]["count"], d["privilege_escalation"]["window"]), "a user probing actions the role may never do"],
            ["object_enumeration", "%d different ids refused or missing in %d s" % (d["object_enumeration"]["count"], d["object_enumeration"]["window"]), "guessing document ids (BOLA hunting)"],
            ["request_burst", "%d requests in %d s from one address" % (d["request_burst"]["count"], d["request_burst"]["window"]), "scripted flooding"],
            ["expired_reuse", "%d expired-token uses in %d s" % (d["expired_reuse"]["count"], d["expired_reuse"]["window"]), "replay of old tokens"],
            ["mass_access", "%d lake rows read by one user in %d s" % (d["mass_access"]["rows"], d["mass_access"]["window"]), "data dumping, even by a legitimate account"],
            ["repeated_denied", "%d refused lake queries in %d s" % (d["repeated_denied"]["count"], d["repeated_denied"]["window"]), "an insider testing the limits of the policy"]]
    s += table(rows, [3.4, 7.4, 6.2])
    s.append(P("We chose <b>rule-based</b> detection rather than machine learning: every alert is explained by one sentence and one threshold, which suits an audit context, and no training data is needed. "
               "The weakness is that a patient attacker who stays below every threshold is not seen."))
    s.append(H2("6.2 Detection with time windows on Spark"))
    s.append(P("The two lake rules also exist as a batch job over the exported log: events are grouped by user and by a <b>sliding window</b> of 60 s that moves every 10 s (Spark <i>window()</i>), "
               "summing rows returned and counting refusals per window. A plain-Python version enumerates the same epoch-aligned windows. Tests plant an attacker who reads 1 200 rows in 20 s and another who is refused four times, hide them in 5 000 normal "
               "entries, and require that both engines find exactly them and nobody else, including a user who reads the same rows spread over six minutes."))
    w = R["window"]
    s += table([["Log entries", "File size", "Plain Python", "Spark (local, 2 cores)", "Same alerts?"]] +
               [[format(r["entries"], ","), "%.1f MB" % r["file_mb"], tsec(r["python_s"]), tsec(r["spark_s"]), "yes" if r["same_alerts"] else "NO"] for r in w], [3.2, 2.6, 3.2, 4.4, 3.0])
    s += figure("chart_window.png", 9.6, "Figure 7 - Time from the exported log to the alerts, by log size.")
    s.append(P("<b>Honest result:</b> on this one machine Spark did <i>not</i> beat plain Python (%s against %s at %s entries); its fixed start-up cost dominates up to at least a million lines, "
               "and the plain script is single-threaded but simple. Spark's value is that the same code keeps working when the log no longer fits on one machine; this experiment does not show that crossover." % (tsec(w[-1]["spark_s"]), tsec(w[-1]["python_s"]), format(w[-1]["entries"], ","))))
    s.append(H2("6.3 Thresholds and false alarms"))
    s.append(P("A threshold too low raises alarms on honest users. We simulated %s requests of %d users who sometimes mistype a password or click a document that is not theirs (<b>synthetic traffic, our assumptions</b>), "
               "and counted false alerts per 10 000 requests while lowering each threshold." % (format(R["fp"]["requests"], ","), R["fp"]["users"])))
    s += figure("chart_fp.png", 15.4, "Figure 8 - False alerts on simulated honest traffic, by threshold (default thresholds: 5, 3, 8 and 30).")
    s.append(P("The defaults sit just above the point where honest behaviour starts to alarm (for example three distinct refused ids already trigger the enumeration rule on honest users, eight do not). "
               "These numbers depend on the assumed behaviour; on real traffic the thresholds must be measured again."))
    s.append(H2("6.4 Attack lab results"))
    rows = [["Attack", "Expected alert", "Alerts fired", "Result"]]
    for a in A["attacks"]:
        rows.append([a["title"], a["expected"] or "(must be refused)", ", ".join(a["fired"]) or "none", "pass" if a["passed"] else "FAIL"])
    s += table(rows, [5.6, 3.6, 5.2, 2.6])
    s.append(P("%d of %d attacks were detected or blocked as expected. A run of normal traffic by the 8 demo users (%d requests, including a typo in a password and a click on a forbidden document) raised %d alerts. "
               "After all this traffic the hash chain of %d entries verified correctly." % (A["passed"], A["total"], A["benign"]["requests"], A["benign"]["alerts"], A["log_entries"])))
    s.append(P("Each attack is sent through the real gateway as ordinary HTTP requests from a simulated source address (the header <i>X-Sim-IP</i> exists only for the lab and can be disabled by a setting), and is flagged <i>lab</i> in the log."))

    # ------------------------------------------------------------------ 7
    s.append(H1("7. The web application"))
    s.append(P("Start with <font face='Courier' size='8.8'>python server.py --open</font> (127.0.0.1 only). A login window opens; the demo accounts are listed in the window. Tabs: "
               "<b>Home</b> (the three questions and a 5-minute demonstration); <b>Token</b> (decode your token, edit the payload and see the gateway refuse it); <b>Documents</b> (filtered list, open by id to try another user's document, create as teacher, delete as administrator); "
               "<b>Data lake</b> (purpose, network zone and engine choice, preset and editable queries, decision per column with the rule that decided, original SQL beside the rewritten SQL, results, and for the administrator the same query answered for three identities); "
               "<b>Dashboard</b> (live feed, alerts, hash-chain verification, simulated log tampering, key rotation); <b>Attack lab</b> (12 attacks, normal-traffic run); <b>RSA lab</b> (toy keys, forgery without padding, factoring, OpenSSL check). "
               "A strip at the bottom shows every request the page sends and how the gateway answered, so the teacher sees the access control working."))
    s += table([["Account", "Role", "Notes"],
                ["alice, bob", "student", "alice follows SSAD and NET, bob only SSAD"],
                ["carol, dave", "teacher", "carol teaches SSAD, dave NET"],
                ["root", "administrator", "audit, lab, keys; cannot read exams or patients"],
                ["dr_amine, dr_sofia", "doctor", "cardiology and oncology"],
                ["lina", "analyst", "purposes research and statistics"]], [3.6, 3.2, 10.2])
    s.append(P("Passwords of the demo accounts are shown in the login window of the lab only. A real deployment would remove them (setting SHOW_DEMO_USERS) and the simulated-address header."))

    # ------------------------------------------------------------------ 8
    s.append(H1("8. Tests"))
    s.append(P("The suite has <b>%d tests</b> (%d on cryptography, tokens, passwords, RBAC, audit and detection; %d on the data lake; %d on the HTTP API and the attack lab; %d in a real browser with Playwright). "
               "They cover boundaries (4 failures do not alert, 5 do), both success and refusal paths, injection strings, the equality of the Python and Spark engines, and the 12 attacks." % (TOTAL, NT["test_core"], NT["test_lake"], NT["test_api"], NT["test_frontend"])))
    s.append(P("<b>Do the tests really protect the rules?</b> A passing suite proves little if it cannot fail. We therefore broke the code on purpose, one security rule at a time, and counted the failing tests (script mutation_check.py):"))
    s += table([["Deliberate defect", "Tests run", "Tests failing", "Caught"]] +
               [[m["mutant"], m["tests_run"], m["tests_failing"], "yes" if m["caught"] else "NO"] for m in M], [8.6, 2.4, 3.0, 3.0])
    s.append(P("The last row is the control: the original code with all tests passing (0 failing is the correct result there)."))

    # ------------------------------------------------------------------ 9
    s.append(H1("9. Limits and critical discussion"))
    s += B(["<b>The RSA is not for real security.</b> It is pure Python, not constant-time, with no protection against side channels; the key file of the lab is stored in plain text. It is acceptable to teach and to compare with OpenSSL, not to deploy.",
            "<b>One process.</b> Authentication server, gateway and services run in one Flask process so that one command starts the lab. A real system separates them; the HMAC proof only simulates the trust between gateway and service.",
            "<b>Simulated addresses.</b> The zone (internal or external) and the attack lab use a header that any client can set. In production the zone must come from the network, not from a header.",
            "<b>Hashes are pseudonyms, not anonymity.</b> The pepper is a fixed string in the lab; whoever knows it and a candidate value can test a guess. A keyed hash (HMAC) with a secret in a vault is the correct form; a minimum group size does not stop every inference attack either.",
            "<b>The benchmark is one machine.</b> Spark ran locally on %d cores, not on a cluster; data is synthetic; small-size differences are noise; Q2 and Q3 overheads depend on hashing and will differ with other data." % R["meta"]["cpus"],
            "<b>Spark did not win everywhere.</b> For the window detection plain Python was as fast or faster up to a million log lines; we report this rather than hide it.",
            "<b>Detection is thresholds.</b> A slow attacker stays below them; the false-alarm study uses simulated, not real, behaviour.",
            "<b>The audit log can lose its tail</b> without the chain noticing, unless the head hash is kept elsewhere.",
            "<b>Scope.</b> Not covered: HTTPS and certificates, multi-factor login, a real database server, password reset, anomaly detection by machine learning, the full XACML standard for ABAC."])

    # ------------------------------------------------------------------ 10
    s.append(H1("10. Conclusion"))
    s.append(P("Authentication, authorization and accountability are three separate answers that only protect when chained: a perfect signature is useless if the role check is skipped, and a perfect role check cannot be trusted if it leaves no trace. "
               "SecureHub shows the chain on documents (RBAC with object rules) and on a data lake (ABAC with deny-overrides, masking, hashing and query rewriting on Spark), proves it with %d tests plus deliberate-defect checks, and measures the price: "
               "the decision costs microseconds, and the data-plane cost appears only where the policy forces per-row work such as hashing (about %+.0f %% to %+.0f %% at 1 GB for our two hashing queries). "
               "The health case (doctor, analyst, administrator) shows why this matters: the three see three different views of the same table, and each view is explained and logged." % (TOTAL, q2g["overhead_pct"], q3g["overhead_pct"])))

    # ------------------------------------------------------------------ 11
    s.append(H1("11. Sources"))
    s += B(["R. Rivest, A. Shamir, L. Adleman, <i>A method for obtaining digital signatures and public-key cryptosystems</i>, 1978.",
            "RFC 8017, <i>PKCS #1: RSA Cryptography Specifications v2.2</i> (signature padding).",
            "RFC 7519, <i>JSON Web Token</i>, and RFC 7515 (JWS): token structure and the algorithm-confusion warnings.",
            "NIST SP 800-162, <i>Guide to Attribute Based Access Control (ABAC) Definition and Considerations</i>, 2014.",
            "D. Ferraiolo, R. Sandhu et al., <i>Proposed NIST standard for role-based access control</i>, 2001.",
            "J. P. Anderson, <i>Computer Security Technology Planning Study</i>, 1972 (reference monitor).",
            "OWASP, <i>API Security Top 10 (2023)</i>: API1 Broken Object Level Authorization; and the Password Storage Cheat Sheet.",
            "NIST SP 800-63B, <i>Digital Identity Guidelines: Authentication</i> (memorized secrets, salted slow hashes).",
            "Apache Spark documentation: SQL functions <i>window</i>, <i>sha2</i>, structured data sources (CSV, Parquet).",
            "OpenSSL documentation: <i>openssl-dgst</i> and <i>openssl-genrsa</i> (signature check used in the interoperability test)."])
    s.append(PageBreak())
    s.append(H1("Appendix: files of the code archive"))
    s += table([["Path", "Content"],
                ["server.py, requirements.txt, README.md", "start command, dependencies, guide for the teacher"],
                ["securehub/rsa.py, tokens.py, passwords.py", "RSA and Miller-Rabin, token issue and verify, PBKDF2"],
                ["securehub/rbac.py, docsvc.py, store.py", "roles and object rules, document service with gateway proof, seeded data"],
                ["securehub/audit.py, detect.py, lab.py, app.py", "hash chain, 8 detection rules, attack lab, gateway and routes"],
                ["lake/catalog.py, policy.py, engines.py", "columns and sensitivity, ABAC engine and query rewriting, Python and Spark engines"],
                ["lake/data.py, spark_detect.py", "synthetic hospital data, window detection in Python and Spark"],
                ["web/index.html, style.css, app.js", "front end without any library or CDN"],
                ["tests/ (%d tests)" % TOTAL, "core, lake, API and browser tests"],
                ["benchmark.py, mutation_check.py, report/", "measurements, deliberate-defect check, charts and this report"]], [6.4, 10.6])
    return s


if __name__ == "__main__":
    build("Full_Report.pdf", story(), "SSAD TP3 - SecureHub - full report")
