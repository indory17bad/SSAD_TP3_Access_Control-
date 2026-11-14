"""Black-and-white figures for the report. Measured values are read from results/benchmark.json."""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "results")
R = json.load(open(os.path.join(OUT, "benchmark.json")))
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8.5, "axes.edgecolor": "black", "text.color": "black",
                     "xtick.color": "black", "ytick.color": "black", "axes.labelcolor": "black"})
HATCH = ["", "///", "xxx", "..."]
FILL = ["white", "0.65", "0.3", "white"]


def box(ax, x, y, w, h, text, fs=8, lw=1.2, fill="white", bold=False, ls="-"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fill, ec="black", lw=lw, ls=ls))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, fontweight="bold" if bold else "normal", linespacing=1.25)


def arrow(ax, a, b, text=None, dy=0.0, ls="-", fs=7):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=10, lw=1.1, color="black", ls=ls, shrinkA=0, shrinkB=0))
    if text:
        ax.text((a[0] + b[0]) / 2, (a[1] + b[1]) / 2 + dy, text, ha="center", va="bottom", fontsize=fs, backgroundcolor="white")


def save(fig, name):
    fig.savefig(os.path.join(OUT, name), dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("wrote", name)


def architecture():
    fig, ax = plt.subplots(figsize=(7.4, 4.3))
    ax.set_xlim(0, 10); ax.set_ylim(0, 6); ax.axis("off")
    box(ax, 0.1, 4.3, 1.8, 1.0, "Browser\n(5 roles)", bold=True)
    box(ax, 0.1, 1.9, 1.8, 1.0, "Auth server\npassword check\nRSA signs token")
    box(ax, 3.1, 3.5, 2.5, 2.2, "GATEWAY\nreference monitor\n1 verify RSA signature\n2 expiry, audience\n3 RBAC (role, action)\n4 ABAC plan / object rule", bold=True, lw=2.2)
    box(ax, 7.0, 4.7, 2.8, 1.0, "Document service\nobject rule re-checked\nneeds gateway proof")
    box(ax, 7.0, 3.0, 2.8, 1.35, "Data lake\npolicy -> rewritten SQL\nengine A: pure Python\nengine B: PySpark")
    box(ax, 3.1, 0.2, 2.5, 1.5, "Audit log\nevery request, allowed\nor refused; hash chain")
    box(ax, 7.0, 0.2, 2.8, 1.5, "Detection (8 rules)\nlive + Spark windows\nadmin dashboard (SSE)")
    arrow(ax, (1.0, 4.3), (1.0, 2.9), "login", dy=0.05)
    arrow(ax, (1.9, 4.8), (3.1, 4.8), "token + request", dy=0.05)
    arrow(ax, (5.6, 5.2), (7.0, 5.2), "proof", dy=0.05)
    arrow(ax, (5.6, 3.9), (7.0, 3.7), "plan", dy=0.05)
    arrow(ax, (4.35, 3.5), (4.35, 1.7), "log", dy=0.0)
    arrow(ax, (5.6, 0.95), (7.0, 0.95), "feed", dy=0.05)
    arrow(ax, (1.0, 1.9), (3.1, 3.7), "public key", dy=0.1, ls="--")
    ax.text(5.0, 5.95, "Figure: one gateway in front of two services; every decision ends in the audit log", ha="center", fontsize=8, style="italic")
    save(fig, "chart_architecture.png")


def token():
    fig, ax = plt.subplots(figsize=(7.4, 2.9))
    ax.set_xlim(0, 10); ax.set_ylim(0, 4); ax.axis("off")
    box(ax, 0.1, 2.0, 2.7, 1.5, 'HEADER\n{"alg":"RS256",\n "kid":"k1"}', fs=7.5)
    box(ax, 3.2, 2.0, 3.6, 1.5, 'PAYLOAD (readable, not secret)\n{"sub":"alice","role":"student",\n "aud":"securehub-api","exp":...,\n "jti":"..."}', fs=7.2)
    box(ax, 7.2, 2.0, 2.7, 1.5, "SIGNATURE\n(padded SHA-256 of\nheader.payload)^d mod n", fs=7.5, fill="0.85")
    ax.text(3.0, 2.75, ".", fontsize=18, ha="center"); ax.text(7.0, 2.75, ".", fontsize=18, ha="center")
    arrow(ax, (1.45, 2.0), (1.45, 1.1)); arrow(ax, (5.0, 2.0), (5.0, 1.1)); arrow(ax, (8.55, 2.0), (8.55, 1.1))
    box(ax, 0.1, 0.1, 9.8, 0.95, "Gateway: 1 three parts?  2 alg is RS256 (our list, not the token's)?  3 known, active key?  4 signature ok?  5 claims: iss, aud, exp, iat?  6 jti not revoked?", fs=7.5)
    save(fig, "chart_token.png")


def sequence():
    fig, ax = plt.subplots(figsize=(7.4, 4.6))
    ax.set_xlim(0, 10); ax.set_ylim(0, 8); ax.axis("off")
    xs = {"Browser": 1, "Auth": 3.2, "Gateway": 5.4, "Service": 7.5, "Audit": 9.3}
    for n, x in xs.items():
        box(ax, x - 0.7, 7.1, 1.4, 0.65, n, fs=8, bold=True)
        ax.plot([x, x], [0.2, 7.1], color="black", lw=0.8, ls=":")
    msgs = [("Browser", "Auth", 6.5, "1 login(user, password)"), ("Auth", "Browser", 6.0, "2 RSA-signed token"),
            ("Browser", "Gateway", 5.35, "3 request + token"), ("Gateway", "Gateway", 4.85, "4 verify signature, RBAC"),
            ("Gateway", "Service", 4.2, "5 call + HMAC proof / plan"), ("Service", "Gateway", 3.6, "6 data (filtered, masked)"),
            ("Gateway", "Audit", 2.95, "7 entry + hash of previous"), ("Gateway", "Browser", 2.3, "8 response (or 401/403)"),
            ("Audit", "Audit", 1.6, "9 detection rules, live alert")]
    for a, b, y, t in msgs:
        if a == b:
            ax.annotate("", xy=(xs[a] + 0.02, y - 0.35), xytext=(xs[a] + 0.02, y), arrowprops=dict(arrowstyle="-|>", lw=1, connectionstyle="arc3,rad=-1.6"))
            ax.text(xs[a] - 0.15, y - 0.12, t, ha="right" if xs[a] > 5 else "left", fontsize=7.3, va="center")
        else:
            arrow(ax, (xs[a], y), (xs[b], y))
            ax.text((xs[a] + xs[b]) / 2, y + 0.08, t, ha="center", fontsize=7.3, backgroundcolor="white")
    save(fig, "chart_sequence.png")


def hashchain():
    fig, ax = plt.subplots(figsize=(7.4, 2.5))
    ax.set_xlim(0, 10); ax.set_ylim(0, 3.2); ax.axis("off")
    for i in range(4):
        x = 0.2 + i * 2.5
        box(ax, x, 1.1, 2.1, 1.5, "entry #%d\nuser, path, status\nprev = H(#%d)\nhash = H(prev + entry)" % (i + 1, i), fs=7.3,
            fill="0.8" if i == 2 else "white", lw=2.0 if i == 2 else 1.2)
        if i:
            arrow(ax, (x, 1.85), (x - 0.4, 1.85))
    ax.text(5.35, 0.65, "Edit entry #3 (grey): its hash no longer matches, and so do the prev links of #4 and later.", ha="center", fontsize=7.6)
    ax.text(5.35, 0.25, "Deleting the last entries is only caught if the head hash was written down elsewhere.", ha="center", fontsize=7.6, style="italic")
    save(fig, "chart_hashchain.png")


def rsa_cost():
    fig, axs = plt.subplots(1, 2, figsize=(7.4, 2.8))
    kg, sv = R["rsa"]["keygen"], R["rsa"]["sign_verify"]
    bits = [str(k["bits"]) for k in kg]
    x = range(len(bits))
    axs[0].bar(x, [k["median_s"] * 1000 for k in kg], 0.55, fc="0.6", ec="black")
    if "openssl_genrsa" in R["rsa"]:
        axs[0].bar([i + 0.3 for i in x], [k["median_s"] * 1000 for k in R["rsa"]["openssl_genrsa"]], 0.25, fc="white", ec="black", hatch="///")
    axs[0].set_yscale("log"); axs[0].set_xticks([i + 0.1 for i in x]); axs[0].set_xticklabels(bits)
    axs[0].set_xlabel("key size (bits)"); axs[0].set_ylabel("time (ms, log)"); axs[0].set_title("Key generation", fontsize=9)
    axs[0].legend(["our Python", "openssl genrsa (incl. start-up)"], fontsize=7, frameon=False, loc="upper left")
    w = 0.38
    axs[1].bar([i - w / 2 for i in x], [s["sign_ms"] for s in sv], w, fc="0.6", ec="black", label="sign")
    axs[1].bar([i + w / 2 for i in x], [s["verify_ms"] for s in sv], w, fc="white", ec="black", hatch="///", label="verify")
    axs[1].set_yscale("log"); axs[1].set_xticks(list(x)); axs[1].set_xticklabels(bits); axs[1].set_xlabel("key size (bits)")
    axs[1].set_ylabel("time (ms, log)"); axs[1].set_title("Sign (private d) and verify (public e)", fontsize=9); axs[1].legend(fontsize=7, frameon=False)
    for a in axs:
        a.spines["top"].set_visible(False); a.spines["right"].set_visible(False)
    fig.tight_layout()
    save(fig, "chart_rsa_cost.png")


def lake():
    sizes = R["lake"]["sizes"]
    labels = ["%s MB" % s["mb"] if s["mb"] < 1000 else "1 GB" for s in sizes]
    qs = ["Q1", "Q2", "Q3", "Q4"]
    fig, axs = plt.subplots(1, 2, figsize=(7.4, 3.1))
    x = range(len(sizes))
    for k, (q, ls, mk) in enumerate(zip(["Q2", "Q3"], ["-", "--"], ["o", "s"])):
        axs[0].plot(x, [s["queries"][q]["baseline_ms"] / 1000 for s in sizes], ls, marker=mk, color="black", mfc="white", label="%s without control" % q)
        axs[0].plot(x, [s["queries"][q]["controlled_ms"] / 1000 for s in sizes], ls, marker=mk, color="black", label="%s with control" % q)
    axs[0].set_xticks(list(x)); axs[0].set_xticklabels(labels); axs[0].set_yscale("log")
    axs[0].set_xlabel("dataset size (CSV equivalent)"); axs[0].set_ylabel("query time (s, log)"); axs[0].set_title("Time with and without access control", fontsize=9)
    axs[0].legend(fontsize=6.5, frameon=False)
    w = 0.2
    for i, q in enumerate(qs):
        axs[1].bar([j + (i - 1.5) * w for j in x], [s["queries"][q]["overhead_pct"] for s in sizes], w, fc=FILL[i], ec="black", hatch=HATCH[i], label=q)
    axs[1].axhline(0, color="black", lw=0.8)
    axs[1].set_xticks(list(x)); axs[1].set_xticklabels(labels); axs[1].set_xlabel("dataset size"); axs[1].set_ylabel("overhead (%)")
    axs[1].set_title("Relative overhead of access control", fontsize=9); axs[1].legend(fontsize=7, frameon=False, ncol=2)
    for a in axs:
        a.spines["top"].set_visible(False); a.spines["right"].set_visible(False)
    fig.tight_layout()
    save(fig, "chart_lake_overhead.png")


def window():
    w = R["window"]
    fig, ax = plt.subplots(figsize=(4.6, 2.9))
    n = [r["entries"] for r in w]
    ax.plot(n, [r["python_s"] for r in w], "-o", color="black", mfc="white", label="plain Python")
    ax.plot(n, [r["spark_s"] for r in w], "--s", color="black", label="Spark (window aggregation)")
    ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("audit-log entries"); ax.set_ylabel("time to alerts, from file (s)")
    ax.legend(fontsize=7.5, frameon=False); ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    ax.set_title("Window detection on the exported log", fontsize=9)
    fig.tight_layout()
    save(fig, "chart_window.png")


def fp():
    sw = R["fp"]["sweeps"]
    rules = ["brute_force", "privilege_escalation", "object_enumeration", "request_burst"]
    fig, axs = plt.subplots(1, 4, figsize=(7.4, 2.3))
    for a, r in zip(axs, rules):
        pts = [s for s in sw if s["rule"] == r]
        a.bar([str(p["threshold"]) for p in pts], [p["per_10k_requests"] for p in pts], fc="0.6", ec="black")
        a.set_title(r.replace("_", " "), fontsize=7.5); a.set_xlabel("threshold", fontsize=7.5)
        a.spines["top"].set_visible(False); a.spines["right"].set_visible(False); a.tick_params(labelsize=7)
    axs[0].set_ylabel("false alerts per 10 000 requests", fontsize=7.5)
    fig.tight_layout()
    save(fig, "chart_fp.png")


if __name__ == "__main__":
    for f in (architecture, token, sequence, hashchain, rsa_cost, lake, window, fp):
        f()
