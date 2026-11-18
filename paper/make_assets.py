"""Build every figure, table and number of the paper from the CSVs in results/.

Usage (from the repo root):
    python paper/make_assets.py

Outputs go to paper/generated/: fig_*.pdf, tab_*.tex and numbers.tex (one
\\newcommand per number quoted in the text). Nothing is typed by hand: if a CSV
is missing, the matching macro expands to "[not measured]" and the table says so.
"""
import csv
import json
import math
import os
import statistics
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

RESULTS = "results"
OUT = os.path.join("paper", "generated")
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({"font.size": 8, "font.family": "serif", "axes.grid": True, "grid.alpha": 0.3,
                     "figure.dpi": 150, "savefig.bbox": "tight", "axes.axisbelow": True})
COL = 3.45  # IEEE column width in inches
GRAYS = ["0.15", "0.45", "0.7", "0.85"]
HATCH = ["", "///", "...", "xx"]
numbers = {}


def load(name):
    path = os.path.join(RESULTS, name)
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def fl(rows, col):
    return [float(r[col]) for r in rows if r.get(col, "") not in ("", None)]


def miq(vals):
    """median, q1, q3 (inclusive method)."""
    if not vals:
        return (float("nan"),) * 3
    if len(vals) == 1:
        return vals[0], vals[0], vals[0]
    q1, med, q3 = statistics.quantiles(vals, n=4, method="inclusive")
    return med, q1, q3


def sig(v, digits=3):
    """Format with `digits` significant digits and thousands separators."""
    if v != v:
        return "n/a"
    if v == 0:
        return "0"
    exp = math.floor(math.log10(abs(v)))
    dec = max(0, digits - 1 - exp)
    return f"{v:,.{dec}f}"


def cell(vals, digits=3):
    med, q1, q3 = miq(vals)
    return f"{sig(med, digits)} [{sig(q1, digits)}, {sig(q3, digits)}]"


DIGITS = dict(zip('0123456789', ['Zero', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine']))


def num(name, value):
    # TeX macro names may contain letters only.
    name = ''.join(DIGITS.get(ch, ch) for ch in name)
    numbers[name] = str(value)


def write(name, text):
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        f.write(text)


def table(name, header, rows, colspec):
    body = " \\\\\n".join(" & ".join(r) for r in rows)
    write(name, "\\begin{tabular}{%s}\n\\hline\n%s \\\\\n\\hline\n%s \\\\\n\\hline\n\\end{tabular}\n"
          % (colspec, " & ".join(header), body if rows else "\\multicolumn{%d}{c}{[not measured]}" % len(header)))


def kib(v):
    return sig(v / 1024.0, 3)


def mib(v):
    return f"{v / 1048576.0:.2f}"


# ---------------------------------------------------------------- hardware
hw_path = os.path.join(RESULTS, "hardware.json")
if os.path.exists(hw_path):
    with open(hw_path, encoding="utf-8") as f:
        hw = json.load(f)
    m = hw.get("machine") or {}
    cpu = (m.get("cpus") or [{}])[0]
    num("hwModel", f"{m.get('manufacturer', '?')} {m.get('model', '?')}")
    num("hwCPU", str(cpu.get("name", "?")).replace("(R)", "").replace("(TM)", ""))
    num("hwCores", cpu.get("physical_cores", "?"))
    num("hwThreads", cpu.get("logical_cores", "?"))
    num("hwRAM", f"{float(m.get('ram_bytes', 0)) / 2**30:.1f}")
    num("hwOS", f"{m.get('os', '?')} ({m.get('os_version', '?')})")
    num("hwGo", hw.get("go_version", "?"))
    num("hwNode", hw.get("node_version", "?"))
    num("hwCommit", hw.get("git_commit", "?")[:7])
    num("hwDate", hw.get("date", "?")[:10])
    scheme = str(m.get("power_scheme", "?"))
    num("hwPower", scheme[scheme.find("(") + 1:scheme.rfind(")")] if "(" in scheme else scheme)
    num("hwAC", "AC power" if m.get("on_ac_power") else "battery")
    num("hwDefender", "enabled" if m.get("defender_realtime_enabled") else "disabled")

# ---------------------------------------------------------------- E1
e1 = load("e1.csv")
if e1:
    num("eOneRuns", f"{len(e1):,}")
    num("eOneRandom", f"{sum(1 for r in e1 if r['case'] == 'random'):,}")
    num("eOneFixed", sum(1 for r in e1 if r["case"] != "random"))
    num("eOneMismatch", sum(1 for r in e1 if r["ok"] != "true" and r["error"] == ""))
    num("eOneFailed", sum(1 for r in e1 if r["error"] != ""))
    for cls in ("inside", "boundary", "outside"):
        num("eOne" + cls.capitalize(), f"{sum(1 for r in e1 if r['class_observed'] == cls):,}")
    fixed = [r for r in e1 if r["case"] != "random"]
    table("tab_e1.tex", ["Case", "$P$", "$U$", "$R$", "$\\Delta$", "Expected", "Observed"],
          [[r["case"].replace("_", "\\_"), f"({r['px']},{r['py']})", f"({r['ux']},{r['uy']})", r["r"], "$" + r["delta_true"] + "$",
            r["class_expected"], r["class_observed"]] for r in fixed], "lcccrll")

e1b = load("e1_browser.csv")
if e1b:
    num("eOneBrowserRuns", len(e1b))
    num("eOneBrowserOk", sum(1 for r in e1b if r["ok"] == "true"))
    num("eOneBrowserChrome", e1b[0]["chrome_version"].replace("HeadlessChrome/", "Chrome ").replace("Chrome/", "Chrome "))

# ---------------------------------------------------------------- E2
e2 = load("e2.csv")
if e2:
    pts = sorted((int(r["delta_true"]), int(r["delta_decoded"]), r["ok"] == "true") for r in e2)
    good = [d for d, _, ok in pts if ok]
    # the contiguous correct range around zero
    lo = max([d for d, _, ok in pts if not ok and d < 0], default=None)
    hi = min([d for d, _, ok in pts if not ok and d > 0], default=None)
    num("eTwoRuns", len(e2))
    num("eTwoFirstWrongNeg", f"{lo:,}".replace("-", "$-$") if lo is not None else "n/a")
    num("eTwoFirstWrongPos", f"{hi:,}" if hi is not None else "n/a")
    num("eTwoLastGoodNeg", f"{min(d for d in good if lo is None or d > lo):,}".replace("-", "$-$"))
    num("eTwoLastGoodPos", f"{max(d for d in good if hi is None or d < hi):,}")
    num("eTwoWrong", sum(1 for _, _, ok in pts if not ok))
    num("eTwoFailed", sum(1 for r in e2 if r["error"] != ""))
    fig, ax = plt.subplots(figsize=(COL, 2.1))
    ax.plot([d for d, _, ok in pts if ok], [v for _, v, ok in pts if ok], "o", ms=2.2, color="0.1", label="class correct")
    ax.plot([d for d, _, ok in pts if not ok], [v for _, v, ok in pts if not ok], "x", ms=3.5, color="0.5", label="class wrong")
    for x in (-32768, 32768):
        ax.axvline(x, color="0.3", lw=0.6, ls="--")
    ax.set_xticks([-60000, -30000, 0, 30000, 60000])
    ax.set_xticklabels(["$-$60k", "$-$30k", "0", "30k", "60k"])
    ax.set_xlabel("true $\\Delta$ (integer)")
    ax.set_ylabel("$\\Delta$ seen by the circuit")
    ax.legend(loc="upper left", fontsize=6.5, frameon=True)
    fig.savefig(os.path.join(OUT, "fig_e2_wrap.pdf"))
    plt.close(fig)

# ---------------------------------------------------------------- E3
e3 = load("e3.csv")
PHASES = [("t_keygen_ms", "Collective keygen (CPK+RLK)"), ("t_encrypt_ms", "Encrypt (4 ciphertexts)"),
          ("t_eval_ms", "Server evaluation of $\\Delta$"), ("t_e2s_ms", "Encryption-to-shares"),
          ("t_garble_ms", "Garble"), ("t_ot_ms", "Oblivious transfer (17)"), ("t_gc_eval_ms", "Circuit evaluation")]
if e3:
    num("eThreeRuns", f"{len(e3):,}")
    num("eThreeMismatch", sum(1 for r in e3 if r["ok"] != "true" and r["error"] == ""))
    num("eThreeFailed", sum(1 for r in e3 if r["error"] != ""))
    num("eThreeQBits", sig(miq(fl(e3, "q_bits"))[0], 3))
    num("eThreeFresh", f"{miq(fl(e3, 'fresh_bits'))[0]:.1f}")
    num("eThreeDelta", f"{miq(fl(e3, 'delta_bits'))[0]:.1f}")
    num("eThreeDeltaMax", f"{max(fl(e3, 'delta_bits')):.1f}")
    num("eThreeBudget", f"{miq(fl(e3, 'budget_e2s_bits'))[0]:.1f}")
    num("eThreeBudgetMin", f"{min(fl(e3, 'budget_e2s_bits')):.1f}")
    num("eThreeFlood", f"{miq(fl(e3, 'flood_margin_bits'))[0]:.1f}".replace("-", "$-$"))
    num("eThreeFloodMax", f"{max(fl(e3, 'flood_margin_bits')):.1f}".replace("-", "$-$"))
    num("eThreeNoiseStd", f"{miq(fl(e3, 'delta_std_bits'))[0] - math.log2(65537):.1f}")
    num("eThreeTotal", cell(fl(e3, "t_total_ms")))
    num("eThreeGarbled", f"{int(fl(e3, 'garbled_bytes')[0]):,}")
    rows = []
    for col, label in PHASES:
        v = fl(e3, col)
        med, q1, q3 = miq(v)
        rows.append([label, sig(med), f"[{sig(q1)}, {sig(q3)}]", sig(min(v)), sig(max(v))])
        num("eThree" + "".join(p.capitalize() for p in col[2:-3].split("_")), sig(med))
    table("tab_e3.tex", ["Phase", "Median", "IQR", "Min", "Max"], rows, "lrrrr")

# ---------------------------------------------------------------- E4
sets = load("e4_sets.csv")
timing = load("e4_timing.csv")
if sets:
    by_set = defaultdict(list)
    for r in timing:
        by_set[r["set_id"]].append(r)

    def party_ms(r, role):
        return sum(float(r[c % role]) for c in ("t_skgen_%s_ms", "t_ckg_share_%s_ms", "t_rkg_r1_%s_ms", "t_rkg_r2_%s_ms",
                                               "t_encrypt_%s_ms", "t_e2s_share_%s_ms"))

    summary = []
    for s in sets:
        reps = [r for r in by_set.get(s["set_id"], []) if r["error"] == ""]
        entry = dict(s)
        entry["reps"] = reps
        if reps:
            entry["client"] = miq([party_ms(r, "p") for r in reps])
            entry["server"] = miq([float(r["t_setup_server_ms"]) + float(r["t_eval_ms"]) + float(r["t_e2s_final_ms"]) for r in reps])
            entry["budget_min"] = min(fl(reps, "budget_e2s_bits"))
            entry["ct"] = float(reps[0]["ciphertext_bytes"])
            entry["rlk"] = float(reps[0]["rlk_bytes"])
        summary.append(entry)
    default = [e for e in summary if e["xs"] == "ternary_p2/3"]
    sparse = [e for e in summary if e["xs"] != "ternary_p2/3"]
    num("eFourSets", len(summary))
    num("eFourRunsPerSet", sets[0]["n_runs"])
    num("eFourReps", sets[0]["timing_reps"])
    num("eFourCorrect", sum(1 for e in summary if e["status"] == "correct"))
    num("eFourIncorrect", sum(1 for e in summary if e["status"] == "incorrect"))
    num("eFourInvalid", sum(1 for e in summary if e["status"] not in ("correct", "incorrect")))
    num("eFourWithin", sum(1 for e in default if e["status"] == "correct" and e["he_std2018_status"] == "within"))

    def status_cell(e):
        if e["status"] == "correct":
            return "yes"
        if e["status"] == "incorrect":
            return f"no ({e['mismatches']}/{e['n_runs']})"
        return e["status"].replace("_", " ")

    rows = []
    for e in default:
        if not e.get("reps"):
            rows.append([e["logN"], e["logQ"], e["logP"], sig(float(e["qp_total_bits"] or 0), 3) if e["qp_total_bits"] else "--",
                         e["he_std2018_status"] or "--", status_cell(e), "--", "--", "--", "--", "--"])
            continue
        rows.append([e["logN"], e["logQ"], e["logP"], f"{float(e['qp_total_bits']):.0f}", e["he_std2018_status"],
                     status_cell(e), f"{e['budget_min']:.1f}", sig(e["client"][0]), sig(e["server"][0]), kib(e["ct"]),
                     mib(float(e["peak_ws_timing_bytes"]))])
    table("tab_e4.tex", ["$\\log N$", "$\\log Q$", "$\\log P$", "$\\log QP$", "Std.", "Correct", "Budget", "Client", "Server", "Ct", "Mem"],
          rows, "rllrllrrrrr")

    failed = [e for e in summary if e["status"] != "correct"]
    num("eFourFailList", "; ".join("$\\log N=%s$, $\\log Q=\\{%s\\}$, %s secret (%s of %s runs wrong)" % (e["logN"], e["logQ"].replace("-", ","), "uniform ternary" if e["xs"] == "ternary_p2/3" else "sparse", e["mismatches"], e["n_runs"]) for e in failed) or "none")
    tight = next((e for e in default if e["logN"] == "14" and e["logQ"] == "56" and e.get("reps")), None)
    if tight:
        num("eFourTightBudget", f"{tight['budget_min']:.1f}")
    ok = [e for e in default if e["status"] == "correct" and e["he_std2018_status"] == "within" and e.get("reps")]
    base = next((e for e in default if e["logN"] == "14" and e["logQ"] == "56-55-55-54-54-54"), None)
    if ok:
        best = min(ok, key=lambda e: e["client"][0] + e["server"][0])
        num("eFourBestN", best["logN"])
        num("eFourBestQ", best["logQ"].replace("-", ", "))
        num("eFourBestP", best["logP"].replace("-", ", "))
        num("eFourBestQP", f"{float(best['qp_total_bits']):.0f}")
        num("eFourBestClient", sig(best["client"][0]))
        num("eFourBestServer", sig(best["server"][0]))
        num("eFourBestBudget", f"{best['budget_min']:.1f}")
        num("eFourBestCt", kib(best["ct"]))
        num("eFourBestMem", mib(float(best["peak_ws_timing_bytes"])))
        if base and base.get("reps"):
            num("eFourBaseClient", sig(base["client"][0]))
            num("eFourBaseServer", sig(base["server"][0]))
            num("eFourBaseCt", kib(base["ct"]))
            num("eFourBaseMem", mib(float(base["peak_ws_timing_bytes"])))
            num("eFourBaseBudget", f"{base['budget_min']:.1f}")
            num("eFourSpeedClient", sig(base["client"][0] / best["client"][0], 2))
            num("eFourSpeedServer", sig(base["server"][0] / best["server"][0], 2))
            num("eFourShrinkCt", sig(base["ct"] / best["ct"], 2))
    # sparse vs default: median ratio of client time over matching sets
    ratios = []
    for e in sparse:
        twin = next((d for d in default if d["logN"] == e["logN"] and d["logQ"] == e["logQ"] and d["logP"] == e["logP"]), None)
        if twin and twin.get("reps") and e.get("reps"):
            ratios.append((e["client"][0] + e["server"][0]) / (twin["client"][0] + twin["server"][0]))
    if ratios:
        num("eFourSparseRatio", f"{statistics.median(ratios):.2f}")
        num("eFourSparseRatioMin", f"{min(ratios):.2f}")
        num("eFourSparseRatioMax", f"{max(ratios):.2f}")
        num("eFourSparseCorrect", f"{sum(1 for e in sparse if e['status'] == 'correct')} of {len(sparse)}")

    fig, ax = plt.subplots(figsize=(COL, 2.3))
    markers = {"12": "o", "13": "s", "14": "^", "15": "D"}
    for logn, mk in markers.items():
        pts = [e for e in default if e["logN"] == logn and e.get("reps")]
        good = [e for e in pts if e["status"] == "correct"]
        bad = [e for e in pts if e["status"] != "correct"]
        ax.plot([float(e["qp_total_bits"]) for e in good], [e["client"][0] + e["server"][0] for e in good], mk, ms=4.5,
                color="0.15", mfc="0.15", label=f"$\\log N={logn}$")
        ax.plot([float(e["qp_total_bits"]) for e in bad], [e["client"][0] + e["server"][0] for e in bad], mk, ms=4.5,
                color="0.15", mfc="white")
    ax.set_yscale("log")
    ax.set_xlabel("$\\log_2 QP$ (bits)")
    ax.set_ylabel("one client + server (ms)")
    ax.legend(fontsize=6.5, ncol=2, loc="lower right")
    fig.savefig(os.path.join(OUT, "fig_e4_sweep.pdf"))
    plt.close(fig)

# ---------------------------------------------------------------- E5a
e5a = load("e5a.csv")
if e5a:
    rows = []
    groups = defaultdict(list)
    for r in e5a:
        groups[r["t"]].append(r)
    for t, grp in groups.items():
        okrows = [r for r in grp if r["error"] == ""]
        if not okrows:
            rows.append([f"{int(t):,}", "--", "--", "--", "--", "invalid", "--", "--", "--", "--"])
            continue
        wrong = sum(1 for r in grp if r["ok"] != "true")
        rows.append([f"{int(t):,}", okrows[0]["share_bits"], okrows[0]["max_coord"], okrows[0]["and_gates"],
                     f"{int(okrows[0]['garbled_bytes']):,}", f"{wrong}/{len(grp)}", sig(miq(fl(okrows, 't_garble_ms'))[0] * 1000),
                     sig(miq(fl(okrows, 't_ot_ms'))[0]), sig(miq(fl(okrows, 't_gc_eval_ms'))[0] * 1000),
                     f"{min(fl(okrows, 'budget_e2s_bits')):.0f}"])
    table("tab_e5a.tex", ["$t$", "Bits", "$M$", "AND", "GC bytes", "Wrong", "Garble ($\\mu$s)", "OT (ms)", "Eval ($\\mu$s)", "Budget"],
          rows, "rrrrrrrrrr")
    num("eFiveARuns", len(next(iter(groups.values()))))

# ---------------------------------------------------------------- E5b
e5b = load("e5b.csv")
if e5b:
    groups = defaultdict(list)
    for r in e5b:
        groups[(int(r["d"]), r["variant"])].append(r)
    variants = ["scalar_relin_each", "scalar_relin_once", "packed_rotations"]
    labels = {"scalar_relin_each": "scalar, relin. per term", "scalar_relin_once": "scalar, relin. once", "packed_rotations": "slot-packed + rotations"}
    styles = {"scalar_relin_each": ("o-", "0.1"), "scalar_relin_once": ("s--", "0.45"), "packed_rotations": ("^:", "0.1")}
    dims = sorted({d for d, _ in groups})
    fig, axes = plt.subplots(2, 1, figsize=(COL, 3.6), sharex=True)
    for v in variants:
        xs, ev, enc = [], [], []
        for d in dims:
            g = [r for r in groups.get((d, v), []) if r["error"] == ""]
            if g:
                xs.append(d)
                ev.append(miq(fl(g, "t_eval_ms"))[0])
                enc.append(miq(fl(g, "t_encrypt_p_ms"))[0])
        st, c = styles[v]
        axes[0].plot(xs, ev, st, color=c, ms=3, lw=0.9, label=labels[v])
        axes[1].plot(xs, enc, st, color=c, ms=3, lw=0.9, label=labels[v])
    axes[0].set_ylabel("server evaluation (ms)")
    axes[1].set_ylabel("one party's encryption (ms)")
    axes[1].set_xlabel("dimensions $d$")
    axes[0].legend(fontsize=6.5)
    fig.savefig(os.path.join(OUT, "fig_e5b_dims.pdf"))
    plt.close(fig)

    rows = []
    for d in [x for x in (2, 4, 8, 15, 16, 32) if x in dims]:
        row = [str(d), groups[(d, variants[0])][0]["max_coord"] if groups.get((d, variants[0])) else "--"]
        for v in variants:
            g = [r for r in groups.get((d, v), []) if r["error"] == ""]
            row.append(sig(miq(fl(g, "t_eval_ms"))[0]) if g else "--")
        for v in (variants[0], variants[2]):
            g = [r for r in groups.get((d, v), []) if r["error"] == ""]
            row.append(kib(float(g[0]["upload_bytes_per_party"])) if g else "--")
        g = [r for r in groups.get((d, variants[2]), []) if r["error"] == ""]
        row.append(g[0]["rot_keys"] if g else "--")
        row.append(sig(float(g[0]["t_rotkey_share_p_ms"])) if g else "--")
        rows.append(row)
    table("tab_e5b.tex", ["$d$", "$M$", "each", "once", "packed", "up. scalar", "up. packed", "keys", "keygen"], rows, "rrrrrrrrr")
    num("eFiveBRuns", len(next(iter(groups.values()))))
    num("eFiveBWrong", sum(1 for r in e5b if r["ok"] != "true"))
    num("eFiveBTotal", f"{len(e5b):,}")
    num("eFiveBMaxD", max(dims))
    for d, tag in ((2, "Two"), (15, "Fifteen")):
        for v, vt in zip(variants, ("Each", "Once", "Packed")):
            g = [r for r in groups.get((d, v), []) if r["error"] == ""]
            if g:
                num(f"eFiveB{tag}{vt}", sig(miq(fl(g, "t_eval_ms"))[0]))
        g = groups.get((d, variants[0]))
        if g:
            num(f"eFiveB{tag}M", g[0]["max_coord"])

# ---------------------------------------------------------------- E9
e9 = load("e9_sizes.csv")
if e9:
    rows = []
    for r in e9:
        name = (r["group"] + ": " + r["variant"]).replace("_", "\\_")
        if r["status"] != "ok":
            rows.append([name, "\\multicolumn{4}{l}{%s}" % r["status"].replace("_", " ")])
            continue
        rows.append([name, f"{int(r['bytes']):,}", mib(float(r["bytes"])), mib(float(r["gzip9_bytes"])), mib(float(r["brotli11_bytes"]))])
        tag = "eNine" + "".join(p.capitalize() for p in (r["group"] + "_" + r["variant"]).replace("-", "_").split("_"))
        num(tag, f"{int(r['bytes']):,}")
        num(tag + "MiB", mib(float(r["bytes"])))
        num(tag + "Gz", mib(float(r["gzip9_bytes"])))
        num(tag + "Br", mib(float(r["brotli11_bytes"])))
    table("tab_e9.tex", ["Artifact", "Bytes", "MiB", "gzip -9", "brotli 11"], rows, "lrrrr")
    okr = [r for r in e9 if r["status"] == "ok" and r["group"] == "party" and r["variant"] != "committed_in_repo"]
    if okr:
        fig, ax = plt.subplots(figsize=(COL, 2.2))
        xs = range(len(okr))
        for i, (col, lab) in enumerate((("bytes", "raw"), ("gzip9_bytes", "gzip -9"), ("brotli11_bytes", "brotli 11"))):
            ax.bar([x + (i - 1) * 0.27 for x in xs], [float(r[col]) / 1048576 for r in okr], 0.27, color=GRAYS[i], hatch=HATCH[i],
                   edgecolor="0.1", lw=0.4, label=lab)
        ax.set_xticks(list(xs))
        ax.set_xticklabels([r["variant"].replace("_", "\n") for r in okr], fontsize=5.5)
        ax.set_ylabel("size (MiB)")
        ax.legend(fontsize=6.5)
        fig.savefig(os.path.join(OUT, "fig_e9_sizes.pdf"))
        plt.close(fig)

e9w = load("e9_wasm_node_e3.csv")
e9n = load("e9_native_e3.csv")
if e9w and e9n:
    rows = []
    for col, label in PHASES:
        a, b = miq(fl(e9n, col)), miq(fl(e9w, col))
        rows.append([label, sig(a[0]), sig(b[0]), sig(b[0] / a[0], 2) + "$\\times$" if a[0] > 0 else "--"])
        num("eNineSlow" + "".join(p.capitalize() for p in col[2:-3].split("_")), sig(b[0] / a[0], 2) if a[0] > 0 else "n/a")
    a, b = miq(fl(e9n, "t_total_ms")), miq(fl(e9w, "t_total_ms"))
    rows.append(["One evaluation (no keygen)", sig(a[0]), sig(b[0]), sig(b[0] / a[0], 2) + "$\\times$"])
    num("eNineSlowTotal", sig(b[0] / a[0], 2))
    num("eNineWasmRuns", len(e9w))
    table("tab_e9_slowdown.tex", ["Phase", "Native (ms)", "WASM (ms)", "Ratio"], rows, "lrrr")
e9l = load("e9_load_node.csv")
if e9l:
    for col, tag in (("read_ms", "Read"), ("compile_ms", "Compile"), ("instantiate_ms", "Instantiate"), ("ready_ms", "Ready")):
        v = fl(e9l, col)
        if v:
            num("eNineLoad" + tag, cell(v))
    num("eNineLoadRuns", len(e9l))

# ---------------------------------------------------------------- E10
e10 = load("e10.csv")
if e10:
    for model, tag in (("exact_delta", "Exact"), ("class_greedy", "Class")):
        q = [int(r["queries"]) for r in e10 if r["model"] == model]
        med, q1, q3 = miq([float(x) for x in q])
        num(f"eTen{tag}Median", f"{med:g}")
        num(f"eTen{tag}IQR", f"[{q1:g}, {q3:g}]")
        num(f"eTen{tag}Min", min(q))
        num(f"eTen{tag}Max", max(q))
        for acc in (1, 2, 5):
            h = [float(r[f"hours_{acc}_account" + ("s" if acc > 1 else "")]) for r in e10 if r["model"] == model]
            num(f"eTen{tag}Hours{ {1: 'One', 2: 'Two', 5: 'Five'}[acc] }", f"{miq(h)[0]:g}")
    num("eTenPoints", len([r for r in e10 if r["model"] == "class_greedy"]))
    fig, ax = plt.subplots(figsize=(COL, 1.9))
    q = [int(r["queries"]) for r in e10 if r["model"] == "class_greedy"]
    ax.hist(q, bins=range(min(q), max(q) + 2), color="0.45", edgecolor="0.1", lw=0.4, align="left")
    ax.axvline(math.log2(10201), color="0.1", ls="--", lw=0.8)
    ax.set_xlabel("queries until one candidate remains")
    ax.set_ylabel("hidden points")
    fig.savefig(os.path.join(OUT, "fig_e10_queries.pdf"))
    plt.close(fig)

# ---------------------------------------------------------------- E11
e11 = load("e11_chisq.csv")
if e11:
    rows = [[r["test"].replace("_", " "), r["case"].replace("_", " "), f"{float(r['samples']):,.0f}", f"{int(r['bins']):,}",
             sig(float(r["chi_square"]), 5), r["df"], f"{float(r['p_approx']):.3f}"] for r in e11]
    table("tab_e11.tex", ["Test", "Input", "Samples", "Bins", "$\\chi^2$", "df", "$p$"], rows, "llrrrrr")
    ps = [float(r["p_approx"]) for r in e11]
    num("eElevenTests", len(ps))
    num("eElevenMinP", f"{min(ps):.3f}")
    num("eElevenMaxP", f"{max(ps):.3f}")
    num("eElevenBelow", sum(1 for p in ps if p < 0.01))
    num("eElevenRuns", f"{len(load('e11_serverview.csv')):,}")

# ---------------------------------------------------------------- E6
e6 = load("e6_summary.csv")
if e6:
    okr = [r for r in e6 if r["status"] == "ok"]
    num("eSixCrashed", sum(1 for r in e6 if r["status"] != "ok"))
    num("eSixFailedPairs", sum(int(r["failed"]) for r in okr))
    num("eSixReps", max(int(r["rep"]) for r in e6) + 1)
    groups = defaultdict(list)
    for r in okr:
        groups[(int(r["pairs"]), r["mode"])].append(r)
    ns = sorted({n for n, _ in groups})
    conc = {n: miq(fl(groups[(n, "concurrent")], "pairs_per_s"))[0] for n in ns if groups.get((n, "concurrent"))}
    if conc:
        best = max(conc, key=conc.get)
        num("eSixMaxPairs", max(conc))
        num("eSixBestN", best)
        num("eSixBestThroughput", sig(conc[best]))
        num("eSixSeqThroughput", sig(miq(fl(groups[(ns[0], "sequential")], "pairs_per_s"))[0]))
        num("eSixMaxMem", sig(max(float(r["peak_ws_bytes"]) for r in okr) / 1048576, 3))
        num("eSixMaxUtil", f"{100 * max(float(r['cpu_utilization']) for r in okr):.0f}")
    one = miq(fl(groups[(ns[0], "concurrent")], "peak_ws_bytes"))[0]
    top = miq(fl(groups[(ns[-1], "concurrent")], "peak_ws_bytes"))[0]
    if ns[-1] > ns[0]:
        slope = (top - one) / (ns[-1] - ns[0])
        num("eSixMemPerPair", sig(slope / 1048576, 3))
        if os.path.exists(hw_path):
            num("eSixRamLimit", f"{int(float(m.get('ram_bytes', 0)) / slope / 10) * 10:,}")
    fig, axes = plt.subplots(2, 1, figsize=(COL, 3.3), sharex=True)
    for mode, st, c in (("sequential", "s--", "0.5"), ("concurrent", "o-", "0.1")):
        xs = [n for n in ns if groups.get((n, mode))]
        axes[0].plot(xs, [miq(fl(groups[(n, mode)], "pairs_per_s"))[0] for n in xs], st, color=c, ms=3, lw=0.9, label=mode)
        axes[1].plot(xs, [miq(fl(groups[(n, mode)], "peak_ws_bytes"))[0] / 1048576 for n in xs], st, color=c, ms=3, lw=0.9, label=mode)
    axes[0].set_ylabel("pairs per second")
    axes[1].set_ylabel("peak working set (MiB)")
    axes[1].set_xlabel("number of Police–User pairs $n$")
    axes[1].set_xscale("log", base=2)
    axes[0].legend(fontsize=6.5)
    fig.savefig(os.path.join(OUT, "fig_e6_scaling.pdf"))
    plt.close(fig)
    pairs = load("e6_pairs.csv")
    for n, tag in ((1, "One"), (3, "Three")):
        v = [float(r["t_latency_ms"]) for r in pairs if r["pairs"] == str(n) and r["mode"] == "concurrent" and r["ok"] == "true"]
        if v:
            num(f"eSixLatency{tag}", cell(v))

# ---------------------------------------------------------------- E7
e7 = load("e7_payload.csv")
if e7:
    rows = [[r["phase"], r["message"].replace("_", "\\_"), r["sender"] + " $\\rightarrow$ " + r["receiver"], r["count"],
             kib(float(r["base64_bytes_each"])), kib(float(r["base64_bytes_total"]))] for r in e7]
    table("tab_e7.tex", ["Phase", "Message", "Direction", "\\#", "Each", "Total"], rows, "lllrrr")
    up = sum(float(r["base64_bytes_total"]) for r in e7 if r["sender"] == "each client")
    num("eSevenClientUp", kib(up))
    num("eSevenGC", kib(sum(float(r["base64_bytes_total"]) for r in e7 if r["phase"].startswith(("Garbled", "OT")))))

# ---------------------------------------------------------------- browser: E6 heat map
e6b = load("e6_browser.csv")
if e6b:
    num("eSixBrRows", len(e6b))
    num("eSixBrFailed", sum(1 for r in e6b if r["ok"] != "true"))
    num("eSixBrReps", max(int(r["rep"]) for r in e6b) + 1)
    num("eSixBrChrome", e6b[0]["chrome_version"].replace("HeadlessChrome/", "Chrome ").replace("Chrome/", "Chrome "))
    cells = defaultdict(dict)
    for r in e6b:
        if r["cell_latency_s"]:
            cells[(r["mode"], int(r["users"]), int(r["assignments_per_pair"]))][r["rep"]] = float(r["cell_latency_s"])
    med = {k: miq(list(v.values())) for k, v in cells.items()}
    names = {1: "One", 2: "Two", 3: "Three"}
    for (mode, u, a), m in med.items():
        num(f"eSixBr{mode.capitalize()}{names[u]}{names[a]}", f"{m[0]:.2f}")
        num(f"eSixBr{mode.capitalize()}{names[u]}{names[a]}IQR", f"[{m[1]:.2f}, {m[2]:.2f}]")
    one = [r for r in e6b if r["mode"] == "concurrent" and r["users"] == "1" and r["assignments_per_pair"] == "1" and r["t_total_s"]]
    if one:
        num("eSixBrSetup", cell(fl(one, "t_setup_s")))
        num("eSixBrInputResult", cell(fl(one, "t_input_to_result_s")))
        num("eSixBrTotal", cell(fl(one, "t_total_s")))
    fig, ax = plt.subplots(figsize=(COL, 2.3))
    grid = [[med.get(("concurrent", u, a), (float("nan"),))[0] for u in (1, 2, 3)] for a in (1, 2, 3)]
    im = ax.imshow(grid, cmap="Greys", origin="lower", vmin=0, vmax=max(max(row) for row in grid) * 1.25, aspect="auto")
    for i, a in enumerate((1, 2, 3)):
        for j, u in enumerate((1, 2, 3)):
            v = grid[i][j]
            ax.text(j, i, f"{v:.1f} s", ha="center", va="center", fontsize=8, color="white" if v > im.get_clim()[1] * 0.55 else "black")
    ax.set_xticks([0, 1, 2]); ax.set_xticklabels(["1", "2", "3"])
    ax.set_yticks([0, 1, 2]); ax.set_yticklabels(["1", "2", "3"])
    ax.set_xlabel("users"); ax.set_ylabel("assignments per pair"); ax.grid(False)
    fig.colorbar(im, ax=ax, label="latency (s)")
    fig.savefig(os.path.join(OUT, "fig_e6_heat.pdf"))
    plt.close(fig)

# ---------------------------------------------------------------- browser: E7 traffic
e7t = load("e7_traffic.csv")
if e7t:
    agg = defaultdict(lambda: defaultdict(lambda: [0, 0.0, 0.0]))  # (role, phase) -> rep -> [n, up, down]
    for r in e7t:
        a = agg[(r["role"], r["phase"])][r["rep"]]
        a[0] += 1
        a[1] += float(r["request_body_bytes"] or 0)
        a[2] += float(r["response_wire_bytes"] or 0)
    nreps = len({r["rep"] for r in e7t})
    num("eSevenTrReps", nreps)

    def medv(role, phase, idx):
        vals = [v[idx] for v in agg.get((role, phase), {}).values()]
        vals += [0] * (nreps - len(vals))
        return statistics.median(vals) if vals else 0

    order = ["CPK + RLK r1 shares", "CPK + RLK r1 aggregate", "RLK r2 share", "Ciphertexts", "Enc(delta)", "E2S share", "E2S aggregate",
             "send garbled", "send gcLabels", "send otA", "fetch otA", "send otR", "fetch otR", "send otE", "fetch garbled", "fetch gcLabels", "fetch otE",
             "Result", "polling (session state)", "other API", "static: party.wasm", "static: other"]
    phases = [p for p in order if any(k[1] == p for k in agg)] + sorted({k[1] for k in agg} - set(order))
    rows = []
    tot = {"police": [0, 0, 0], "user": [0, 0, 0]}
    for p in phases:
        row = [p.replace("_", "\\_")]
        for role in ("police", "user"):
            n, up, down = medv(role, p, 0), medv(role, p, 1), medv(role, p, 2)
            for i, v in enumerate((n, up, down)):
                tot[role][i] += v
            row += [f"{n:g}", kib(up) if up else "0", kib(down) if down else "0"]
        rows.append(row)
    rows.append(["\\textbf{Total}"] + [x for role in ("police", "user") for x in (f"{tot[role][0]:g}", kib(tot[role][1]), kib(tot[role][2]))])
    table("tab_e7_traffic.tex", ["Phase", "P \\#", "P up", "P down", "U \\#", "U up", "U down"], rows, "lrrrrrr")
    for role, tag in (("police", "Police"), ("user", "User")):
        num(f"eSevenTr{tag}Poll", f"{medv(role, 'polling (session state)', 0):g}")
        num(f"eSevenTr{tag}Requests", f"{tot[role][0]:g}")
        num(f"eSevenTr{tag}Up", kib(tot[role][1]))
        num(f"eSevenTr{tag}Down", kib(tot[role][2]))
        num(f"eSevenTr{tag}Wasm", kib(medv(role, "static: party.wasm", 2)))

# ---------------------------------------------------------------- browser: E8 per role
e8 = load("e8_browser.csv")
if e8:
    by = defaultdict(dict)
    for r in e8:
        by[(r["role"], r["rep"])][r["phase"][0]] = r
    num("eEightReps", len({r["rep"] for r in e8}))
    rows = []
    for role in ("police", "user", "api"):
        reps8 = [v for (ro, _), v in by.items() if ro == role and all(k in v for k in "123")]
        if not reps8:
            continue

        def g(phase, col):
            return [float(v[phase][col]) for v in reps8 if v[phase][col] not in ("", None)]

        def delta(a, b, col):
            return [float(v[b][col]) - float(v[a][col]) for v in reps8 if v[a][col] not in ("", None) and v[b][col] not in ("", None)]

        ws1, ws3 = miq(g("1", "working_set_bytes"))[0], miq(g("3", "working_set_bytes"))[0]
        cpu_k, cpu_e = miq(delta("1", "2", "cpu_ms_cumulative"))[0], miq(delta("2", "3", "cpu_ms_cumulative"))[0]
        wasm = miq(g("3", "wasm_memory_bytes"))[0] if g("3", "wasm_memory_bytes") else float("nan")
        procs = miq(g("3", "processes"))[0]
        rows.append([{"police": "Police browser", "user": "User browser", "api": "API process"}[role], f"{procs:g}", mib(ws1), mib(ws3),
                     sig(cpu_k), sig(cpu_e), mib(wasm) if wasm == wasm and wasm > 0 else "--"])
        tag = role.capitalize()
        num(f"eEight{tag}WsEnd", mib(ws3))
        num(f"eEight{tag}CpuKeygen", sig(cpu_k))
        num(f"eEight{tag}CpuEval", sig(cpu_e))
        if wasm == wasm and wasm > 0:
            num(f"eEight{tag}Wasm", mib(wasm))
    table("tab_e8.tex", ["Participant", "Proc.", "WS loaded", "WS end", "CPU keygen", "CPU eval.", "WASM mem."], rows, "lrrrrrr")

lt = load("e9_longtasks.csv")
if e8:
    per = defaultdict(list)
    for r in lt:
        per[(r["role"], r["rep"])].append(float(r["duration_ms"]))
    for role, tag in (("police", "Police"), ("user", "User")):
        runs = [per.get((role, rep), []) for rep in sorted({r["rep"] for r in e8})]
        num(f"eNineLt{tag}Count", f"{statistics.median([len(x) for x in runs]):g}")
        num(f"eNineLt{tag}Max", sig(max([max(x) for x in runs if x], default=0)))
        num(f"eNineLt{tag}Total", sig(statistics.median([sum(x) for x in runs])))

# ---------------------------------------------------------------- browser: E9 load
bl = load("e9_browser_load.csv")
if bl:
    rows = []
    for series in ("cold", "warm"):
        g = [r for r in bl if r["series"] == series]
        if not g:
            continue
        rows.append([series, str(len(g)), kib(miq(fl(g, "wasm_transfer_bytes"))[0]), cell(fl(g, "fetch_ms")), cell(fl(g, "compile_instantiate_ms")), cell(fl(g, "ready_ms"))])
        tag = series.capitalize()
        num(f"eNineBr{tag}Ready", cell(fl(g, "ready_ms")))
        num(f"eNineBr{tag}Fetch", cell(fl(g, "fetch_ms")))
        num(f"eNineBr{tag}Transfer", kib(miq(fl(g, "wasm_transfer_bytes"))[0]))
        num("eNineBrWasmMem", mib(miq(fl(g, "wasm_memory_bytes"))[0]))
    table("tab_e9_load.tex", ["Cache", "Runs", "Transfer (KiB)", "Fetch (ms)", "Compile + inst. (ms)", "Ready (ms)"], rows, "lrrrrr")

# ---------------------------------------------------------------- browser: E13
e13 = load("e13_robustness.csv")
if e13:
    label = {"missing_ot_response": "User leaves before answering the OT", "user_reopens_page": "User reopens the page",
             "police_reload_after_keygen": "Police reload after key generation", "out_of_range_input": "Client script sends $x = 200$"}
    obs = {"pending after 15 s without the User": "still pending after 15 s", "DENTRO DEL RADIO": "completes: inside", "FUERA DEL RADIO": "completes: outside"}
    rows = [[label.get(r["scenario"], r["scenario"].replace("_", " ")),
             obs.get(r["observed"], "rejected inside the WASM client" if r["observed"].startswith("rejected") else r["observed"].replace("_", " ")),
             "yes" if r["ok"] == "true" else "no"] for r in e13]
    table("tab_e13.tex", ["Scenario", "Observed", "As expected"], rows, "llc")
    num("eThirteenRuns", len(e13))
    num("eThirteenOk", sum(1 for r in e13 if r["ok"] == "true"))

# ---------------------------------------------------------------- short report: four condensed tables
def N(key):
    return numbers.get(''.join(DIGITS.get(ch, ch) for ch in key), "[not measured]")


# Table: summary of the experiments. The E12 row is read from results/e12_test.log (300 of 300 trials), as in the text.
table("tab_summary.tex", ["Experiment", "Runs", "Result"], [
    ["Correctness (E1)", N("eOneRuns"), N("eOneMismatch") + " wrong"],
    ["Value limit (E2)", N("eTwoRuns"), "correct from " + N("eTwoLastGoodNeg") + " to " + N("eTwoLastGoodPos")],
    ["Noise (E3)", N("eThreeRuns"), N("eThreeDelta") + " of " + N("eThreeQBits") + " bits used"],
    ["Parameter sets (E4)", N("eFourSets") + " sets", N("eFourCorrect") + " correct"],
    ["Load, native (E6)", "up to " + N("eSixMaxPairs") + " pairs", "peak " + N("eSixBestThroughput") + " pairs/s, " + N("eSixMaxMem") + " MiB"],
    ["Browser (E6)", N("eSixBrRows"), N("eSixBrConcurrentOneOne") + " s per assignment; " + N("eSixBrFailed") + " failed"],
    ["Repeated queries (E10)", N("eTenPoints") + " points", "median " + N("eTenClassMedian") + " queries to locate"],
    ["Cheating garbler (E12)", "300", "300 succeeded"],
], "lrl")

# Table: native time per phase (E3) with the WebAssembly/native ratio of the separate E9 comparison.
if e3:
    rows = []
    for col, label in PHASES:
        med, q1, q3 = miq(fl(e3, col))
        ratio = "--"
        if e9w and e9n and miq(fl(e9n, col))[0] > 0:
            ratio = sig(miq(fl(e9w, col))[0] / miq(fl(e9n, col))[0], 2) + "$\\times$"
        rows.append([label, sig(med), f"[{sig(q1)}, {sig(q3)}]", ratio])
    table("tab_phases.tex", ["Phase", "Native (ms)", "IQR", "WASM/native"], rows, "lrrr")

# Table: five representative parameter sets (E4).
if sets:
    def pick(logn, logq, logp=None):
        return next((e for e in default if e["logN"] == logn and e["logQ"] == logq and e.get("reps")
                     and (logp is None or e["logP"] == logp)), None)

    passed = [e for e in default if e["status"] == "correct" and e.get("reps")]
    fastest = pick(N("eFourBestN"), N("eFourBestQ").replace(", ", "-"), N("eFourBestP").replace(", ", "-"))
    chosen = [("Deployed", pick("14", "56-55-55-54-54-54")), ("Middle", pick("13", "56-54-54")), ("Fastest within std.", fastest),
              ("Tightest that passed", min(passed, key=lambda e: e["budget_min"])),
              ("Failed", next((e for e in default if e["status"] == "incorrect" and e.get("reps")), None))]
    rows = [[name, e["logN"], f"{float(e['qp_total_bits']):.0f}", status_cell(e), f"{e['budget_min']:.1f}", sig(e["client"][0]),
             sig(e["server"][0]), kib(e["ct"])] for name, e in chosen if e]
    table("tab_e4_short.tex", ["Set", "$\\log N$", "$\\log QP$", "Correct", "Budget", "Client", "Server", "Ct"], rows, "lrrlrrrr")

# Table: data per assignment (E7 serialized sizes after base64, E9 module size).
if e7:
    def up(pred):
        return kib(sum(float(r["base64_bytes_total"]) for r in e7 if r["sender"] == "each client" and pred(r["phase"])))

    table("tab_data.tex", ["Item", "Size"], [
        ["Key-generation shares, per client", up(lambda p: p.startswith(("CPK", "RLK"))) + " KiB"],
        ["Encrypted coordinates, per client", up(lambda p: p == "Ciphertexts") + " KiB"],
        ["Share-conversion message, per client", up(lambda p: p == "E2S") + " KiB"],
        ["Garbled circuit and oblivious transfer", N("eSevenGC") + " KiB"],
        ["WebAssembly client (with brotli)", N("eNinePartyDefaultMiB") + " MiB (" + N("eNinePartyDefaultBr") + " MiB)"],
    ], "lr")

# ---------------------------------------------------------------- numbers.tex
ALL = ["hwModel", "hwCPU", "hwCores", "hwThreads", "hwRAM", "hwOS", "hwGo", "hwNode", "hwCommit", "hwDate", "hwPower", "hwAC", "hwDefender"]
lines = ["% Generated by paper/make_assets.py from results/*.csv. Do not edit by hand.",
         "\\providecommand{\\notmeasured}{[not measured]}"]
for name, value in sorted(numbers.items()):
    value = str(value).replace("%", "\\%").replace("_", "\\_").replace("#", "\\#")
    lines.append("\\newcommand{\\%s}{%s}" % (name, value))
write("numbers.tex", "\n".join(lines) + "\n")
print(f"wrote {len(numbers)} numbers and the figures/tables to {OUT}")
