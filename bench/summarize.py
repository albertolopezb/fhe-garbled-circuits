"""Print median / IQR / min / max per group for a results CSV.

Usage (from the repo root):
    python bench/summarize.py results/e3.csv
    python bench/summarize.py results/e4_timing.csv --by set_id

Only the Python standard library is used. Empty cells are skipped and counted.
"""
import argparse
import csv
import statistics
from collections import defaultdict


def quartiles(values):
    """Return (q1, median, q3) with the inclusive method; one value repeats."""
    if len(values) == 1:
        return values[0], values[0], values[0]
    q1, med, q3 = statistics.quantiles(values, n=4, method="inclusive")
    return q1, med, q3


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_path")
    ap.add_argument("--by", default="experiment", help="column to group by")
    ap.add_argument("--cols", default="", help="comma-separated columns (default: every t_*, *_bits, *_bytes)")
    args = ap.parse_args()

    with open(args.csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print("no rows")
        return
    if args.cols:
        cols = args.cols.split(",")
    else:
        cols = [c for c in rows[0] if c.startswith("t_") or c.endswith("_bits") or c.endswith("_bytes")]

    groups = defaultdict(list)
    for r in rows:
        groups[r.get(args.by, "")].append(r)

    for name, grp in groups.items():
        bad = sum(1 for r in grp if r.get("ok", "true") != "true")
        print(f"\n== {args.by}={name}  rows={len(grp)}  not_ok={bad}")
        for c in cols:
            vals = [float(r[c]) for r in grp if r.get(c, "") != ""]
            if not vals:
                continue
            q1, med, q3 = quartiles(vals)
            print(f"  {c:24s} median {med:12.4f}  IQR [{q1:.4f}, {q3:.4f}]  min {min(vals):.4f}  max {max(vals):.4f}  n={len(vals)}")


if __name__ == "__main__":
    main()
