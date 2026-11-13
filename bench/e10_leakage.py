"""E10: leakage simulation. How many queries pin a hidden grid point?

Usage (from the repo root):
    python bench/e10_leakage.py --seed 1 --points 300

Writes results/e10.csv (one row per hidden point and attacker model) and
results/e10_summary.csv. This is a SIMULATION of an attacker who controls the
Police point P and the radius R; it does not run the cryptographic protocol.

Models
  exact_delta   Old protocol: each query reveals delta = dist^2 - R^2 exactly.
                Fixed queries from grid corners until the answers are unique.
  class_greedy  Current protocol: each query reveals inside / boundary /
                outside. Adaptive attacker that, at every step, picks the query
                (from a random sample plus the current candidates as centres)
                whose worst-case answer leaves the fewest candidates.
"""
import argparse
import csv
import math
import os

import numpy as np

GRID = 101          # coordinates 0..100
QUOTA_PER_HOUR = 3  # evaluations per Police-User pair per hour (cmd/api/limits.go)


def exact_delta_queries(points):
    """Queries needed when delta is revealed, using corners as Police points."""
    corners = [(0, 0), (100, 0), (0, 100), (100, 100)]
    xs, ys = np.meshgrid(np.arange(GRID), np.arange(GRID), indexing="ij")
    all_pts = np.stack([xs.ravel(), ys.ravel()], axis=1)
    keys = np.zeros(len(all_pts), dtype=np.int64)
    needed = np.zeros(len(all_pts), dtype=np.int64)
    for k, (cx, cy) in enumerate(corners, start=1):
        d2 = (all_pts[:, 0] - cx) ** 2 + (all_pts[:, 1] - cy) ** 2
        keys = keys * 20011 + d2  # 20011 > max dist^2 + 1, so the key stays injective
        _, inverse, counts = np.unique(keys, return_inverse=True, return_counts=True)
        unique_now = counts[inverse] == 1
        needed[(needed == 0) & unique_now] = k
    index = {(int(x), int(y)): int(n) for (x, y), n in zip(all_pts, needed)}
    return [index[(int(x), int(y))] for x, y in points]


def classify(px, py, r, pts):
    """0 = inside, 1 = boundary, 2 = outside for every candidate point."""
    delta = (pts[:, 0] - px) ** 2 + (pts[:, 1] - py) ** 2 - r * r
    return np.where(delta < 0, 0, np.where(delta == 0, 1, 2))


def class_greedy_queries(hidden, rng, sample=300):
    xs, ys = np.meshgrid(np.arange(GRID), np.arange(GRID), indexing="ij")
    cand = np.stack([xs.ravel(), ys.ravel()], axis=1)
    queries = 0
    while len(cand) > 1:
        # Candidate queries: random (P, R) plus circles centred on some candidates.
        px = rng.integers(0, GRID, sample)
        py = rng.integers(0, GRID, sample)
        r = rng.integers(0, GRID, sample)
        pick = cand[rng.integers(0, len(cand), min(60, len(cand)))]
        px = np.concatenate([px, pick[:, 0], pick[:, 0]])
        py = np.concatenate([py, pick[:, 1], pick[:, 1]])
        r = np.concatenate([r, rng.integers(0, 12, len(pick)), np.zeros(len(pick), dtype=np.int64)])

        delta = (cand[None, :, 0] - px[:, None]) ** 2 + (cand[None, :, 1] - py[:, None]) ** 2 - (r * r)[:, None]
        inside = (delta < 0).sum(axis=1)
        boundary = (delta == 0).sum(axis=1)
        outside = len(cand) - inside - boundary
        worst = np.maximum(np.maximum(inside, boundary), outside)
        best = int(np.argmin(worst))
        if worst[best] == len(cand):
            continue  # no sampled query separates the candidates: resample
        answer = classify(px[best], py[best], r[best], np.array([hidden]))[0]
        cand = cand[classify(px[best], py[best], r[best], cand) == answer]
        queries += 1
    assert tuple(cand[0]) == tuple(hidden)
    return queries


def hours_needed(queries, accounts=1):
    """Waiting time in hours under the quota: 3 per hour per colluding account."""
    per_hour = QUOTA_PER_HOUR * accounts
    return max(0, math.ceil(queries / per_hour) - 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--points", type=int, default=300, help="hidden points to attack")
    ap.add_argument("--out", default="results/e10.csv")
    args = ap.parse_args()

    rng = np.random.default_rng(args.seed)
    points = rng.integers(0, GRID, size=(args.points, 2))
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    exact = exact_delta_queries(points)
    rows = []
    for i, (hidden, q_exact) in enumerate(zip(points, exact)):
        q_class = class_greedy_queries(hidden, rng)
        for model, q in (("exact_delta", q_exact), ("class_greedy", q_class)):
            rows.append({
                "experiment": "e10", "seed": args.seed, "point_id": i,
                "hidden_x": int(hidden[0]), "hidden_y": int(hidden[1]),
                "model": model, "queries": q,
                "hours_1_account": hours_needed(q, 1),
                "hours_2_accounts": hours_needed(q, 2),
                "hours_5_accounts": hours_needed(q, 5),
            })
        if (i + 1) % 50 == 0:
            print(f"{i + 1}/{args.points} hidden points")
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    summary_path = args.out.replace(".csv", "_summary.csv")
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["model", "points", "queries_min", "queries_q1", "queries_median", "queries_q3", "queries_max",
                    "median_hours_1_account", "median_hours_2_accounts", "median_hours_5_accounts", "bound_note"])
        for model in ("exact_delta", "class_greedy"):
            q = np.array([r["queries"] for r in rows if r["model"] == model])
            med = int(np.median(q))
            note = ("log2(10201) = %.2f bits; log3(10201) = %.2f three-way answers"
                    % (math.log2(GRID * GRID), math.log(GRID * GRID, 3)))
            w.writerow([model, len(q), q.min(), np.percentile(q, 25), np.median(q), np.percentile(q, 75), q.max(),
                        hours_needed(med, 1), hours_needed(med, 2), hours_needed(med, 5), note])
            print(f"{model:13s} queries: min {q.min()} median {np.median(q)} max {q.max()}"
                  f" | hours at median: {hours_needed(med, 1)} (1 account), {hours_needed(med, 5)} (5 accounts)")
    print("wrote", args.out, "and", summary_path)


if __name__ == "__main__":
    main()
