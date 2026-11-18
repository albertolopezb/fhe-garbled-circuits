#!/usr/bin/env bash
# Full re-run of the paper experiments on AC power, best-performance mode.
# Run in Git Bash from anywhere inside the repo: bash bench/rerun_all.sh
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
stamp=$(date +%Y%m%d-%H%M%S)
mkdir -p results/raw
status_file=results/raw/rerun-$stamp.status
step() {
  local name=$1; shift
  local log=results/raw/$name-$(date +%Y%m%d-%H%M%S).log
  echo "$(date +%T) START $name" | tee -a "$status_file"
  local t0=$SECONDS
  "$@" > "$log" 2>&1
  local rc=$?
  echo "$(date +%T) END   $name rc=$rc $((SECONDS - t0))s" | tee -a "$status_file"
}
# keep copies of every current CSV before anything overwrites it
mkdir -p results/raw/before-rerun-$stamp
cp results/*.csv results/hardware.json results/raw/before-rerun-$stamp/ 2>/dev/null

step build   env GOTOOLCHAIN=go1.26.0 go build -o bin/bench.exe ./cmd/bench
step hardware ./bin/bench.exe hardware
step e1      ./bin/bench.exe e1 -seed 1 -n 10000
step e2      ./bin/bench.exe e2
step e3      ./bin/bench.exe e3 -seed 1 -n 1000
step e4      ./bin/bench.exe e4 -n 1000 -reps 30 -workers 8
step e5a     ./bin/bench.exe e5a
step e5b     ./bin/bench.exe e5b
step e6      ./bin/bench.exe e6
step e7      ./bin/bench.exe e7
step e11     ./bin/bench.exe e11 -n 1000
step e12     env GOTOOLCHAIN=go1.26.0 go test ./bench
step e9_wasm bash bench/e9_wasm.sh
step e10     python bench/e10_leakage.py --seed 1 --points 300
step e9_node bash bench/e9_node.sh
step scenarios bash bench/browser_scenarios.sh
step heat    node bench/browser_bench.mjs heat 5
step profile node bench/browser_bench.mjs profile 10
step load    node bench/browser_bench.mjs load 30
step robust  node bench/browser_bench.mjs robust
step assets  python paper/make_assets.py
echo "$(date +%T) ALL DONE" | tee -a "$status_file"
