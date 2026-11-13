#!/usr/bin/env bash
# E9: the same harness, native versus WebAssembly under Node.js, back to back.
# Run from the repo root in Git Bash:   bash bench/e9_node.sh
# Output: results/e9_native_e3.csv, results/e9_wasm_node_e3.csv, results/e9_load_node.csv
set -euo pipefail
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.0}"
n="${1:-30}"
mkdir -p results/raw/wasm bin
go build -o bin/bench-native.exe ./cmd/bench
GOOS=js GOARCH=wasm go build -o results/raw/wasm/bench.wasm ./cmd/bench
goroot="$(go env GOROOT)"
./bin/bench-native.exe e3 -seed 1 -n "$n" -out results/e9_native_e3.csv
node "$goroot/lib/wasm/wasm_exec_node.js" results/raw/wasm/bench.wasm e3 -seed 1 -n "$n" -out results/e9_wasm_node_e3.csv
node bench/e9_load.mjs results/raw/wasm/party-default.wasm results/e9_load_node.csv
echo "node $(node --version), $(go version)"