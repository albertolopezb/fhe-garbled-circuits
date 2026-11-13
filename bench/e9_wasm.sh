#!/usr/bin/env bash
# E9: WebAssembly size by build variant, compression and package ablation.
# Run from the repo root in Git Bash:   bash bench/e9_wasm.sh
# Output: results/e9_sizes.csv (one row per artifact), builds in results/raw/wasm/.
set -uo pipefail
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.0}"
out=results/raw/wasm
csv=results/e9_sizes.csv
mkdir -p "$out"
echo "experiment,group,variant,status,bytes,gzip9_bytes,brotli11_bytes,build_s,go_version,commit,note" > "$csv"
gov=$(go version | awk '{print $3}')
commit=$(git rev-parse HEAD)

record() { # group variant file build_s note
  local f="$3"
  if [[ -f "$f" ]]; then
    local raw gz br
    raw=$(wc -c < "$f")
    gz=$(gzip -9 -c "$f" | wc -c)
    br=$(brotli -q 11 -c "$f" | wc -c)
    echo "e9,$1,$2,ok,$raw,$gz,$br,$4,$gov,$commit,$5" >> "$csv"
    echo "$1/$2: $raw B, gzip $gz, brotli $br"
  else
    echo "e9,$1,$2,failed,,,,$4,$gov,$commit,$5" >> "$csv"
    echo "$1/$2: FAILED ($5)"
  fi
}

build() { # group variant pkg note [go build flags...]
  local group="$1" variant="$2" pkg="$3" note="$4"; shift 4
  local f="$out/$group-$variant.wasm" start=$SECONDS
  rm -f "$f"
  if ! GOOS=js GOARCH=wasm go build "$@" -o "$f" "$pkg" 2> "$out/$group-$variant.err"; then
    note="$(head -c 200 "$out/$group-$variant.err" | tr ',\n' ';  ')"
  fi
  record "$group" "$variant" "$f" "$((SECONDS - start))" "$note"
}

# 1. Build variants of the real client.
build party default        ./cmd/party "go build with no flags (what build.sh does)"
build party strip          ./cmd/party "-ldflags=-s -w"            -ldflags="-s -w"
build party trimpath       ./cmd/party "-trimpath"                 -trimpath
build party strip_trimpath ./cmd/party "-ldflags=-s -w -trimpath"  -ldflags="-s -w" -trimpath

# 2. wasm-opt -Oz on the default and on the stripped build.
for v in default strip; do
  f="$out/party-${v}_wasmopt_Oz.wasm"; rm -f "$f"; start=$SECONDS
  note="wasm-opt -Oz --all-features on party-$v (with only --enable-bulk-memory the validator rejects Go output: i64.trunc_sat)"
  if ! wasm-opt -Oz --all-features "$out/party-$v.wasm" -o "$f" 2> "$out/wasmopt-$v.err"; then
    note="$(head -c 200 "$out/wasmopt-$v.err" | tr ',\n' ';  ')"; rm -f "$f"
  fi
  record party "${v}_wasmopt_Oz" "$f" "$((SECONDS - start))" "$note"
done

# 3. TinyGo attempt.
if command -v tinygo > /dev/null; then
  f="$out/party-tinygo.wasm"; rm -f "$f"; start=$SECONDS; note="tinygo build -target wasm"
  if ! tinygo build -o "$f" -target wasm ./cmd/party 2> "$out/tinygo.err"; then
    note="$(head -c 200 "$out/tinygo.err" | tr ',\n' ';  ')"
  fi
  record party tinygo "$f" "$((SECONDS - start))" "$note"
else
  echo "e9,party,tinygo,not_run,,,,0,$gov,$commit,tinygo is not installed on this machine" >> "$csv"
  echo "party/tinygo: not run (tinygo not installed)"
fi

# 4. Ablation: what each layer adds (all with default flags).
build ablate empty_runtime ./bench/wasmablate/empty "Go runtime + syscall/js only"
build ablate gc_ot         ./bench/wasmablate/gcot  "runtime + garbled circuit + OT (edwards25519)"
build ablate bgv           ./bench/wasmablate/bgv   "runtime + single-key BGV"
build ablate mpbgv         ./bench/wasmablate/mpbgv "runtime + BGV + multiparty protocols"

# 5. The file that is committed in the repository (built on another machine).
git show HEAD:web/party.wasm > "$out/party-committed.wasm" 2>/dev/null
record party committed_in_repo "$out/party-committed.wasm" 0 "web/party.wasm at HEAD; built on a different machine and toolchain"

echo "wrote $csv"