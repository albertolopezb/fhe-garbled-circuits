#!/usr/bin/env bash
# Runs the four browser scenarios against a THROW-AWAY copy of the app, so the
# repository's data/demo.db is not modified and the quota of the real demo
# database is not consumed.
# Run from the repo root in Git Bash:   bash bench/browser_scenarios.sh
# Needs: ./build.sh already run (bin/lattigo-api, web/party.wasm), Google Chrome, Node 22+.
set -euo pipefail
chrome="${CHROME:-/c/Program Files/Google/Chrome/Application/chrome.exe}"
work="$(mktemp -d)"
port_api=8090
port_cdp=9333
mkdir -p "$work/app/data" "$work/profile"
cp -r web "$work/app/web"
git show HEAD:data/demo.db > "$work/app/data/demo.db"   # the committed fixture, not the working copy
cp data/schema.sql "$work/app/data/"
cp bin/lattigo-api "$work/app/lattigo-api.exe"

( cd "$work/app" && ADDR="127.0.0.1:$port_api" ./lattigo-api.exe > "$work/api.log" 2>&1 ) &
api_pid=$!
"$chrome" --headless=new --remote-debugging-port=$port_cdp --user-data-dir="$(cygpath -w "$work/profile")" \
  --no-first-run --no-default-browser-check --disable-extensions --window-size=1100,1250 about:blank > "$work/chrome.log" 2>&1 &
chrome_pid=$!
cleanup() { kill "$chrome_pid" "$api_pid" 2>/dev/null || true; taskkill //F //IM lattigo-api.exe > /dev/null 2>&1 || true; }
trap cleanup EXIT

for _ in $(seq 1 40); do
  if curl -s -o /dev/null "http://127.0.0.1:$port_api/" && curl -s -o /dev/null "http://127.0.0.1:$port_cdp/json/version"; then break; fi
  sleep 0.5
done
status=0
node bench/browser_scenarios.mjs "http://127.0.0.1:$port_api" "$port_cdp" paper/figures results/e1_browser.csv || status=$?
mkdir -p results/raw
cp "$work/api.log" results/raw/browser_scenarios_api.log 2>/dev/null || true
exit $status
