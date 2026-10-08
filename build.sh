#!/usr/bin/env bash
set -euo pipefail

mkdir -p web

echo "[1/3] Compilando party.wasm..."
GOOS=js GOARCH=wasm go build -o web/party.wasm ./cmd/party

echo "[2/3] Compilando API nativa..."
go build -o bin/lattigo-api ./cmd/api

echo "[3/3] Copiando wasm_exec.js..."
GOROOT="$(go env GOROOT)"
if [[ -f "$GOROOT/lib/wasm/wasm_exec.js" ]]; then
  cp "$GOROOT/lib/wasm/wasm_exec.js" web/wasm_exec.js
elif [[ -f "$GOROOT/misc/wasm/wasm_exec.js" ]]; then
  cp "$GOROOT/misc/wasm/wasm_exec.js" web/wasm_exec.js
else
  echo "No encontré wasm_exec.js en GOROOT=$GOROOT" >&2
  exit 1
fi

echo
echo "Build terminado."
echo "Ejecuta: ./bin/lattigo-api"
echo "Luego abre: http://localhost:8080"
