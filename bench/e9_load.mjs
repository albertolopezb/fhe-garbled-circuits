// E9: time to read and compile the client module under Node.js (V8).
// Usage: node bench/e9_load.mjs <module.wasm> <out.csv>
// This is NOT a browser measurement: there is no network fetch, no HTTP cache
// and no streaming compilation. It isolates read + WebAssembly.compile.
import { readFile, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";

const [modulePath, outPath] = process.argv.slice(2);
const WARMUP = 3, RUNS = 30;
const rows = ["experiment,module,run_id,bytes,read_ms,compile_ms,node_version"];
for (let i = -WARMUP; i < RUNS; i++) {
  const t0 = performance.now();
  const bytes = await readFile(modulePath);
  const t1 = performance.now();
  await WebAssembly.compile(bytes);
  const t2 = performance.now();
  if (i >= 0) rows.push(`e9,${modulePath},${i},${bytes.length},${(t1 - t0).toFixed(4)},${(t2 - t1).toFixed(4)},${process.version}`);
}
await writeFile(outPath, rows.join("\n") + "\n");
console.log(`wrote ${outPath} (${RUNS} runs, ${WARMUP} warm-up runs discarded)`);