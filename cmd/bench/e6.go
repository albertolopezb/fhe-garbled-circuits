package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"lattigo-auth-ui-demo/bench"
	"lattigo-auth-ui-demo/internal/demo"
)

const (
	e6PairsFile   = "results/e6_pairs.csv"
	e6SummaryFile = "results/e6_summary.csv"
)

var e6PairsHeader = []string{"experiment", "pairs", "mode", "rep", "pair_id", "ok", "error", "t_keygen_ms", "t_evaluation_ms", "t_latency_ms"}

var e6SummaryHeader = []string{"experiment", "pairs", "mode", "rep", "status", "wall_ms", "pairs_per_s", "failed",
	"cpu_ms", "cpu_utilization", "logical_cpus", "peak_ws_bytes", "peak_commit_bytes", "commit", "dirty", "go_version"}

// runE6 measures native scaling: n independent Police + User pairs, each doing
// collective key generation and one evaluation, run one after another or all at
// once. The HTTP API, SQLite and the browsers are NOT in this loop.
func runE6(args []string) {
	fs := flag.NewFlagSet("e6", flag.ExitOnError)
	list := fs.String("pairs", "1,2,3,4,8,14,20,32,64,128", "numbers of pairs to test")
	reps := fs.Int("reps", 5, "repetitions per (pairs, mode)")
	fs.Parse(args)

	for _, f := range []struct {
		name   string
		header []string
	}{{"e6_pairs", e6PairsHeader}, {"e6_summary", e6SummaryHeader}} {
		w, logFile := openResult(f.name, f.header)
		w.Close()
		logFile.Close()
	}
	for _, field := range strings.Split(*list, ",") {
		n := strings.TrimSpace(field)
		for _, mode := range []string{"sequential", "concurrent"} {
			for rep := 0; rep < *reps; rep++ {
				child := exec.Command(os.Args[0], "e6run", "-pairs", n, "-mode", mode, "-rep", strconv.Itoa(rep))
				out, err := child.CombinedOutput()
				os.Stdout.Write(out)
				if err != nil {
					// The process died (for example out of memory): record the limit.
					fmt.Printf("e6 pairs=%s %s rep %d: child failed: %v\n", n, mode, rep, err)
					if w, werr := bench.OpenAppend(e6SummaryFile, e6SummaryHeader); werr == nil {
						rec := make([]string, len(e6SummaryHeader))
						rec[0], rec[1], rec[2], rec[3], rec[4] = "e6", n, mode, strconv.Itoa(rep), "crashed: "+err.Error()
						w.Row(rec)
						w.Close()
					}
				}
			}
		}
	}
}

// runE6Run is one child process: it runs the pairs and reports its own peak memory.
func runE6Run(args []string) {
	fs := flag.NewFlagSet("e6run", flag.ExitOnError)
	pairs := fs.Int("pairs", 1, "")
	mode := fs.String("mode", "sequential", "")
	rep := fs.Int("rep", 0, "")
	fs.Parse(args)

	params, err := demo.Parameters()
	if err != nil {
		log.Fatal(err)
	}
	type outcome struct {
		keygen, eval, latency float64
		err                   error
	}
	results := make([]outcome, *pairs)
	one := func(i int) {
		start := bench.Now()
		env, err := bench.NewEnv(params, []byte(fmt.Sprintf("e6-%d-%d-%d", *pairs, *rep, i)))
		if err != nil {
			results[i] = outcome{err: err}
			return
		}
		lap := bench.Now()
		res, err := env.RunOnce(10, 20, int64(i%101), 22, 5, false)
		if err == nil {
			_, expected := bench.Oracle(10, 20, int64(i%101), 22, 5)
			if bench.Class(res.Inside, res.Zero) != expected {
				err = fmt.Errorf("wrong class")
			}
		}
		results[i] = outcome{keygen: env.KeygenMs, eval: bench.SinceMs(lap), latency: bench.SinceMs(start), err: err}
	}

	cpu0 := bench.ProcessCPUMs()
	begin := bench.Now()
	if *mode == "concurrent" {
		var wg sync.WaitGroup
		for i := 0; i < *pairs; i++ {
			wg.Add(1)
			go func(i int) { defer wg.Done(); one(i) }(i)
		}
		wg.Wait()
	} else {
		for i := 0; i < *pairs; i++ {
			one(i)
		}
	}
	wall := bench.SinceMs(begin)
	cpu := bench.ProcessCPUMs() - cpu0

	w, err := bench.OpenAppend(e6PairsFile, e6PairsHeader)
	if err != nil {
		log.Fatal(err)
	}
	failed := 0
	for i, r := range results {
		msg := ""
		if r.err != nil {
			failed++
			msg = r.err.Error()
		}
		w.Row([]string{"e6", strconv.Itoa(*pairs), *mode, strconv.Itoa(*rep), strconv.Itoa(i), strconv.FormatBool(r.err == nil), msg,
			bench.F(r.keygen), bench.F(r.eval), bench.F(r.latency)})
	}
	w.Close()

	peakWS, peakCommit := bench.ProcessMemory()
	hash, dirty := bench.GitCommit()
	s, err := bench.OpenAppend(e6SummaryFile, e6SummaryHeader)
	if err != nil {
		log.Fatal(err)
	}
	s.Row([]string{"e6", strconv.Itoa(*pairs), *mode, strconv.Itoa(*rep), "ok", bench.F(wall), bench.F(float64(*pairs) / wall * 1000), strconv.Itoa(failed),
		bench.F(cpu), bench.F(cpu / wall / float64(runtime.NumCPU())), strconv.Itoa(runtime.NumCPU()),
		strconv.FormatUint(peakWS, 10), strconv.FormatUint(peakCommit, 10), hash, strconv.FormatBool(dirty), runtime.Version()})
	s.Close()
	fmt.Printf("e6 pairs=%-4d %-10s rep %d: wall %.0f ms, %.1f pairs/s, peak working set %.0f MiB, %d failed\n",
		*pairs, *mode, *rep, wall, float64(*pairs)/wall*1000, float64(peakWS)/1048576, failed)
}
