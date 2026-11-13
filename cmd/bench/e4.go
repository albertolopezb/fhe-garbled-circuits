package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"lattigo-auth-ui-demo/bench"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const (
	e4SetsFile   = "results/e4_sets.csv"
	e4TimingFile = "results/e4_timing.csv"
	e4RunsFile   = "results/e4_runs.csv"
)

// e4SetsHeader: one row per parameter set (validity, security check, memory).
var e4SetsHeader = []string{
	"set_id", "logN", "logQ", "logP", "xs", "t", "q_total_bits", "qp_total_bits",
	"he_std2018_max_logq_128", "he_std2018_status", "status", "error",
	"timing_reps", "timing_errors", "n_runs", "mismatches", "failures", "workers",
	"peak_ws_timing_bytes", "peak_ws_total_bytes", "peak_commit_total_bytes", "cpu_ms_total", "wall_s",
	"seed", "commit", "dirty", "go_version",
}

// e4TimingHeader: one row per timed repetition (fresh keys, single thread).
var e4TimingHeader = []string{
	"set_id", "logN", "logQ", "logP", "xs", "rep", "ok", "error",
	"t_skgen_p_ms", "t_skgen_u_ms", "t_ckg_share_p_ms", "t_ckg_share_u_ms",
	"t_rkg_r1_p_ms", "t_rkg_r1_u_ms", "t_rkg_r2_p_ms", "t_rkg_r2_u_ms", "t_setup_server_ms", "t_keygen_total_ms",
	"t_encrypt_p_ms", "t_encrypt_u_ms", "t_eval_ms", "t_e2s_share_p_ms", "t_e2s_share_u_ms", "t_e2s_final_ms",
	"t_garble_ms", "t_ot_ms", "t_gc_eval_ms",
	"sk_bytes", "cpk_bytes", "rlk_bytes", "ckg_share_bytes", "rkg_r1_share_bytes", "rkg_r2_share_bytes",
	"ciphertext_bytes", "e2s_share_bytes", "garbled_bytes",
	"q_bits", "delta_bits", "budget_delta_bits", "budget_e2s_bits", "flood_margin_bits",
	"heap_alloc_bytes", "heap_sys_bytes",
}

// runE4 is the parent: it runs every parameter set in its own child process,
// so that the peak working set reported for a set belongs to that set only.
func runE4(args []string) {
	fs := flag.NewFlagSet("e4", flag.ExitOnError)
	n := fs.Int("n", 1000, "random correctness runs per set (plus the 11 fixed cases)")
	reps := fs.Int("reps", 30, "timed repetitions per set (3 warm-up runs are added and discarded)")
	workers := fs.Int("workers", 8, "parallel workers for the correctness runs")
	seed := fs.Uint64("seed", 1, "seed for the random inputs and the CRS")
	only := fs.String("only", "", "run only the sets whose id contains this text")
	fs.Parse(args)

	stamp := time.Now().Format("20060102-150405")
	if err := os.MkdirAll("results/raw", 0o755); err != nil {
		log.Fatal(err)
	}
	for _, f := range []string{e4SetsFile, e4TimingFile, e4RunsFile} {
		if _, err := os.Stat(f); err == nil {
			kept := filepath.Join("results", "raw", strings.TrimSuffix(filepath.Base(f), ".csv")+"-replaced-at-"+stamp+".csv")
			if err := os.Rename(f, kept); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("previous %s kept as %s\n", f, kept)
		}
	}
	logFile, err := os.Create(filepath.Join("results", "raw", "e4-"+stamp+".log"))
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	begin := time.Now()
	sets := bench.DefaultSets()
	done := 0
	for _, s := range sets {
		if *only != "" && !strings.Contains(s.ID(), *only) {
			continue
		}
		child := exec.Command(os.Args[0], "e4set",
			"-logN", strconv.Itoa(s.LogN), "-logQ", joinDash(s.LogQ), "-logP", joinDash(s.LogP), "-xs", s.Xs,
			"-n", strconv.Itoa(*n), "-reps", strconv.Itoa(*reps), "-workers", strconv.Itoa(*workers),
			"-seed", strconv.FormatUint(*seed, 10))
		out, err := child.CombinedOutput()
		logFile.Write(out)
		os.Stdout.Write(out)
		if err != nil {
			// The child died before writing its own summary row: record that.
			msg := fmt.Sprintf("child process failed: %v", err)
			fmt.Println(s.ID(), msg)
			fmt.Fprintln(logFile, s.ID(), msg)
			if w, werr := bench.OpenAppend(e4SetsFile, e4SetsHeader); werr == nil {
				rec := make([]string, len(e4SetsHeader))
				rec[0], rec[1], rec[2], rec[3], rec[4] = s.ID(), strconv.Itoa(s.LogN), joinDash(s.LogQ), joinDash(s.LogP), s.Xs
				rec[10], rec[11] = "crashed", msg
				w.Row(rec)
				w.Close()
			}
		}
		done++
	}
	fmt.Printf("e4 done: %d sets in %.0f s -> %s, %s, %s\n", done, time.Since(begin).Seconds(), e4SetsFile, e4TimingFile, e4RunsFile)
}

// runE4Set measures one parameter set: timed repetitions on one thread with
// fresh keys each time, then parallel correctness runs, then a summary row.
func runE4Set(args []string) {
	fs := flag.NewFlagSet("e4set", flag.ExitOnError)
	logN := fs.Int("logN", 14, "")
	logQ := fs.String("logQ", "56-55-55-54-54-54", "")
	logP := fs.String("logP", "55-55", "")
	xs := fs.String("xs", "ternary_p2/3", "")
	n := fs.Int("n", 1000, "")
	reps := fs.Int("reps", 30, "")
	workers := fs.Int("workers", 8, "")
	seed := fs.Uint64("seed", 1, "")
	fs.Parse(args)

	begin := time.Now()
	q, err1 := bench.ParseInts(*logQ)
	p, err2 := bench.ParseInts(*logP)
	if err1 != nil || err2 != nil {
		log.Fatal("bad -logQ or -logP")
	}
	set := bench.ParamSet{LogN: *logN, LogQ: q, LogP: p, Xs: *xs}
	hash, dirty := bench.GitCommit()

	sets, err := bench.OpenAppend(e4SetsFile, e4SetsHeader)
	if err != nil {
		log.Fatal(err)
	}
	defer sets.Close()
	summary := func(params *bgv.Parameters, status, errText string, timingErrs, runs, mismatches, failures int, peakTiming uint64) {
		rec := []string{set.ID(), strconv.Itoa(set.LogN), *logQ, *logP, set.Xs, "65537", "", "", "", "", status, errText,
			strconv.Itoa(*reps), strconv.Itoa(timingErrs), strconv.Itoa(runs), strconv.Itoa(mismatches), strconv.Itoa(failures), strconv.Itoa(*workers)}
		if params != nil {
			bound, sec := set.SecurityCheck(params.LogQP())
			rec[6], rec[7], rec[8], rec[9] = bench.F(params.LogQ()), bench.F(params.LogQP()), strconv.Itoa(bound), sec
		}
		peakWS, peakCommit := bench.ProcessMemory()
		rec = append(rec, strconv.FormatUint(peakTiming, 10), strconv.FormatUint(peakWS, 10), strconv.FormatUint(peakCommit, 10),
			bench.F(bench.ProcessCPUMs()), bench.F(time.Since(begin).Seconds()),
			strconv.FormatUint(*seed, 10), hash, strconv.FormatBool(dirty), runtime.Version())
		sets.Row(rec)
	}

	params, err := set.Build()
	if err != nil {
		summary(nil, "invalid_params", err.Error(), 0, 0, 0, 0, 0)
		fmt.Printf("%-44s invalid parameters: %v\n", set.ID(), err)
		return
	}

	// Phase 1: timing. One goroutine, fresh collective keys for every repetition.
	timing, err := bench.OpenAppend(e4TimingFile, e4TimingHeader)
	if err != nil {
		log.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(*seed, uint64(*logN)))
	draw := func() int64 { return rng.Int64N(101) }
	timingErrs := 0
	const warmup = 3
	for rep := -warmup; rep < *reps; rep++ {
		j := job{"timing", draw(), draw(), draw(), draw(), draw()}
		rec, ok := timedRep(set, params, rep, *seed, j)
		if rep < 0 {
			continue // warm-up: discarded
		}
		if !ok {
			timingErrs++
		}
		timing.Row(rec)
	}
	timing.Close()
	peakTiming, _ := bench.ProcessMemory()

	// Phase 2: correctness. Parallel workers, so these rows are NOT for timing.
	jobs := append(fixedCases(), randomCases(*seed, *n)...)
	runs, err := bench.OpenAppend(e4RunsFile, bench.Header)
	if err != nil {
		log.Fatal(err)
	}
	lit := params.ParametersLiteral()
	meta := bench.Meta{Commit: hash, Dirty: dirty, GoVersion: runtime.Version(),
		LogN: params.LogN(), LogQ: bench.Ints(logs(lit.Q)), LogP: bench.Ints(logs(lit.P)), T: params.PlaintextModulus()}
	opt := options{experiment: "e4", seed: *seed}

	var mu sync.Mutex
	var wg sync.WaitGroup
	mismatches, failures := 0, 0
	next := make(chan int)
	for wk := 0; wk < *workers; wk++ {
		wg.Add(1)
		go func(wk int) {
			defer wg.Done()
			var env *bench.Env
			count := 0
			for i := range next {
				j := jobs[i]
				j.name = set.ID() + ":" + j.name
				deltaTrue, expected := bench.Oracle(j.px, j.py, j.ux, j.uy, j.r)
				var res *bench.Result
				var runErr error
				start := bench.Now()
				func() {
					defer func() {
						if r := recover(); r != nil {
							runErr = fmt.Errorf("panic: %v", r)
						}
					}()
					if env == nil || count%50 == 0 {
						if env, runErr = bench.NewEnv(params, []byte(fmt.Sprintf("e4-%d-%d-%d", *seed, wk, count))); runErr != nil {
							return
						}
					}
					res, runErr = env.RunOnce(j.px, j.py, j.ux, j.uy, j.r, false)
				}()
				count++
				total := bench.SinceMs(start)
				mu.Lock()
				if env != nil {
					runs.Row(row(opt, meta, i, wk, j, deltaTrue, expected, env, res, runErr, total))
				}
				switch {
				case runErr != nil:
					failures++
				case bench.Class(res.Inside, res.Zero) != expected:
					mismatches++
				}
				mu.Unlock()
			}
		}(wk)
	}
	for i := range jobs {
		next <- i
	}
	close(next)
	wg.Wait()
	runs.Close()

	status := "correct"
	if mismatches > 0 || failures > 0 || timingErrs > 0 {
		status = "incorrect"
	}
	summary(&params, status, "", timingErrs, len(jobs), mismatches, failures, peakTiming)
	fmt.Printf("%-44s %-9s %4d/%d wrong, %d failed, %d timing errors, %.0f s\n",
		set.ID(), status, mismatches, len(jobs), failures, timingErrs, time.Since(begin).Seconds())
}

// timedRep runs one keygen plus one evaluation and formats an e4_timing row.
// ok is false when the run failed or returned the wrong class.
func timedRep(set bench.ParamSet, params bgv.Parameters, rep int, seed uint64, j job) (rec []string, ok bool) {
	rec = []string{set.ID(), strconv.Itoa(set.LogN), joinDash(set.LogQ), joinDash(set.LogP), set.Xs, strconv.Itoa(rep)}
	var env *bench.Env
	var res *bench.Result
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		if env, err = bench.NewEnv(params, []byte(fmt.Sprintf("e4-timing-%d-%d", seed, rep))); err != nil {
			return
		}
		res, err = env.RunOnce(j.px, j.py, j.ux, j.uy, j.r, true)
	}()
	if err != nil || env == nil || res == nil {
		msg := "unknown error"
		if err != nil {
			msg = err.Error()
		}
		rec = append(rec, "false", msg)
		for len(rec) < len(e4TimingHeader) {
			rec = append(rec, "")
		}
		return rec, false
	}
	_, expected := bench.Oracle(j.px, j.py, j.ux, j.uy, j.r)
	ok = bench.Class(res.Inside, res.Zero) == expected
	st, sz, nz := env.Setup, env.Sizes, res.Noise
	alloc, sys := bench.HeapNow()
	i := strconv.Itoa
	rec = append(rec, strconv.FormatBool(ok), "",
		bench.F(st.SkGenP), bench.F(st.SkGenU), bench.F(st.CKGShareP), bench.F(st.CKGShareU),
		bench.F(st.RKGR1P), bench.F(st.RKGR1U), bench.F(st.RKGR2P), bench.F(st.RKGR2U), bench.F(st.Server), bench.F(env.KeygenMs),
		bench.F(res.EncryptPMs), bench.F(res.EncryptUMs), bench.F(res.EvalMs),
		bench.F(res.E2SSharePMs), bench.F(res.E2SShareUMs), bench.F(res.E2SFinalMs),
		bench.F(res.GarbleMs), bench.F(res.OTMs), bench.F(res.GCEvalMs),
		i(sz.SecretKey), i(sz.CPK), i(sz.RLK), i(sz.CKGShare), i(sz.RKGShareR1), i(sz.RKGShareR2),
		i(res.CiphertextBytes), i(res.E2SShareBytes), i(res.GarbledBytes),
		bench.F(nz.QBits), bench.F(nz.DeltaBits), bench.F(nz.BudgetDeltaBits), bench.F(nz.BudgetE2SBits), bench.F(nz.FloodMarginBits),
		strconv.FormatUint(alloc, 10), strconv.FormatUint(sys, 10))
	return rec, ok
}

func joinDash(v []int) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, "-")
}
