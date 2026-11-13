// Command bench runs the native paper experiments and writes one CSV row per run.
//
//	go run ./cmd/bench hardware
//	go run ./cmd/bench e1 -seed 1 -n 10000
//	go run ./cmd/bench e2
//	go run ./cmd/bench e3 -seed 1 -n 1000
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"lattigo-auth-ui-demo/bench"
	"lattigo-auth-ui-demo/internal/demo"
)

// job is one evaluation to run: both points, the radius and a label.
type job struct {
	name              string
	px, py, ux, uy, r int64
}

// options are the settings shared by e1, e2 and e3.
type options struct {
	experiment string
	out        string
	seed       uint64
	rekey      int  // new collective keys every rekey runs
	noise      bool // measure ciphertext noise (uses the summed secret key)
	warmup     int
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "hardware":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		out := fs.String("out", "results/hardware.json", "output file")
		fs.Parse(args)
		h, err := bench.WriteHardware(*out)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("wrote %s (commit %s, %s)\n", *out, h.GitCommit, h.GoVersion)
		if h.ProbeError != "" {
			fmt.Println("machine probe failed:", h.ProbeError)
		}
	case "e1", "e2", "e3":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		out := fs.String("out", "results/"+cmd+".csv", "output CSV")
		seed := fs.Uint64("seed", 1, "seed for the random inputs and the CRS")
		n := fs.Int("n", defaultN(cmd), "number of random runs (e1, e3)")
		rekey := fs.Int("rekey", 50, "generate new collective keys every this many runs")
		fine := fs.Int64("fine", 24, "e2: half-width of the step-1 window around each limit")
		coarse := fs.Int64("coarse", 1000, "e2: step of the wide sweep from -70000 to 70000")
		fs.Parse(args)

		opt := options{experiment: cmd, out: *out, seed: *seed, rekey: *rekey, warmup: 3}
		var jobs []job
		switch cmd {
		case "e1":
			jobs = append(fixedCases(), randomCases(*seed, *n)...)
		case "e2":
			jobs = sweepCases(*fine, *coarse)
		case "e3":
			opt.noise = true
			jobs = append(fixedCases(), randomCases(*seed, *n)...)
		}
		mismatches, failures, err := run(opt, jobs)
		if err != nil {
			log.Fatal(err)
		}
		// E2 is expected to mismatch outside the safe range; E1 and E3 are not.
		if cmd != "e2" && (mismatches > 0 || failures > 0) {
			os.Exit(1)
		}
	case "e4":
		runE4(args)
	case "e4set": // internal: one parameter set, started by e4
		runE4Set(args)
	case "e5a":
		runE5a(args)
	case "e5b":
		runE5b(args)
	case "e11":
		runE11(args)
	case "e6":
		runE6(args)
	case "e6run": // internal: one process of e6
		runE6Run(args)
	case "e7":
		runE7(args)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: bench hardware|e1|e2|e3|e4|e5a|e5b|e6|e7|e11 [flags]   (bench e1 -h lists the flags)")
	os.Exit(2)
}

func defaultN(cmd string) int {
	if cmd == "e3" {
		return 1000
	}
	return 10000
}

// fixedCases are the named E1 cases: the three classes, both ends of the
// delta range, radius zero, identical points and opposite corners.
func fixedCases() []job {
	return []job{
		{"inside", 10, 20, 11, 22, 5},          // delta = -20
		{"boundary", 10, 20, 13, 24, 5},        // delta = 0
		{"outside", 10, 20, 14, 24, 5},         // delta = 7
		{"delta_min", 0, 0, 0, 0, 100},         // delta = -10000
		{"delta_max", 100, 100, 0, 0, 0},       // delta = 20000
		{"identical_r0", 5, 5, 5, 5, 0},        // delta = 0
		{"identical_r1", 50, 50, 50, 50, 1},    // delta = -1
		{"corners_r100", 0, 0, 100, 100, 100},  // delta = 10000
		{"corners_anti_r0", 0, 100, 100, 0, 0}, // delta = 20000
		{"adjacent_r1", 0, 0, 0, 1, 1},         // delta = 0
		{"adjacent_r0", 0, 0, 0, 1, 0},         // delta = 1
	}
}

// randomCases draws n evaluations with every coordinate and the radius uniform
// in [0, MaxProximityInput], from a PCG generator seeded with seed.
func randomCases(seed uint64, n int) []job {
	rng := rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15))
	draw := func() int64 { return rng.Int64N(demo.MaxProximityInput + 1) }
	jobs := make([]job, n)
	for i := range jobs {
		jobs[i] = job{"random", draw(), draw(), draw(), draw(), draw()}
	}
	return jobs
}

// deltaCase builds inputs whose true integer delta is exactly v, ignoring the
// application's input bounds: an odd w equals a^2 - r^2 with a and r adjacent,
// and an even v uses py = 1 to add one.
func deltaCase(v int64) job {
	w, py := v, int64(0)
	if v%2 == 0 {
		w, py = v-1, 1
	}
	abs := w
	if abs < 0 {
		abs = -abs
	}
	a, r := (abs+1)/2, (abs-1)/2
	if w < 0 {
		a, r = r, a
	}
	return job{"sweep", a, py, 0, 0, r}
}

// sweepCases covers delta from -70000 to 70000 in steps of coarse, plus every
// integer within fine of -32768 and of +32768.
func sweepCases(fine, coarse int64) []job {
	var jobs []job
	for v := int64(-70000); v <= 70000; v += coarse {
		jobs = append(jobs, deltaCase(v))
	}
	for _, center := range []int64{-32768, 32768} {
		for v := center - fine; v <= center+fine; v++ {
			jobs = append(jobs, deltaCase(v))
		}
	}
	return jobs
}

// run executes the jobs in order, writes one row each, and returns how many
// rows had a wrong class and how many runs returned an error.
func run(opt options, jobs []job) (mismatches, failures int, err error) {
	stamp := time.Now().Format("20060102-150405")
	if err := os.MkdirAll("results/raw", 0o755); err != nil {
		return 0, 0, err
	}
	logFile, err := os.Create(filepath.Join("results", "raw", opt.experiment+"-"+stamp+".log"))
	if err != nil {
		return 0, 0, err
	}
	defer logFile.Close()
	log.SetOutput(io.MultiWriter(os.Stderr, logFile))

	// Keep an earlier result file instead of overwriting it.
	if _, statErr := os.Stat(opt.out); statErr == nil {
		kept := filepath.Join("results", "raw", opt.experiment+"-replaced-at-"+stamp+".csv")
		if err := os.Rename(opt.out, kept); err != nil {
			return 0, 0, err
		}
		log.Printf("previous %s kept as %s", opt.out, kept)
	}

	params, err := demo.Parameters()
	if err != nil {
		return 0, 0, err
	}
	lit := params.ParametersLiteral()
	hash, dirty := bench.GitCommit()
	meta := bench.Meta{Commit: hash, Dirty: dirty, GoVersion: runtime.Version(),
		LogN: params.LogN(), LogQ: bench.Ints(logs(lit.Q)), LogP: bench.Ints(logs(lit.P)), T: params.PlaintextModulus()}
	log.Printf("%s: %d runs, seed %d, rekey every %d, commit %s dirty=%v, %s", opt.experiment, len(jobs), opt.seed, opt.rekey, hash, dirty, meta.GoVersion)

	w, err := bench.Open(opt.out, bench.Header)
	if err != nil {
		return 0, 0, err
	}
	defer w.Close()

	newEnv := func(keyID int) (*bench.Env, error) {
		return bench.NewEnv(params, []byte(fmt.Sprintf("bench-%d-%d", opt.seed, keyID)))
	}
	env, err := newEnv(0)
	if err != nil {
		return 0, 0, err
	}
	for i := 0; i < opt.warmup; i++ {
		if _, err := env.RunOnce(10, 20, 11, 22, 5, opt.noise); err != nil {
			return 0, 0, fmt.Errorf("warm-up run %d: %w", i, err)
		}
	}
	log.Printf("%d warm-up runs discarded", opt.warmup)

	begin := time.Now()
	keyID := 0
	for i, j := range jobs {
		if i > 0 && opt.rekey > 0 && i%opt.rekey == 0 {
			keyID++
			if env, err = newEnv(keyID); err != nil {
				return mismatches, failures, err
			}
		}
		deltaTrue, expected := bench.Oracle(j.px, j.py, j.ux, j.uy, j.r)
		start := bench.Now()
		res, runErr := env.RunOnce(j.px, j.py, j.ux, j.uy, j.r, opt.noise)
		total := bench.SinceMs(start)

		rec := row(opt, meta, i, keyID, j, deltaTrue, expected, env, res, runErr, total)
		if err := w.Row(rec); err != nil {
			return mismatches, failures, err
		}
		switch {
		case runErr != nil:
			failures++
			log.Printf("run %d FAILED: %v", i, runErr)
		case bench.Class(res.Inside, res.Zero) != expected:
			mismatches++
			if opt.experiment != "e2" {
				log.Printf("run %d MISMATCH: %+v delta=%d expected %s got %s", i, j, deltaTrue, expected, bench.Class(res.Inside, res.Zero))
			}
		}
		if (i+1)%500 == 0 {
			log.Printf("%d/%d runs, %d mismatches, %d failures, %.0f s", i+1, len(jobs), mismatches, failures, time.Since(begin).Seconds())
		}
	}
	log.Printf("%s done: %d runs, %d mismatches, %d failed runs, %.1f s -> %s", opt.experiment, len(jobs), mismatches, failures, time.Since(begin).Seconds(), opt.out)
	return mismatches, failures, nil
}

// row formats one CSV record in the order of bench.Header.
func row(opt options, meta bench.Meta, i, keyID int, j job, deltaTrue int64, expected string,
	env *bench.Env, res *bench.Result, runErr error, total float64) []string {
	itoa := func(v int64) string { return strconv.FormatInt(v, 10) }
	alloc, sys := bench.HeapNow()
	rec := []string{
		opt.experiment, strconv.Itoa(i), j.name, strconv.FormatUint(opt.seed, 10), strconv.Itoa(keyID),
		meta.Commit, strconv.FormatBool(meta.Dirty), meta.GoVersion,
		strconv.Itoa(meta.LogN), meta.LogQ, meta.LogP, strconv.FormatUint(meta.T, 10),
		itoa(j.px), itoa(j.py), itoa(j.ux), itoa(j.uy), itoa(j.r),
		itoa(deltaTrue),
	}
	if runErr != nil {
		rec = append(rec, "", expected, "", "false", runErr.Error(), bench.F(env.KeygenMs))
		rec = append(rec, "", "", "", "", "", "", bench.F(total), "")
	} else {
		observed := bench.Class(res.Inside, res.Zero)
		rec = append(rec, itoa(res.DeltaDecoded), expected, observed, strconv.FormatBool(observed == expected), "",
			bench.F(env.KeygenMs), bench.F(res.EncryptMs), bench.F(res.EvalMs), bench.F(res.E2SMs),
			bench.F(res.GarbleMs), bench.F(res.OTMs), bench.F(res.GCEvalMs), bench.F(total),
			strconv.Itoa(res.GarbledBytes))
	}
	rec = append(rec, strconv.FormatUint(alloc, 10), strconv.FormatUint(sys, 10))
	if res != nil && res.Noise != nil {
		n := res.Noise
		rec = append(rec, bench.F(n.QBits), bench.F(n.RawBits), bench.F(n.FreshBits), bench.F(n.DeltaBits),
			bench.F(n.DeltaStdBits), bench.F(n.E2SBits), bench.F(n.BudgetDeltaBits), bench.F(n.BudgetE2SBits), bench.F(n.FloodMarginBits))
	} else {
		rec = append(rec, "", "", "", "", "", "", "", "", "")
	}
	return rec
}

// logs returns the bit length of each modulus in a chain.
func logs(moduli []uint64) []int {
	out := make([]int, len(moduli))
	for i, q := range moduli {
		// Rounded log2, so a prime just above 2^56 is still reported as 56.
		out[i] = int(math.Round(math.Log2(float64(q))))
	}
	return out
}

// logMulti sends log output to stderr and to the raw log file.
func logMulti(f *os.File) io.Writer { return io.MultiWriter(os.Stderr, f) }
