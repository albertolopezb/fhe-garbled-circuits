package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"runtime"
	"strconv"

	"lattigo-auth-ui-demo/bench"
	"lattigo-auth-ui-demo/internal/demo"
)

var e11ViewHeader = []string{"experiment", "case", "run_id", "delta_true", "server_view_slot0", "class_observed", "ok", "seed", "commit", "dirty", "go_version"}

var e11TestHeader = []string{"experiment", "test", "case", "samples", "bins", "chi_square", "df", "z_approx", "p_approx", "note"}

// chiSquareUniform returns the chi-square statistic of counts against a
// uniform expectation, with the Wilson-Hilferty normal approximation of the
// upper-tail p-value.
func chiSquareUniform(counts []float64) (stat float64, df int, z, p float64) {
	total := 0.0
	for _, c := range counts {
		total += c
	}
	expected := total / float64(len(counts))
	for _, c := range counts {
		stat += (c - expected) * (c - expected) / expected
	}
	df = len(counts) - 1
	z, p = wilsonHilferty(stat, df)
	return
}

// chiSquareHomogeneity tests whether two histograms come from one distribution.
func chiSquareHomogeneity(a, b []float64) (stat float64, df int, z, p float64) {
	na, nb := 0.0, 0.0
	for i := range a {
		na += a[i]
		nb += b[i]
	}
	for i := range a {
		col := a[i] + b[i]
		if col == 0 {
			continue
		}
		ea, eb := col*na/(na+nb), col*nb/(na+nb)
		stat += (a[i]-ea)*(a[i]-ea)/ea + (b[i]-eb)*(b[i]-eb)/eb
	}
	df = len(a) - 1
	z, p = wilsonHilferty(stat, df)
	return
}

func wilsonHilferty(stat float64, df int) (z, p float64) {
	k := float64(df)
	z = (math.Cbrt(stat/k) - (1 - 2/(9*k))) / math.Sqrt(2/(9*k))
	return z, 0.5 * math.Erfc(z/math.Sqrt2)
}

// runE11 samples the server's view of the E2S step for three fixed inputs and
// tests it for uniformity and for independence from the input.
func runE11(args []string) {
	fs := flag.NewFlagSet("e11", flag.ExitOnError)
	n := fs.Int("n", 1000, "runs per case")
	pooled := fs.Int("pooled", 100, "runs per case whose every slot enters the full-resolution test")
	seed := fs.Uint64("seed", 1, "seed for the CRS")
	fs.Parse(args)

	views, logFile := openResult("e11_serverview", e11ViewHeader)
	defer logFile.Close()
	defer views.Close()
	tests, err := bench.Open("results/e11_chisq.csv", e11TestHeader)
	if err != nil {
		log.Fatal(err)
	}
	defer tests.Close()

	params, err := demo.Parameters()
	if err != nil {
		log.Fatal(err)
	}
	t := params.PlaintextModulus()
	hash, dirty := bench.GitCommit()
	cases := []job{{"inside", 10, 20, 11, 22, 5}, {"boundary", 10, 20, 13, 24, 5}, {"outside", 10, 20, 90, 90, 5}}
	const coarseBins = 16
	coarse := make(map[string][]float64)

	for _, c := range cases {
		fine := make([]float64, t)
		coarse[c.name] = make([]float64, coarseBins)
		deltaTrue, expected := bench.Oracle(c.px, c.py, c.ux, c.uy, c.r)
		var env *bench.Env
		for i := 0; i < *n; i++ {
			if i%50 == 0 {
				if env, err = bench.NewEnv(params, []byte(fmt.Sprintf("e11-%d-%s-%d", *seed, c.name, i))); err != nil {
					log.Fatal(err)
				}
				env.CaptureServerView = true
			}
			res, err := env.RunOnce(c.px, c.py, c.ux, c.uy, c.r, false)
			if err != nil {
				log.Printf("e11 %s run %d FAILED: %v", c.name, i, err)
				views.Row([]string{"e11", c.name, strconv.Itoa(i), i64(deltaTrue), "", "", "false", strconv.FormatUint(*seed, 10), hash, strconv.FormatBool(dirty), runtime.Version()})
				continue
			}
			observed := bench.Class(res.Inside, res.Zero)
			v0 := res.ServerView[0]
			coarse[c.name][v0*coarseBins/t]++
			if i < *pooled {
				for _, v := range res.ServerView {
					fine[v]++
				}
			}
			views.Row([]string{"e11", c.name, strconv.Itoa(i), i64(deltaTrue), strconv.FormatUint(v0, 10), observed,
				strconv.FormatBool(observed == expected), strconv.FormatUint(*seed, 10), hash, strconv.FormatBool(dirty), runtime.Version()})
		}
		stat, df, z, p := chiSquareUniform(fine)
		total := float64(*pooled) * float64(params.MaxSlots())
		tests.Row([]string{"e11", "uniform_all_slots", c.name, bench.F(total), strconv.Itoa(len(fine)), bench.F(stat), strconv.Itoa(df), bench.F(z), bench.F(p),
			"every slot of the first runs; one bin per residue mod t"})
		stat, df, z, p = chiSquareUniform(coarse[c.name])
		tests.Row([]string{"e11", "uniform_slot0", c.name, strconv.Itoa(*n), strconv.Itoa(coarseBins), bench.F(stat), strconv.Itoa(df), bench.F(z), bench.F(p),
			"slot 0 (the slot that carries delta), one value per run"})
		log.Printf("e11 %s: %d runs done", c.name, *n)
	}
	for _, pair := range [][2]string{{"inside", "outside"}, {"inside", "boundary"}, {"boundary", "outside"}} {
		stat, df, z, p := chiSquareHomogeneity(coarse[pair[0]], coarse[pair[1]])
		tests.Row([]string{"e11", "same_distribution_slot0", pair[0] + "_vs_" + pair[1], strconv.Itoa(2 * *n), strconv.Itoa(coarseBins), bench.F(stat), strconv.Itoa(df), bench.F(z), bench.F(p),
			"two-sample chi-square: does the server's slot-0 view depend on the class?"})
	}
	log.Printf("e11 done -> results/e11_serverview.csv, results/e11_chisq.csv")
}
