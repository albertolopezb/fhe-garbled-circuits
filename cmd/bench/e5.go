package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"lattigo-auth-ui-demo/bench"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

var e5aHeader = []string{
	"experiment", "t", "share_bits", "max_coord", "max_radius", "and_gates", "garbled_bytes",
	"run_id", "case", "px", "py", "ux", "uy", "r", "delta_true", "delta_decoded", "class_expected", "class_observed", "ok", "error",
	"t_keygen_ms", "t_encrypt_ms", "t_eval_ms", "t_e2s_ms", "t_garble_ms", "t_ot_ms", "t_gc_eval_ms",
	"q_bits", "delta_bits", "budget_delta_bits", "budget_e2s_bits", "flood_margin_bits",
	"seed", "commit", "dirty", "go_version",
}

var e5bHeader = []string{
	"experiment", "d", "variant", "max_coord", "run_id", "case",
	"ciphertexts_per_party", "upload_bytes_per_party",
	"rot_keys", "t_rotkey_share_p_ms", "t_rotkey_share_u_ms", "t_rotkey_server_ms", "rotkey_share_bytes", "rotkey_bytes",
	"r", "delta_true", "delta_decoded", "class_expected", "class_observed", "ok", "error",
	"t_encrypt_p_ms", "t_encrypt_u_ms", "t_eval_ms", "t_e2s_ms", "t_garble_ms", "t_ot_ms", "t_gc_eval_ms",
	"q_bits", "delta_bits", "budget_delta_bits", "budget_e2s_bits", "flood_margin_bits",
	"heap_alloc_bytes", "seed", "commit", "dirty", "go_version",
}

// appParams returns the application's chain (LogN 14, 438-bit QP) with plaintext modulus t.
func appParams(t uint64) (bgv.Parameters, error) {
	return bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN: 14, LogQ: []int{56, 55, 55, 54, 54, 54}, LogP: []int{55, 55}, PlaintextModulus: t,
	})
}

// openResult archives an existing result file and starts a new one with a raw log.
func openResult(name string, header []string) (*bench.Writer, *os.File) {
	stamp := time.Now().Format("20060102-150405")
	if err := os.MkdirAll("results/raw", 0o755); err != nil {
		log.Fatal(err)
	}
	out := "results/" + name + ".csv"
	if _, err := os.Stat(out); err == nil {
		kept := filepath.Join("results", "raw", name+"-replaced-at-"+stamp+".csv")
		if err := os.Rename(out, kept); err != nil {
			log.Fatal(err)
		}
	}
	logFile, err := os.Create(filepath.Join("results", "raw", name+"-"+stamp+".log"))
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(logMulti(logFile))
	w, err := bench.Open(out, header)
	if err != nil {
		log.Fatal(err)
	}
	return w, logFile
}

// runE5a varies the plaintext modulus t: wider shares, a wider circuit, a
// larger safe coordinate range.
func runE5a(args []string) {
	fs := flag.NewFlagSet("e5a", flag.ExitOnError)
	n := fs.Int("n", 300, "random runs per modulus (plus 4 edge cases)")
	seed := fs.Uint64("seed", 1, "seed for the random inputs and the CRS")
	moduli := fs.String("t", "65537,163841,786433", "plaintext moduli, each a prime = 1 mod 2N")
	fs.Parse(args)

	w, logFile := openResult("e5a", e5aHeader)
	defer logFile.Close()
	defer w.Close()
	hash, dirty := bench.GitCommit()
	tail := []string{strconv.FormatUint(*seed, 10), hash, strconv.FormatBool(dirty), runtime.Version()}

	for _, field := range strings.Split(*moduli, ",") {
		t, err := strconv.ParseUint(strings.TrimSpace(field), 10, 64)
		if err != nil {
			log.Fatal(err)
		}
		head := []string{"e5a", strconv.FormatUint(t, 10)}
		params, err := appParams(t)
		if err != nil {
			log.Printf("t=%d: invalid parameters: %v", t, err)
			rec := append(head, make([]string, len(e5aHeader)-len(head)-len(tail))...)
			rec[19] = "invalid parameters: " + err.Error()
			w.Row(append(rec, tail...))
			continue
		}
		m := bench.MaxCoordinate(t, 2)
		rmax := bench.MaxCoordinate(t, 1)
		env, err := bench.NewEnv(params, []byte(fmt.Sprintf("e5a-%d-%d", *seed, t)))
		if err != nil {
			log.Fatal(err)
		}
		head = append(head, strconv.Itoa(env.Bits), strconv.FormatInt(m, 10), strconv.FormatInt(rmax, 10), strconv.Itoa(env.Circuit.NumAND()))

		jobs := []job{
			{"delta_max", m, m, 0, 0, 0}, {"delta_min", 0, 0, 0, 0, rmax},
			{"boundary", 0, 0, 3, 4, 5}, {"identical_r0", m, m, m, m, 0},
		}
		rng := rand.New(rand.NewPCG(*seed, t))
		for i := 0; i < *n; i++ {
			jobs = append(jobs, job{"random", rng.Int64N(m + 1), rng.Int64N(m + 1), rng.Int64N(m + 1), rng.Int64N(m + 1), rng.Int64N(m + 1)})
		}
		for i := 0; i < 3; i++ { // warm-up, discarded
			env.RunOnce(1, 2, 3, 4, 5, true)
		}
		wrong, failed := 0, 0
		for i, j := range jobs {
			deltaTrue, expected := bench.Oracle(j.px, j.py, j.ux, j.uy, j.r)
			res, runErr := env.RunOnce(j.px, j.py, j.ux, j.uy, j.r, true)
			rec := append([]string{}, head...)
			if runErr != nil {
				failed++
				rec = append(rec, "", strconv.Itoa(i), j.name, i64(j.px), i64(j.py), i64(j.ux), i64(j.uy), i64(j.r), i64(deltaTrue), "", expected, "", "false", runErr.Error(),
					"", "", "", "", "", "", "", "", "", "", "", "")
			} else {
				observed := bench.Class(res.Inside, res.Zero)
				if observed != expected {
					wrong++
				}
				nz := res.Noise
				rec = append(rec, strconv.Itoa(res.GarbledBytes), strconv.Itoa(i), j.name, i64(j.px), i64(j.py), i64(j.ux), i64(j.uy), i64(j.r), i64(deltaTrue), i64(res.DeltaDecoded),
					expected, observed, strconv.FormatBool(observed == expected), "",
					bench.F(env.KeygenMs), bench.F(res.EncryptMs), bench.F(res.EvalMs), bench.F(res.E2SMs), bench.F(res.GarbleMs), bench.F(res.OTMs), bench.F(res.GCEvalMs),
					bench.F(nz.QBits), bench.F(nz.DeltaBits), bench.F(nz.BudgetDeltaBits), bench.F(nz.BudgetE2SBits), bench.F(nz.FloodMarginBits))
			}
			w.Row(append(rec, tail...))
		}
		log.Printf("e5a t=%d: %d share bits, M=%d, %d AND gates, %d runs, %d wrong, %d failed", t, env.Bits, m, env.Circuit.NumAND(), len(jobs), wrong, failed)
	}
}

// runE5b varies the number of dimensions d at t = 65537 and compares the
// three evaluation variants.
func runE5b(args []string) {
	fs := flag.NewFlagSet("e5b", flag.ExitOnError)
	n := fs.Int("n", 30, "timed runs per (d, variant); 3 warm-up runs are added and discarded")
	seed := fs.Uint64("seed", 1, "seed for the random inputs and the CRS")
	dims := fs.String("d", "2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,24,32", "dimensions to test")
	fs.Parse(args)

	w, logFile := openResult("e5b", e5bHeader)
	defer logFile.Close()
	defer w.Close()
	hash, dirty := bench.GitCommit()
	params, err := appParams(65537)
	if err != nil {
		log.Fatal(err)
	}
	t := params.PlaintextModulus()
	rmax := bench.MaxCoordinate(t, 1)

	for _, field := range strings.Split(*dims, ",") {
		d, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil {
			log.Fatal(err)
		}
		m := bench.MaxCoordinate(t, d)
		for _, variant := range []string{bench.VariantScalarEach, bench.VariantScalarOnce, bench.VariantPacked} {
			env, err := bench.NewEnv(params, []byte(fmt.Sprintf("e5b-%d-%d", *seed, d)))
			if err != nil {
				log.Fatal(err)
			}
			var rk bench.RotationKeys
			if variant == bench.VariantPacked {
				if rk, err = env.AddRotationKeys(d, []byte(fmt.Sprintf("e5b-rot-%d-%d", *seed, d))); err != nil {
					log.Printf("e5b d=%d %s: rotation keys failed: %v", d, variant, err)
					continue
				}
			}
			rng := rand.New(rand.NewPCG(*seed, uint64(d)))
			wrong, failed := 0, 0
			for i := -3; i < *n; i++ {
				p, u := make([]int64, d), make([]int64, d)
				r := rng.Int64N(rmax + 1)
				name := "random"
				switch i {
				case 0: // largest delta: opposite corners, radius 0
					name, r = "delta_max", 0
					for k := range p {
						p[k] = m
					}
				case 1: // smallest delta: same point, largest radius
					name, r = "delta_min", rmax
				case 2: // boundary: distance^2 == r^2
					name, r = "boundary", 0
				default:
					for k := range p {
						p[k], u[k] = rng.Int64N(m+1), rng.Int64N(m+1)
					}
				}
				deltaTrue, expected := bench.OracleDims(p, u, r)
				res, runErr := env.RunDims(p, u, r, variant, true)
				if i < 0 {
					continue // warm-up
				}
				alloc, _ := bench.HeapNow()
				rec := []string{"e5b", strconv.Itoa(d), variant, i64(m), strconv.Itoa(i), name}
				rot := []string{strconv.Itoa(rk.Keys), bench.F(rk.GenSharePMs), bench.F(rk.GenShareUMs), bench.F(rk.ServerMs), strconv.Itoa(rk.ShareBytes), strconv.Itoa(rk.KeyBytes)}
				if runErr != nil {
					failed++
					rec = append(rec, "", "")
					rec = append(rec, rot...)
					rec = append(rec, i64(r), i64(deltaTrue), "", expected, "", "false", runErr.Error(), "", "", "", "", "", "", "", "", "", "", "", "")
				} else {
					observed := bench.Class(res.Inside, res.Zero)
					if observed != expected {
						wrong++
					}
					nz := res.Noise
					rec = append(rec, strconv.Itoa(res.CiphertextsPerParty), strconv.Itoa(res.UploadBytesPerParty))
					rec = append(rec, rot...)
					rec = append(rec, i64(r), i64(deltaTrue), i64(res.DeltaDecoded), expected, observed, strconv.FormatBool(observed == expected), "",
						bench.F(res.EncryptPMs), bench.F(res.EncryptUMs), bench.F(res.EvalMs), bench.F(res.E2SMs), bench.F(res.GarbleMs), bench.F(res.OTMs), bench.F(res.GCEvalMs),
						bench.F(nz.QBits), bench.F(nz.DeltaBits), bench.F(nz.BudgetDeltaBits), bench.F(nz.BudgetE2SBits), bench.F(nz.FloodMarginBits))
				}
				rec = append(rec, strconv.FormatUint(alloc, 10), strconv.FormatUint(*seed, 10), hash, strconv.FormatBool(dirty), runtime.Version())
				w.Row(rec)
			}
			log.Printf("e5b d=%d M=%d %-18s %d runs, %d wrong, %d failed", d, m, variant, *n, wrong, failed)
		}
	}
}

func i64(v int64) string { return strconv.FormatInt(v, 10) }
