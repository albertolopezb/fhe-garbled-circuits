package main

import (
	"log"
	"strconv"

	"lattigo-auth-ui-demo/bench"
	"lattigo-auth-ui-demo/internal/demo"
)

var e7Header = []string{"experiment", "phase", "message", "sender", "receiver", "count", "binary_bytes_each", "base64_bytes_each", "base64_bytes_total", "note"}

// runE7 lists every cryptographic message of one assignment with its
// serialized size. The sizes are Lattigo BinarySize / actual byte slices from
// one native run; the base64 column is what the JSON API carries (4 bytes per
// 3). HTTP headers, JSON field names and polling requests are NOT included:
// they need a capture of the real traffic.
func runE7(args []string) {
	params, err := demo.Parameters()
	if err != nil {
		log.Fatal(err)
	}
	env, err := bench.NewEnv(params, []byte("e7"))
	if err != nil {
		log.Fatal(err)
	}
	res, err := env.RunOnce(10, 20, 11, 22, 5, false)
	if err != nil {
		log.Fatal(err)
	}
	w, logFile := openResult("e7_payload", e7Header)
	defer logFile.Close()
	defer w.Close()

	sz := env.Sizes
	b64 := func(n int) int { return (n + 2) / 3 * 4 }
	add := func(phase, msg, from, to string, count, bytes int, note string) {
		w.Row([]string{"e7", phase, msg, from, to, strconv.Itoa(count), strconv.Itoa(bytes), strconv.Itoa(b64(bytes)), strconv.Itoa(count * b64(bytes)), note})
	}
	const both = "each client"
	add("CPK", "CKG share", both, "API", 1, sz.CKGShare, "posted together with RKG round 1")
	add("RLK r1", "RKG round-1 share", both, "API", 1, sz.RKGShareR1, "")
	add("CPK", "collective public key", "API", both, 1, sz.CPK, "setup artifacts")
	add("RLK r1", "aggregated round-1 share", "API", both, 1, sz.RKGShareR1, "setup artifacts")
	add("RLK r2", "RKG round-2 share", both, "API", 1, sz.RKGShareR2, "")
	add("Ciphertexts", "encrypted coordinate", both, "API", 2, res.CiphertextBytes, "x and y")
	add("E2S", "Enc(delta)", "API", both, 1, res.CiphertextBytes, "")
	add("E2S", "public E2S share", both, "API", 1, res.E2SShareBytes, "")
	add("E2S", "aggregated E2S share", "API", both, 1, res.E2SShareBytes, "")
	add("Garbled circuit", "garbled tables + decode bits", "User", "API", 1, res.GarbledBytes, "relayed to Police")
	add("Garbled circuit", "garbler input labels", "User", "API", 1, res.LabelBytes, "relayed to Police")
	add("OT otA", "sender message", "User", "API", 1, res.OTABytes, "relayed to Police")
	add("OT otR", "receiver message", "Police", "API", 1, res.OTRBytes, "relayed to User")
	add("OT otE", "encrypted label pairs", "User", "API", 1, res.OTEBytes, "relayed to Police")
	add("Result", "classification string", "Police", "API", 1, 24, "upper bound on the text length")
	log.Printf("e7 done -> results/e7_payload.csv")
}
