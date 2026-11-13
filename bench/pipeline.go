// Package bench is the native measurement harness for the paper experiments.
// It drives the same building blocks as the application (internal/demo and
// internal/gc) without the HTTP API or the browser. Nothing here is used by
// the application itself.
package bench

import (
	crand "crypto/rand"
	"fmt"
	"math"
	"math/big"

	"lattigo-auth-ui-demo/internal/demo"
	"lattigo-auth-ui-demo/internal/gc"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/multiparty/mpbgv"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// FloodSigmaLog2 is log2 of the E2S noise-flooding standard deviation.
const FloodSigmaLog2 = 30

// FloodNoise is the E2S flooding distribution used by the application (sigma = 2^30).
var FloodNoise = ring.DiscreteGaussian{Sigma: 1 << FloodSigmaLog2, Bound: 6 * (1 << FloodSigmaLog2)}

// Env holds one Police + User pair after collective key generation.
type Env struct {
	Params   bgv.Parameters
	Encoder  *bgv.Encoder
	SkP, SkU *rlwe.SecretKey
	// SkSum = SkP + SkU. No party ever holds it in the protocol; it exists only
	// so the harness can measure ciphertext noise.
	SkSum   *rlwe.SecretKey
	CPK     *rlwe.PublicKey
	EVK     *rlwe.MemEvaluationKeySet
	RLK     *rlwe.RelinearizationKey
	Circuit *gc.Circuit
	Bits    int // width of one share: bit length of t
	// CaptureServerView makes every run record what the API can compute from
	// the public E2S shares (used by E11).
	CaptureServerView bool
	KeygenMs          float64
	Setup             SetupTimes
	Sizes             Sizes
}

// NewEnv runs the two-party CPK and RLK generation (both RLK rounds) in one
// process, in the same order as the application. crsSeed keys the common
// reference string; the secret keys come from Lattigo's own crypto randomness
// and cannot be seeded.
func NewEnv(params bgv.Parameters, crsSeed []byte) (*Env, error) {
	start := Now()
	crs, err := sampling.NewKeyedPRNG(crsSeed)
	if err != nil {
		return nil, err
	}
	var st SetupTimes
	lap := Now()
	tick := func(dst *float64) { *dst += SinceMs(lap); lap = Now() }
	kgen := rlwe.NewKeyGenerator(params)
	skP := kgen.GenSecretKeyNew()
	tick(&st.SkGenP)
	skU := kgen.GenSecretKeyNew()
	tick(&st.SkGenU)

	ckg := multiparty.NewPublicKeyGenProtocol(params)
	crpCKG := ckg.SampleCRP(crs)
	sP, sU, sC := ckg.AllocateShare(), ckg.AllocateShare(), ckg.AllocateShare()
	tick(&st.Server)
	ckg.GenShare(skP, crpCKG, &sP)
	tick(&st.CKGShareP)
	ckg.GenShare(skU, crpCKG, &sU)
	tick(&st.CKGShareU)
	ckg.AggregateShares(sP, sC, &sC)
	ckg.AggregateShares(sU, sC, &sC)
	cpk := rlwe.NewPublicKey(params)
	ckg.GenPublicKey(sC, crpCKG, cpk)

	rkg := multiparty.NewRelinearizationKeyGenProtocol(params)
	crpRKG := rkg.SampleCRP(crs)
	ephP, r1P, _ := rkg.AllocateShare()
	ephU, r1U, _ := rkg.AllocateShare()
	_, r1C, _ := rkg.AllocateShare()
	tick(&st.Server)
	rkg.GenShareRoundOne(skP, crpRKG, ephP, &r1P)
	tick(&st.RKGR1P)
	rkg.GenShareRoundOne(skU, crpRKG, ephU, &r1U)
	tick(&st.RKGR1U)
	rkg.AggregateShares(r1P, r1C, &r1C)
	rkg.AggregateShares(r1U, r1C, &r1C)
	_, _, r2P := rkg.AllocateShare()
	_, _, r2U := rkg.AllocateShare()
	_, _, r2C := rkg.AllocateShare()
	tick(&st.Server)
	rkg.GenShareRoundTwo(ephP, skP, r1C, &r2P)
	tick(&st.RKGR2P)
	rkg.GenShareRoundTwo(ephU, skU, r1C, &r2U)
	tick(&st.RKGR2U)
	rkg.AggregateShares(r2P, r2C, &r2C)
	rkg.AggregateShares(r2U, r2C, &r2C)
	rlk := rlwe.NewRelinearizationKey(params)
	rkg.GenRelinearizationKey(r1C, r2C, rlk)
	tick(&st.Server)
	keygenMs := SinceMs(start)
	sizes := Sizes{SecretKey: skP.BinarySize(), CPK: cpk.BinarySize(), RLK: rlk.BinarySize(),
		CKGShare: sP.BinarySize(), RKGShareR1: r1P.BinarySize(), RKGShareR2: r2P.BinarySize()}

	// The application's circuit for t = 65537; the generic one for any other t.
	bits, circuit := gc.ShareBits, gc.ShareCompareCircuit()
	if pm := params.PlaintextModulus(); pm != gc.Modulus {
		bits = big.NewInt(int64(pm)).BitLen()
		circuit = CompareCircuit(bits, pm)
	}

	skSum := rlwe.NewSecretKey(params)
	params.RingQP().Add(skP.Value, skU.Value, skSum.Value)

	return &Env{
		Params: params, Encoder: bgv.NewEncoder(params),
		SkP: skP, SkU: skU, SkSum: skSum,
		CPK: cpk, EVK: rlwe.NewMemEvaluationKeySet(rlk), RLK: rlk,
		Circuit: circuit, Bits: bits, KeygenMs: keygenMs, Setup: st, Sizes: sizes,
	}, nil
}

// Result is one end-to-end run: BGV -> E2S -> garbled circuit with OT.
type Result struct {
	ShareP, ShareU uint64
	DeltaDecoded   int64 // centered (ShareP + ShareU) mod t: what the circuit compares
	Inside, Zero   bool  // circuit outputs [delta < 0, delta == 0]
	GarbledBytes   int

	EncryptMs, EvalMs, E2SMs, GarbleMs, OTMs, GCEvalMs float64
	// Per-role parts: EncryptMs = EncryptPMs + EncryptUMs (two ciphertexts each).
	EncryptPMs, EncryptUMs               float64
	E2SSharePMs, E2SShareUMs, E2SFinalMs float64
	CiphertextBytes, E2SShareBytes       int
	// Binary sizes of the circuit messages: garbler's own labels, otA, otR, otE.
	LabelBytes, OTABytes, OTRBytes, OTEBytes int

	Noise *Noise // nil unless requested

	// ServerView is c0 + aggregated public E2S share, decoded slot by slot: the
	// only plaintext-domain value the API can derive. Nil unless requested.
	ServerView []uint64
}

// Noise holds log2 magnitudes of t*Dec(ct) centered mod Q, which equals
// m + t*e for Lattigo's BGV encoding. Decryption is correct while that value
// stays below Q/2, so budget = QBits - 1 - max.
type Noise struct {
	QBits           float64 // log2 of the ciphertext modulus at the ciphertext level
	RawBits         float64 // log2 max |Dec(ct)| WITHOUT the factor t (encoding sanity check)
	FreshBits       float64 // log2 max |m + t*e| of a fresh input ciphertext
	DeltaBits       float64 // same, for Enc(delta) after the multiplication
	DeltaStdBits    float64 // log2 std of m + t*e for Enc(delta)
	E2SBits         float64 // same max, for c0 + aggregated E2S share (after flooding)
	BudgetDeltaBits float64 // QBits - 1 - DeltaBits
	BudgetE2SBits   float64 // QBits - 1 - E2SBits
	// FloodMarginBits = FloodSigmaLog2 - (DeltaStdBits - log2 t): how many bits the
	// flooding noise of ONE party exceeds the ciphertext noise it has to hide.
	FloodMarginBits float64
}

// Class turns the two circuit output bits into the application's three classes.
func Class(inside, zero bool) string {
	switch {
	case zero:
		return "boundary"
	case inside:
		return "inside"
	default:
		return "outside"
	}
}

// Oracle is the plaintext reference: the true integer delta = dist^2 - R^2 and its class.
func Oracle(px, py, ux, uy, r int64) (delta int64, class string) {
	dx, dy := px-ux, py-uy
	delta = dx*dx + dy*dy - r*r
	return delta, Class(delta < 0, delta == 0)
}

// RunOnce executes one full evaluation. It applies NO input-range check, so E2
// can feed values the browser client would reject.
func (e *Env) RunOnce(px, py, ux, uy, r int64, measureNoise bool) (*Result, error) {
	res := &Result{}

	// Both parties encrypt their two coordinates under the collective key.
	start := Now()
	enc := rlwe.NewEncryptor(e.Params, e.CPK)
	cts := make([]*rlwe.Ciphertext, 4)
	for i, v := range []int64{px, py, ux, uy} {
		ct, err := demo.EncryptScalar(e.Params, e.Encoder, enc, v)
		if err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
		cts[i] = ct
		if i == 1 {
			res.EncryptPMs = SinceMs(start)
		}
	}
	res.EncryptMs = SinceMs(start)
	res.EncryptUMs = res.EncryptMs - res.EncryptPMs
	res.CiphertextBytes = cts[0].BinarySize()

	// Server: homomorphic delta, same function as the API.
	start = Now()
	ev := bgv.NewEvaluator(e.Params, e.EVK, true)
	ctDelta, err := demo.ProximityDelta(e.Params, ev, cts[0], cts[1], cts[2], cts[3], r)
	if err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}
	res.EvalMs = SinceMs(start)

	if err := e.finish(res, ctDelta, cts[0], measureNoise); err != nil {
		return nil, err
	}
	return res, nil
}

// finish runs encryption-to-shares and the garbled circuit on Enc(delta) and
// fills res. fresh is one input ciphertext, used only for the noise record.
func (e *Env) finish(res *Result, ctDelta, fresh *rlwe.Ciphertext, measureNoise bool) error {
	t := e.Params.PlaintextModulus()
	// Encryption-to-shares. The User (garbler) calls GetShare, as in the app.
	start := Now()
	e2s, err := mpbgv.NewEncToShareProtocol(e.Params, FloodNoise)
	if err != nil {
		return fmt.Errorf("e2s: %w", err)
	}
	level := ctDelta.Level()
	maskP, maskU := mpbgv.NewAdditiveShare(e.Params), mpbgv.NewAdditiveShare(e.Params)
	pubP, pubU, agg := e2s.AllocateShare(level), e2s.AllocateShare(level), e2s.AllocateShare(level)
	lap := Now()
	e2s.GenShare(e.SkP, ctDelta, &maskP, &pubP)
	res.E2SSharePMs = SinceMs(lap)
	lap = Now()
	e2s.GenShare(e.SkU, ctDelta, &maskU, &pubU)
	res.E2SShareUMs = SinceMs(lap)
	res.E2SShareBytes = pubP.BinarySize()
	lap = Now()
	if err := e2s.AggregateShares(pubP, agg, &agg); err != nil {
		return fmt.Errorf("e2s aggregate: %w", err)
	}
	if err := e2s.AggregateShares(pubU, agg, &agg); err != nil {
		return fmt.Errorf("e2s aggregate: %w", err)
	}
	finalU := mpbgv.NewAdditiveShare(e.Params)
	e2s.GetShare(&maskU, agg, ctDelta, &finalU)
	if res.ShareP, err = e.slot0(maskP.Value, ctDelta); err != nil {
		return err
	}
	if res.ShareU, err = e.slot0(finalU.Value, ctDelta); err != nil {
		return err
	}
	res.E2SMs = SinceMs(start)
	res.E2SFinalMs = SinceMs(lap)
	res.DeltaDecoded = demo.Centered((res.ShareP+res.ShareU)%t, t)

	if e.CaptureServerView {
		// GetShare with a nil secret share is exactly the computation open to a
		// party that holds only public material.
		view := mpbgv.NewAdditiveShare(e.Params)
		e2s.GetShare(nil, agg, ctDelta, &view)
		res.ServerView = make([]uint64, e.Params.MaxSlots())
		if err := e.Encoder.DecodeRingT(view.Value, ctDelta.Scale, res.ServerView); err != nil {
			return fmt.Errorf("decode server view: %w", err)
		}
	}

	if measureNoise {
		ringQ := e.Params.RingQ().AtLevel(level)
		n := &Noise{QBits: ringQ.LogModuli()}
		_, n.FreshBits = e.noiseOf(fresh)
		n.RawBits = e.rawNormOf(ctDelta)
		n.DeltaStdBits, n.DeltaBits = e.noiseOf(ctDelta)
		masked := ringQ.NewPoly()
		ringQ.Add(agg.Value, ctDelta.Value[0], masked)
		ringQ.INTT(masked, masked)
		_, n.E2SBits = e.scaledStats(ringQ, masked)
		n.BudgetDeltaBits = n.QBits - 1 - n.DeltaBits
		n.BudgetE2SBits = n.QBits - 1 - n.E2SBits
		n.FloodMarginBits = FloodSigmaLog2 - (n.DeltaStdBits - log2u(t))
		res.Noise = n
	}

	return e.classify(res)
}

// classify runs the garbled circuit: the User garbles, the Police obtains its
// input labels by OT and evaluates. Only the two output bits are decoded.
func (e *Env) classify(res *Result) error {
	c := e.Circuit

	start := Now()
	g, sec, err := gc.Garble(c, crand.Reader)
	if err != nil {
		return fmt.Errorf("garble: %w", err)
	}
	res.GarbleMs = SinceMs(start)
	if raw, err := g.MarshalBinary(); err == nil {
		res.GarbledBytes = len(raw)
	}

	start = Now()
	ctx := []byte("bench")
	sender, msgA, err := gc.NewOTSender(ctx)
	if err != nil {
		return fmt.Errorf("ot sender: %w", err)
	}
	recv, msgR, err := gc.NewOTReceiver(ctx, msgA, gc.Bits(res.ShareP, e.Bits))
	if err != nil {
		return fmt.Errorf("ot receiver: %w", err)
	}
	m0, m1 := make([]gc.Label, e.Bits), make([]gc.Label, e.Bits)
	for i := range m0 {
		m0[i], m1[i] = sec.Pair(e.Bits + i)
	}
	msgE, err := sender.Respond(msgR, m0, m1)
	if err != nil {
		return fmt.Errorf("ot respond: %w", err)
	}
	policeLabels, err := recv.Finish(msgE)
	if err != nil {
		return fmt.Errorf("ot finish: %w", err)
	}
	res.OTMs = SinceMs(start)
	res.OTABytes, res.OTRBytes, res.OTEBytes = len(msgA), len(msgR), len(msgE)
	res.LabelBytes = e.Bits * gc.LabelSize

	start = Now()
	inputs := make([]gc.Label, 0, c.NumInputs)
	for i, b := range gc.Bits(res.ShareU, e.Bits) {
		inputs = append(inputs, sec.Label(i, b))
	}
	inputs = append(inputs, policeLabels...)
	out, err := gc.Evaluate(c, g, inputs)
	if err != nil {
		return fmt.Errorf("gc evaluate: %w", err)
	}
	res.GCEvalMs = SinceMs(start)
	res.Inside, res.Zero = out[gc.OutInside], out[gc.OutZero]
	return nil
}

// slot0 decodes slot 0 of an additive share in R_t.
func (e *Env) slot0(poly ring.Poly, ct *rlwe.Ciphertext) (uint64, error) {
	vals := make([]uint64, e.Params.MaxSlots())
	if err := e.Encoder.DecodeRingT(poly, ct.Scale, vals); err != nil {
		return 0, fmt.Errorf("decode share: %w", err)
	}
	return vals[0], nil
}

// decryptCoeffs decrypts ct with the summed secret key and returns the
// polynomial in the coefficient domain.
func (e *Env) decryptCoeffs(ct *rlwe.Ciphertext) (*ring.Ring, ring.Poly) {
	dec := rlwe.NewDecryptor(e.Params, e.SkSum)
	pt := rlwe.NewPlaintext(e.Params, ct.Level())
	dec.Decrypt(ct, pt)
	ringQ := e.Params.RingQ().AtLevel(ct.Level())
	if pt.IsNTT {
		ringQ.INTT(pt.Value, pt.Value)
	}
	return ringQ, pt.Value
}

// noiseOf returns log2 of the std and of the max of |m + t*e| for ct.
func (e *Env) noiseOf(ct *rlwe.Ciphertext) (stdBits, maxBits float64) {
	ringQ, poly := e.decryptCoeffs(ct)
	return e.scaledStats(ringQ, poly)
}

// rawNormOf returns log2 max |Dec(ct)| without multiplying by t.
func (e *Env) rawNormOf(ct *rlwe.Ciphertext) float64 {
	ringQ, poly := e.decryptCoeffs(ct)
	_, _, maxBits := rlwe.NormStats(centered(ringQ, poly))
	return maxBits
}

// scaledStats multiplies a coefficient-domain polynomial by t (mod Q) and
// returns log2 of the std and max of its centered coefficients.
func (e *Env) scaledStats(ringQ *ring.Ring, poly ring.Poly) (stdBits, maxBits float64) {
	scaled := ringQ.NewPoly()
	ringQ.MulScalar(poly, e.Params.PlaintextModulus(), scaled)
	stdBits, _, maxBits = rlwe.NormStats(centered(ringQ, scaled))
	return
}

func centered(ringQ *ring.Ring, poly ring.Poly) []*big.Int {
	coeffs := make([]*big.Int, ringQ.N())
	for i := range coeffs {
		coeffs[i] = new(big.Int)
	}
	ringQ.PolyToBigintCentered(poly, 1, coeffs)
	return coeffs
}

// SinceMs returns the milliseconds elapsed since a timestamp taken with Now.
func SinceMs(start int64) float64 { return float64(Now()-start) / 1e6 }

func log2u(v uint64) float64 { return math.Log2(float64(v)) }

// SetupTimes splits collective key generation by role, in milliseconds.
// Server is everything the API does: sampling the CRPs, aggregating shares and
// building the collective public key and relinearization key.
type SetupTimes struct {
	SkGenP, SkGenU       float64
	CKGShareP, CKGShareU float64
	RKGR1P, RKGR1U       float64
	RKGR2P, RKGR2U       float64
	Server               float64
}

// Sizes are serialized sizes in bytes (Lattigo BinarySize) of one object each.
type Sizes struct {
	SecretKey, CPK, RLK              int
	CKGShare, RKGShareR1, RKGShareR2 int
}
