package gc_test

import (
	crand "crypto/rand"
	"testing"

	"lattigo-auth-ui-demo/internal/demo"
	"lattigo-auth-ui-demo/internal/gc"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/multiparty/mpbgv"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// The same noise flooding the old PCKS step used.
var noise = ring.DiscreteGaussian{Sigma: 1 << 30, Bound: 6 * (1 << 30)}

type env struct {
	params   bgv.Parameters
	encoder  *bgv.Encoder
	skP, skS *rlwe.SecretKey
	cpk      *rlwe.PublicKey
	evk      *rlwe.MemEvaluationKeySet
}

// setup runs the two-party CPK + RLK generation exactly like the app does.
func setup(t *testing.T) *env {
	t.Helper()
	params, err := demo.Parameters()
	if err != nil {
		t.Fatal(err)
	}
	crs, _ := sampling.NewKeyedPRNG([]byte("test-crs"))
	kgen := rlwe.NewKeyGenerator(params)
	skP, skS := kgen.GenSecretKeyNew(), kgen.GenSecretKeyNew()

	ckg := multiparty.NewPublicKeyGenProtocol(params)
	crpCKG := ckg.SampleCRP(crs)
	sP, sS, sC := ckg.AllocateShare(), ckg.AllocateShare(), ckg.AllocateShare()
	ckg.GenShare(skP, crpCKG, &sP)
	ckg.GenShare(skS, crpCKG, &sS)
	ckg.AggregateShares(sP, sC, &sC)
	ckg.AggregateShares(sS, sC, &sC)
	cpk := rlwe.NewPublicKey(params)
	ckg.GenPublicKey(sC, crpCKG, cpk)

	rkg := multiparty.NewRelinearizationKeyGenProtocol(params)
	crpRKG := rkg.SampleCRP(crs)
	ephP, r1P, _ := rkg.AllocateShare()
	ephS, r1S, _ := rkg.AllocateShare()
	_, r1C, _ := rkg.AllocateShare()
	rkg.GenShareRoundOne(skP, crpRKG, ephP, &r1P)
	rkg.GenShareRoundOne(skS, crpRKG, ephS, &r1S)
	rkg.AggregateShares(r1P, r1C, &r1C)
	rkg.AggregateShares(r1S, r1C, &r1C)
	_, _, r2P := rkg.AllocateShare()
	_, _, r2S := rkg.AllocateShare()
	_, _, r2C := rkg.AllocateShare()
	rkg.GenShareRoundTwo(ephP, skP, r1C, &r2P)
	rkg.GenShareRoundTwo(ephS, skS, r1C, &r2S)
	rkg.AggregateShares(r2P, r2C, &r2C)
	rkg.AggregateShares(r2S, r2C, &r2C)
	rlk := rlwe.NewRelinearizationKey(params)
	rkg.GenRelinearizationKey(r1C, r2C, rlk)

	return &env{params, bgv.NewEncoder(params), skP, skS, cpk, rlwe.NewMemEvaluationKeySet(rlk)}
}

// evalDelta is the server side of the protocol (same formula as evaluateIfReadyLocked).
func (e *env) evalDelta(t *testing.T, px, py, qx, qy, radius int64) *rlwe.Ciphertext {
	t.Helper()
	enc := rlwe.NewEncryptor(e.params, e.cpk)
	ct := func(v int64) *rlwe.Ciphertext {
		c, err := demo.EncryptScalar(e.params, e.encoder, enc, v)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cPx, cPy, cQx, cQy := ct(px), ct(py), ct(qx), ct(qy)
	ev := bgv.NewEvaluator(e.params, e.evk, true)
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	dx, err := ev.SubNew(cPx, cQx)
	must(err)
	dy, err := ev.SubNew(cPy, cQy)
	must(err)
	mul := func(a, b *rlwe.Ciphertext) *rlwe.Ciphertext {
		o := bgv.NewCiphertext(e.params, 2, a.Level())
		must(ev.Mul(a, b, o))
		must(ev.Relinearize(o, o))
		return o
	}
	dx2, dxdy, dy2 := mul(dx, dx), mul(dx, dy), mul(dy, dy)
	tmp, err := ev.SubNew(dx2, dxdy)
	must(err)
	dist2, err := ev.AddNew(tmp, dy2)
	must(err)
	rv := make([]int64, e.params.MaxSlots())
	rv[0] = radius * radius
	delta, err := ev.SubNew(dist2, rv)
	must(err)
	return delta
}

// shareDelta runs E2S between the two parties. The garbler (suspect) calls GetShare.
func (e *env) shareDelta(t *testing.T, ct *rlwe.Ciphertext) (shareP, shareS uint64) {
	t.Helper()
	e2s, err := mpbgv.NewEncToShareProtocol(e.params, noise)
	if err != nil {
		t.Fatal(err)
	}
	maskP, maskS := mpbgv.NewAdditiveShare(e.params), mpbgv.NewAdditiveShare(e.params)
	pubP, pubS, agg := e2s.AllocateShare(ct.Level()), e2s.AllocateShare(ct.Level()), e2s.AllocateShare(ct.Level())
	e2s.GenShare(e.skP, ct, &maskP, &pubP)
	e2s.GenShare(e.skS, ct, &maskS, &pubS)
	if err := e2s.AggregateShares(pubP, agg, &agg); err != nil {
		t.Fatal(err)
	}
	if err := e2s.AggregateShares(pubS, agg, &agg); err != nil {
		t.Fatal(err)
	}
	finalS := mpbgv.NewAdditiveShare(e.params)
	e2s.GetShare(&maskS, agg, ct, &finalS)

	dec := func(poly ring.Poly) uint64 {
		vals := make([]uint64, e.params.MaxSlots())
		if err := e.encoder.DecodeRingT(poly, ct.Scale, vals); err != nil {
			t.Fatal(err)
		}
		return vals[0]
	}
	return dec(maskP.Value), dec(finalS.Value)
}

func centeredClass(delta int64) (inside, zero bool) { return delta < 0, delta == 0 }

func TestE2SSharesFeedCircuit(t *testing.T) {
	e := setup(t)
	c := gc.ShareCompareCircuit()
	cases := []struct{ px, py, qx, qy, r int64 }{
		{10, 20, 12, 21, 5},  // dx=-2 dy=-1: 4-2+1-25 <0  inside
		{10, 20, 30, 40, 5},  // far: outside
		{0, 0, 3, 0, 3},      // dx=-3,dy=0: 9-0+0-9 = 0  exactly on boundary
		{50, 50, 10, 10, 10}, // dx=dy=40: 1600-1600+1600-100 >0 outside
		{5, 5, 5, 5, 0},      // same point, radius 0: 0
		{0, 0, 1, 1, 1},      // dx=dy=-1: 1-1+1-1 = 0
	}
	for _, tc := range cases {
		ct := e.evalDelta(t, tc.px, tc.py, tc.qx, tc.qy, tc.r)
		dx, dy := tc.px-tc.qx, tc.py-tc.qy
		want := dx*dx - dx*dy + dy*dy - tc.r*tc.r // same formula as the server

		shareP, shareS := e.shareDelta(t, ct)
		if (shareP+shareS)%gc.Modulus != uint64((want%gc.Modulus+gc.Modulus)%gc.Modulus) {
			t.Fatalf("%+v: shares %d+%d do not add up to delta=%d mod t", tc, shareP, shareS, want)
		}

		// the garbled circuit, with the suspect as garbler and the police as evaluator
		g, sec, err := gc.Garble(c, crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ctx := []byte("e2e")
		sender, msgA, _ := gc.NewOTSender(ctx)
		recv, msgR, _ := gc.NewOTReceiver(ctx, msgA, gc.Bits(shareP, gc.ShareBits))
		m0, m1 := make([]gc.Label, gc.ShareBits), make([]gc.Label, gc.ShareBits)
		for i := range m0 {
			m0[i], m1[i] = sec.Pair(gc.ShareBits + i)
		}
		msgE, err := sender.Respond(msgR, m0, m1)
		if err != nil {
			t.Fatal(err)
		}
		evalLabels, err := recv.Finish(msgE)
		if err != nil {
			t.Fatal(err)
		}
		inputs := make([]gc.Label, 0, c.NumInputs)
		for i, b := range gc.Bits(shareS, gc.ShareBits) {
			inputs = append(inputs, sec.Label(i, b))
		}
		inputs = append(inputs, evalLabels...)
		out, err := gc.Evaluate(c, g, inputs)
		if err != nil {
			t.Fatal(err)
		}
		wi, wz := centeredClass(want)
		if out[gc.OutInside] != wi || out[gc.OutZero] != wz {
			t.Fatalf("%+v: delta=%d circuit says inside=%v zero=%v", tc, want, out[gc.OutInside], out[gc.OutZero])
		}
		t.Logf("%+v delta=%d -> inside=%v zero=%v (shares %d / %d)", tc, want, out[gc.OutInside], out[gc.OutZero], shareP, shareS)
	}
}
