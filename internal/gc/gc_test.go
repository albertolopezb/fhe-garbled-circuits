package gc

import (
	crand "crypto/rand"
	"math/rand"
	"testing"
)

func inputBits(a, b uint64) []bool {
	return append(Bits(a, ShareBits), Bits(b, ShareBits)...)
}

// edge cases around the wrap-around at t and the sign boundary t/2
func edgePairs() [][2]uint64 {
	const t = Modulus
	var out [][2]uint64
	vals := []uint64{0, 1, 2, 100, 16384, 32767, 32768, 32769, 32770, 49152, t - 2, t - 1}
	for _, a := range vals {
		for _, b := range vals {
			out = append(out, [2]uint64{a, b})
		}
	}
	// pairs that sum to exact interesting targets: 0, 32768, 32769, t-1
	for _, target := range []uint64{0, 1, 32768, 32769, t - 1} {
		for _, a := range []uint64{0, 5, 32768, t - 1} {
			out = append(out, [2]uint64{a, (target + t - a) % t})
		}
	}
	return out
}

func TestCircuitMatchesReference(t *testing.T) {
	c := ShareCompareCircuit()
	check := func(a, b uint64) {
		got := c.EvalPlain(inputBits(a, b))
		wi, wz := ReferenceCompare(a, b)
		if got[OutInside] != wi || got[OutZero] != wz {
			t.Fatalf("a=%d b=%d: got inside=%v zero=%v want inside=%v zero=%v", a, b, got[OutInside], got[OutZero], wi, wz)
		}
	}
	for _, p := range edgePairs() {
		check(p[0], p[1])
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		check(uint64(rng.Intn(Modulus)), uint64(rng.Intn(Modulus)))
	}
	t.Logf("circuit: %d gates, %d AND", len(c.Gates), c.NumAND())
}

// Δ = x - r mod t for plain integers: shares of Δ must classify like the sign of Δ.
func TestCircuitSignOfDelta(t *testing.T) {
	c := ShareCompareCircuit()
	rng := rand.New(rand.NewSource(2))
	for _, delta := range []int64{-32768, -32767, -1, 0, 1, 32767, -100, 100} {
		d := uint64((delta%Modulus + Modulus) % Modulus)
		for k := 0; k < 50; k++ {
			a := uint64(rng.Intn(Modulus))
			b := (d + Modulus - a) % Modulus
			got := c.EvalPlain(inputBits(a, b))
			if got[OutInside] != (delta < 0) || got[OutZero] != (delta == 0) {
				t.Fatalf("delta=%d: inside=%v zero=%v", delta, got[OutInside], got[OutZero])
			}
		}
	}
}

func TestGarbledMatchesPlain(t *testing.T) {
	c := ShareCompareCircuit()
	g, sec, err := Garble(c, crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// round trip the public part through the wire format
	raw, _ := g.MarshalBinary()
	g2, err := UnmarshalGarbled(raw, c)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(3))
	pairs := edgePairs()
	for i := 0; i < 300; i++ {
		pairs = append(pairs, [2]uint64{uint64(rng.Intn(Modulus)), uint64(rng.Intn(Modulus))})
	}
	for _, p := range pairs {
		bits := inputBits(p[0], p[1])
		labels := make([]Label, len(bits))
		for i, b := range bits {
			labels[i] = sec.Label(i, b)
		}
		got, err := Evaluate(c, g2, labels)
		if err != nil {
			t.Fatal(err)
		}
		wi, wz := ReferenceCompare(p[0], p[1])
		if got[OutInside] != wi || got[OutZero] != wz {
			t.Fatalf("a=%d b=%d garbled got %v want inside=%v zero=%v", p[0], p[1], got, wi, wz)
		}
	}
}

func TestGarbledRejectsMalformed(t *testing.T) {
	c := ShareCompareCircuit()
	g, _, _ := Garble(c, crand.Reader)
	raw, _ := g.MarshalBinary()
	if _, err := UnmarshalGarbled(raw[:len(raw)-1], c); err == nil {
		t.Fatal("truncated garbled circuit accepted")
	}
	if _, err := UnmarshalGarbled(raw[:3], c); err == nil {
		t.Fatal("tiny garbled circuit accepted")
	}
}

func TestSecretRoundTrip(t *testing.T) {
	c := ShareCompareCircuit()
	_, sec, _ := Garble(c, crand.Reader)
	s2, err := SecretFromBytes(sec.Bytes(), c.NumInputs)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Delta != sec.Delta || s2.In0[5] != sec.In0[5] {
		t.Fatal("secret round trip mismatch")
	}
}

// Full two-party run: garbler holds a, evaluator holds b and gets its labels by OT.
func TestFullProtocolWithOT(t *testing.T) {
	c := ShareCompareCircuit()
	ctx := []byte("session-1")
	rng := rand.New(rand.NewSource(4))
	pairs := [][2]uint64{{0, 0}, {32768, 0}, {32769, 0}, {65536, 1}, {40000, 40000}}
	for i := 0; i < 20; i++ {
		pairs = append(pairs, [2]uint64{uint64(rng.Intn(Modulus)), uint64(rng.Intn(Modulus))})
	}
	for _, p := range pairs {
		a, b := p[0], p[1]

		// garbler
		g, sec, err := Garble(c, crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		garbledRaw, _ := g.MarshalBinary()
		aBits := Bits(a, ShareBits)
		garblerLabels := make([]Label, ShareBits)
		for i, bit := range aBits {
			garblerLabels[i] = sec.Label(i, bit)
		}
		sender, msgA, err := NewOTSender(ctx)
		if err != nil {
			t.Fatal(err)
		}

		// evaluator: OT choices are the bits of b
		receiver, msgR, err := NewOTReceiver(ctx, msgA, Bits(b, ShareBits))
		if err != nil {
			t.Fatal(err)
		}

		// garbler answers
		m0 := make([]Label, ShareBits)
		m1 := make([]Label, ShareBits)
		for i := 0; i < ShareBits; i++ {
			m0[i], m1[i] = sec.Pair(ShareBits + i)
		}
		msgE, err := sender.Respond(msgR, m0, m1)
		if err != nil {
			t.Fatal(err)
		}

		// evaluator finishes
		evalLabels, err := receiver.Finish(msgE)
		if err != nil {
			t.Fatal(err)
		}
		gg, err := UnmarshalGarbled(garbledRaw, c)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Evaluate(c, gg, append(append([]Label{}, garblerLabels...), evalLabels...))
		if err != nil {
			t.Fatal(err)
		}
		wi, wz := ReferenceCompare(a, b)
		if got[OutInside] != wi || got[OutZero] != wz {
			t.Fatalf("a=%d b=%d got %v want inside=%v zero=%v", a, b, got, wi, wz)
		}
	}
}

func TestOTHidesUnchosenMessage(t *testing.T) {
	ctx := []byte("ctx")
	sender, msgA, _ := NewOTSender(ctx)
	receiver, msgR, _ := NewOTReceiver(ctx, msgA, []bool{false, true})
	m0 := []Label{{1}, {2}}
	m1 := []Label{{3}, {4}}
	msgE, err := sender.Respond(msgR, m0, m1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := receiver.Finish(msgE)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != m0[0] || got[1] != m1[1] {
		t.Fatal("receiver did not get the chosen messages")
	}
	// a receiver that decrypts the other slot gets garbage
	other := make([]byte, len(msgE))
	copy(other, msgE[LabelSize:2*LabelSize])
	if string(other[:LabelSize]) == string(m1[0][:]) {
		t.Fatal("unexpected plaintext in ciphertext")
	}
}

func TestOTStateRoundTrip(t *testing.T) {
	ctx := []byte("ctx")
	sender, msgA, _ := NewOTSender(ctx)
	receiver, msgR, _ := NewOTReceiver(ctx, msgA, []bool{true, false, true})
	s2, err := OTSenderFromBytes(ctx, sender.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := OTReceiverFromBytes(ctx, receiver.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	m0 := []Label{{1}, {2}, {3}}
	m1 := []Label{{4}, {5}, {6}}
	msgE, err := s2.Respond(msgR, m0, m1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r2.Finish(msgE)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != m1[0] || got[1] != m0[1] || got[2] != m1[2] {
		t.Fatal("restored OT state gives wrong labels")
	}
}
