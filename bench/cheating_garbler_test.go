package bench

// E12: a cheating garbler. TEST CODE ONLY. Nothing here is reachable from the
// application; it exists to show why the semi-honest assumption is essential.
//
// The evaluator runs gc.Evaluate with its own copy of the circuit topology and
// the garbler's tables. It has no way to check that each garbled AND table
// really encodes AND. A garbler that fills the tables with other truth tables
// therefore changes the function, and the evaluation still succeeds.
//
// Here the garbler rewrites the 16 AND gates of the final "delta == 0" OR
// chain so that the second output bit becomes NOT(bit k of delta mod t).
// Repeating the evaluation for k = 0..16 recovers delta mod t exactly.

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"testing"

	"lattigo-auth-ui-demo/internal/gc"
)

// Re-implementations of the three unexported helpers of internal/gc/garble.go.
func xorL(a, b gc.Label) gc.Label {
	var o gc.Label
	for i := range o {
		o[i] = a[i] ^ b[i]
	}
	return o
}

func lsbL(l gc.Label) byte { return l[0] & 1 }

func hashRowL(la, lb gc.Label, gid uint64) gc.Label {
	h := sha256.New()
	h.Write(la[:])
	h.Write(lb[:])
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], gid)
	h.Write(t[:])
	var l gc.Label
	copy(l[:], h.Sum(nil))
	return l
}

// garbleWithTruth is gc.Garble with one change: truth(andIndex, va, vb) decides
// the output bit of every AND gate. truth = va&vb gives the honest garbling.
func garbleWithTruth(c *gc.Circuit, rng io.Reader, truth func(andIndex, va, vb int) int) (*gc.Garbled, *gc.Secret) {
	rnd := func() gc.Label {
		var l gc.Label
		if _, err := io.ReadFull(rng, l[:]); err != nil {
			panic(err)
		}
		return l
	}
	delta := rnd()
	delta[0] |= 1
	zero := make([]gc.Label, c.NumWires)
	sec := &gc.Secret{Delta: delta, In0: make([]gc.Label, c.NumInputs)}
	for i := 0; i < c.NumInputs; i++ {
		zero[i] = rnd()
		sec.In0[i] = zero[i]
	}
	g := &gc.Garbled{}
	var gid uint64
	for _, gate := range c.Gates {
		switch gate.Op {
		case gc.OpXOR:
			zero[gate.Out] = xorL(zero[gate.A], zero[gate.B])
		case gc.OpNOT:
			zero[gate.Out] = xorL(zero[gate.A], delta)
		case gc.OpAND:
			out0 := rnd()
			zero[gate.Out] = out0
			var table [4]gc.Label
			for va := 0; va < 2; va++ {
				for vb := 0; vb < 2; vb++ {
					la, lb := zero[gate.A], zero[gate.B]
					if va == 1 {
						la = xorL(la, delta)
					}
					if vb == 1 {
						lb = xorL(lb, delta)
					}
					lo := out0
					if truth(int(gid), va, vb) == 1 {
						lo = xorL(lo, delta)
					}
					table[int(lsbL(la))<<1|int(lsbL(lb))] = xorL(hashRowL(la, lb, gid), lo)
				}
			}
			g.Tables = append(g.Tables, table)
			gid++
		}
	}
	g.Decode = make([]byte, len(c.Outputs))
	for i, o := range c.Outputs {
		g.Decode[i] = lsbL(zero[o])
	}
	return g, sec
}

func evalWith(t *testing.T, c *gc.Circuit, g *gc.Garbled, sec *gc.Secret, a, b uint64) []bool {
	t.Helper()
	labels := make([]gc.Label, 0, c.NumInputs)
	for i, bit := range gc.Bits(a, gc.ShareBits) {
		labels = append(labels, sec.Label(i, bit))
	}
	for i, bit := range gc.Bits(b, gc.ShareBits) {
		labels = append(labels, sec.Label(gc.ShareBits+i, bit))
	}
	out, err := gc.Evaluate(c, g, labels)
	if err != nil {
		t.Fatalf("the evaluator rejected the garbling: %v", err)
	}
	return out
}

// Sanity: with the honest truth table the re-implementation equals the circuit.
func TestGarbleWithTruthHonest(t *testing.T) {
	c := gc.ShareCompareCircuit()
	rng := rand.New(rand.NewPCG(12, 1))
	for i := 0; i < 200; i++ {
		a, b := rng.Uint64N(gc.Modulus), rng.Uint64N(gc.Modulus)
		g, sec := garbleWithTruth(c, crand.Reader, func(_, va, vb int) int { return va & vb })
		out := evalWith(t, c, g, sec, a, b)
		wantInside, wantZero := gc.ReferenceCompare(a, b)
		if out[gc.OutInside] != wantInside || out[gc.OutZero] != wantZero {
			t.Fatalf("honest garbling wrong for a=%d b=%d", a, b)
		}
	}
}

// The attack: 17 forged garblings recover every bit of delta mod t, and the
// evaluator accepts each one.
func TestCheatingGarblerRevealsDelta(t *testing.T) {
	c := gc.ShareCompareCircuit()
	chainStart := c.NumAND() - (gc.ShareBits - 1) // the last 16 AND gates build "delta == 0"
	rng := rand.New(rand.NewPCG(12, 2))
	for trial := 0; trial < 300; trial++ {
		a, b := rng.Uint64N(gc.Modulus), rng.Uint64N(gc.Modulus)
		x := (a + b) % gc.Modulus // delta mod t, which the honest protocol never reveals

		var recovered uint64
		for k := 0; k < gc.ShareBits; k++ {
			// Chain gate j (1..16) computes AND(NOT any_{j-1}, NOT x_j), and
			// any_0 = x_0. Passing input A along keeps NOT(x_0); taking input B
			// at gate k switches the chain to NOT(x_k).
			truth := func(andIndex, va, vb int) int {
				j := andIndex - chainStart + 1
				switch {
				case j < 1:
					return va & vb // rest of the circuit stays honest
				case j == k:
					return vb
				default:
					return va
				}
			}
			g, sec := garbleWithTruth(c, crand.Reader, truth)
			out := evalWith(t, c, g, sec, a, b)
			if !out[gc.OutZero] { // output is NOT(bit k)
				recovered |= 1 << uint(k)
			}
		}
		if recovered != x {
			t.Fatalf("trial %d: recovered %d, delta mod t is %d", trial, recovered, x)
		}
	}
	t.Logf("300 of 300 trials: 17 forged garblings each recovered delta mod t exactly; gc.Evaluate reported no error")
}

// A simpler cheat with the application's real roles: the garbler forces the
// classification it wants (here "outside") for every input.
func TestCheatingGarblerForcesOutside(t *testing.T) {
	c := gc.ShareCompareCircuit()
	rng := rand.New(rand.NewPCG(12, 3))
	for trial := 0; trial < 300; trial++ {
		a, b := rng.Uint64N(gc.Modulus), rng.Uint64N(gc.Modulus)
		// All-zero truth tables are not enough (NOT and XOR gates still act), so
		// the garbler simply lies in the decode bits after an honest garbling.
		g, sec := garbleWithTruth(c, crand.Reader, func(_, va, vb int) int { return va & vb })
		honest := evalWith(t, c, g, sec, a, b)
		if honest[gc.OutInside] {
			g.Decode[gc.OutInside] ^= 1
		}
		if honest[gc.OutZero] {
			g.Decode[gc.OutZero] ^= 1
		}
		out := evalWith(t, c, g, sec, a, b)
		if out[gc.OutInside] || out[gc.OutZero] {
			t.Fatalf("trial %d: forged decode bits did not force 'outside'", trial)
		}
	}
}
