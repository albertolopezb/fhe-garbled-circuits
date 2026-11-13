package bench

import (
	"math/rand/v2"
	"testing"

	"lattigo-auth-ui-demo/internal/gc"
)

func inputs(a, b uint64, bits int) []bool {
	return append(gc.Bits(a, bits), gc.Bits(b, bits)...)
}

// The generic circuit must agree with the application's circuit for t = 65537.
func TestCompareCircuitMatchesApplication(t *testing.T) {
	app := gc.ShareCompareCircuit()
	gen := CompareCircuit(gc.ShareBits, gc.Modulus)
	rng := rand.New(rand.NewPCG(1, 2))
	pairs := [][2]uint64{{0, 0}, {1, 65536}, {32768, 0}, {32769, 0}, {65536, 65536}, {32768, 32768}, {0, 32769}}
	for i := 0; i < 20000; i++ {
		pairs = append(pairs, [2]uint64{rng.Uint64N(gc.Modulus), rng.Uint64N(gc.Modulus)})
	}
	for _, p := range pairs {
		in := inputs(p[0], p[1], gc.ShareBits)
		want, got := app.EvalPlain(in), gen.EvalPlain(in)
		if want[0] != got[0] || want[1] != got[1] {
			t.Fatalf("a=%d b=%d: application %v, generic %v", p[0], p[1], want, got)
		}
	}
}

// For other moduli the circuit must match the arithmetic definition.
func TestCompareCircuitOtherModuli(t *testing.T) {
	for _, mod := range []uint64{163841, 786433, 17, 257} {
		bits := 0
		for v := mod; v > 0; v >>= 1 {
			bits++
		}
		c := CompareCircuit(bits, mod)
		rng := rand.New(rand.NewPCG(mod, 3))
		h := (mod - 1) / 2
		pairs := [][2]uint64{{0, 0}, {h, 0}, {h + 1, 0}, {mod - 1, 1}, {mod - 1, mod - 1}, {h, 1}}
		for i := 0; i < 20000; i++ {
			pairs = append(pairs, [2]uint64{rng.Uint64N(mod), rng.Uint64N(mod)})
		}
		for _, p := range pairs {
			x := (p[0] + p[1]) % mod
			got := c.EvalPlain(inputs(p[0], p[1], bits))
			if got[0] != (x > h) || got[1] != (x == 0) {
				t.Fatalf("t=%d a=%d b=%d x=%d: got %v", mod, p[0], p[1], x, got)
			}
		}
	}
}

func TestMaxCoordinate(t *testing.T) {
	cases := []struct {
		t    uint64
		d    int
		want int64
	}{{65537, 2, 128}, {65537, 15, 46}, {65537, 1, 181}}
	for _, c := range cases {
		if got := MaxCoordinate(c.t, c.d); got != c.want {
			t.Fatalf("MaxCoordinate(%d, %d) = %d, want %d", c.t, c.d, got, c.want)
		}
	}
}
