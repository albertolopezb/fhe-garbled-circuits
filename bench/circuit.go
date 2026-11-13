package bench

import "lattigo-auth-ui-demo/internal/gc"

// CompareCircuit is gc.ShareCompareCircuit generalized to any odd modulus t
// that fits in `bits` bits. It reconstructs delta = (a + b) mod t from two
// shares and outputs [delta < 0, delta == 0], with delta taken as the centered
// representative, so "negative" means (a + b) mod t > (t-1)/2.
// Inputs are LSB first: wires 0..bits-1 are the garbler's share a, wires
// bits..2*bits-1 are the evaluator's share b. Used only by E5; the
// application keeps its own 17-bit circuit.
func CompareCircuit(bits int, t uint64) *gc.Circuit {
	b := gc.NewBuilder(2 * bits)
	constant := func(k uint64, i int) int {
		if (k>>uint(i))&1 == 1 {
			return gc.WireOne
		}
		return gc.WireZero
	}

	// s = a + b over bits+1 bits.
	s := make([]int, bits+1)
	carry := gc.WireZero
	for i := 0; i < bits; i++ {
		s[i], carry = fullAdder(b, i, bits+i, carry)
	}
	s[bits] = carry

	// d = s + (2^(bits+1) - t) over bits+1 bits; the carry out says s >= t.
	k := (uint64(1) << uint(bits+1)) - t
	d := make([]int, bits+1)
	carry = gc.WireZero
	for i := 0; i <= bits; i++ {
		d[i], carry = fullAdder(b, s[i], constant(k, i), carry)
	}
	ge := carry

	// x = s mod t.
	x := make([]int, bits)
	for i := range x {
		x[i] = b.Mux(ge, s[i], d[i])
	}

	// x > h with h = (t-1)/2  <=>  x + (2^bits - 1 - h) carries out of bits bits.
	h := (t - 1) / 2
	c := (uint64(1) << uint(bits)) - 1 - h
	carry = gc.WireZero
	for i := 0; i < bits; i++ {
		_, carry = fullAdder(b, x[i], constant(c, i), carry)
	}
	negative := carry

	any := gc.WireZero
	for i := 0; i < bits; i++ {
		any = b.Or(any, x[i])
	}
	zero := b.Not(any)

	circuit, err := b.Build(negative, zero)
	if err != nil {
		panic(err) // both outputs depend on inputs
	}
	return circuit
}

// fullAdder returns sum and carry-out with one AND gate (same construction as
// the application's circuit).
func fullAdder(b *gc.Builder, x, y, cin int) (sum, cout int) {
	t := b.Xor(x, cin)
	u := b.Xor(y, cin)
	sum = b.Xor(t, y)
	cout = b.Xor(cin, b.And(t, u))
	return
}

// MaxCoordinate returns the largest coordinate bound M such that delta stays
// in the centered range of t for d dimensions: d*M^2 <= (t-1)/2. The radius
// must satisfy R^2 <= (t-1)/2 as well.
func MaxCoordinate(t uint64, d int) int64 {
	limit := (t - 1) / 2 / uint64(d)
	m := int64(0)
	for uint64((m+1)*(m+1)) <= limit {
		m++
	}
	return m
}
