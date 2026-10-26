package gc

// Share arithmetic of the protocol: Δ is additively shared modulo the BGV
// plaintext modulus t = 65537, so every share has 17 bits.
const (
	ShareBits = 17
	Modulus   = 65537
)

// Output indexes of ShareCompareCircuit.
const (
	OutInside = 0 // Δ < 0  (centered representative of Δ mod t is negative)
	OutZero   = 1 // Δ == 0
)

// ShareCompareCircuit reconstructs Δ = (a + b) mod t from two 17-bit shares and
// outputs [Δ < 0, Δ == 0], with Δ taken as the centered representative in
// (-t/2, t/2]. Inputs are LSB first: wires 0..16 are the garbler's share a,
// wires 17..33 are the evaluator's share b.
func ShareCompareCircuit() *Circuit {
	b := NewBuilder(2 * ShareBits)

	// s = a + b over 18 bits (ripple-carry, one AND per full adder).
	s := make([]int, ShareBits+1)
	carry := WireZero
	for i := 0; i < ShareBits; i++ {
		s[i], carry = fullAdder(b, i, ShareBits+i, carry)
	}
	s[ShareBits] = carry

	// d = s + (2^18 - t) over 18 bits; the carry out says s >= t.
	k := (1 << (ShareBits + 1)) - Modulus
	d := make([]int, ShareBits+1)
	carry = WireZero
	for i := 0; i <= ShareBits; i++ {
		kb := WireZero
		if (k>>i)&1 == 1 {
			kb = WireOne
		}
		d[i], carry = fullAdder(b, s[i], kb, carry)
	}
	ge := carry

	// x = s mod t.
	x := make([]int, ShareBits)
	for i := range x {
		x[i] = b.Mux(ge, s[i], d[i])
	}

	// centered(x) < 0  <=>  x > t/2 = 32768  <=>  x[16] or (x[15] and x[14:0] != 0)
	low := WireZero
	for i := 0; i < ShareBits-2; i++ {
		low = b.Or(low, x[i])
	}
	inside := b.Or(x[ShareBits-1], b.And(x[ShareBits-2], low))

	any := WireZero
	for i := 0; i < ShareBits; i++ {
		any = b.Or(any, x[i])
	}
	zero := b.Not(any)

	c, err := b.Build(inside, zero)
	if err != nil {
		panic(err) // both outputs depend on inputs, so this cannot happen
	}
	return c
}

// fullAdder returns sum and carry-out with one AND gate.
func fullAdder(b *Builder, x, y, cin int) (sum, cout int) {
	t := b.Xor(x, cin)
	u := b.Xor(y, cin)
	sum = b.Xor(t, y)
	cout = b.Xor(cin, b.And(t, u))
	return
}

// ReferenceCompare is the clear-text version of ShareCompareCircuit.
func ReferenceCompare(a, b uint64) (inside, zero bool) {
	x := (a + b) % Modulus
	return x > Modulus/2, x == 0
}

// Bits splits v into n bits, LSB first.
func Bits(v uint64, n int) []bool {
	out := make([]bool, n)
	for i := range out {
		out[i] = (v>>uint(i))&1 == 1
	}
	return out
}
