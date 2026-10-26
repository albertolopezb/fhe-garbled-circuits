// Package gc implements a small Yao garbled-circuit stack: a circuit builder,
// garbling/evaluation (point-and-permute + free-XOR) and a 1-out-of-2
// oblivious transfer. It only uses the Go standard library and
// filippo.io/edwards25519, so it compiles both natively and to WASM.
package gc

import "fmt"

type Op uint8

const (
	OpXOR Op = iota
	OpAND
	OpNOT
)

type Gate struct {
	Op   Op
	A, B int // B is unused for OpNOT
	Out  int
}

// Circuit wires 0..NumInputs-1 are inputs; gate outputs follow in order.
type Circuit struct {
	NumInputs int
	NumWires  int
	Gates     []Gate
	Outputs   []int
}

// NumAND returns the number of AND gates, i.e. the number of garbled tables.
func (c *Circuit) NumAND() int {
	n := 0
	for _, g := range c.Gates {
		if g.Op == OpAND {
			n++
		}
	}
	return n
}

// EvalPlain evaluates the circuit on clear bits. It is used by tests as a reference.
func (c *Circuit) EvalPlain(inputs []bool) []bool {
	w := make([]bool, c.NumWires)
	copy(w, inputs)
	for _, g := range c.Gates {
		switch g.Op {
		case OpXOR:
			w[g.Out] = w[g.A] != w[g.B]
		case OpAND:
			w[g.Out] = w[g.A] && w[g.B]
		case OpNOT:
			w[g.Out] = !w[g.A]
		}
	}
	out := make([]bool, len(c.Outputs))
	for i, o := range c.Outputs {
		out[i] = w[o]
	}
	return out
}

// Constant wires. The builder folds them away, so they never reach a Circuit.
const (
	WireZero = -1
	WireOne  = -2
)

// Builder assembles a Circuit with constant folding.
type Builder struct {
	numInputs int
	next      int
	gates     []Gate
}

func NewBuilder(numInputs int) *Builder {
	return &Builder{numInputs: numInputs, next: numInputs}
}

func (b *Builder) newWire() int {
	w := b.next
	b.next++
	return w
}

func (b *Builder) Not(a int) int {
	switch a {
	case WireZero:
		return WireOne
	case WireOne:
		return WireZero
	}
	out := b.newWire()
	b.gates = append(b.gates, Gate{Op: OpNOT, A: a, Out: out})
	return out
}

func (b *Builder) Xor(a, c int) int {
	switch {
	case a == WireZero:
		return c
	case c == WireZero:
		return a
	case a == WireOne:
		return b.Not(c)
	case c == WireOne:
		return b.Not(a)
	case a == c:
		return WireZero
	}
	out := b.newWire()
	b.gates = append(b.gates, Gate{Op: OpXOR, A: a, B: c, Out: out})
	return out
}

func (b *Builder) And(a, c int) int {
	switch {
	case a == WireZero || c == WireZero:
		return WireZero
	case a == WireOne:
		return c
	case c == WireOne:
		return a
	case a == c:
		return a
	}
	out := b.newWire()
	b.gates = append(b.gates, Gate{Op: OpAND, A: a, B: c, Out: out})
	return out
}

// Or costs one AND; NOT and XOR are free.
func (b *Builder) Or(a, c int) int { return b.Not(b.And(b.Not(a), b.Not(c))) }

// Mux returns sel ? x1 : x0 with a single AND.
func (b *Builder) Mux(sel, x0, x1 int) int {
	return b.Xor(x0, b.And(sel, b.Xor(x0, x1)))
}

func (b *Builder) Build(outputs ...int) (*Circuit, error) {
	for _, o := range outputs {
		if o < 0 {
			return nil, fmt.Errorf("output wire is a constant")
		}
	}
	return &Circuit{NumInputs: b.numInputs, NumWires: b.next, Gates: b.gates, Outputs: outputs}, nil
}
