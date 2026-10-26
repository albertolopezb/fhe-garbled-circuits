package gc

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const LabelSize = 16

type Label [LabelSize]byte

func xorLabel(a, b Label) Label {
	var o Label
	for i := range o {
		o[i] = a[i] ^ b[i]
	}
	return o
}

func lsb(l Label) byte { return l[0] & 1 }

// hashRow is the row key H(la, lb, gate). SHA-256 truncated to one label.
func hashRow(la, lb Label, gid uint64) Label {
	h := sha256.New()
	h.Write(la[:])
	h.Write(lb[:])
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], gid)
	h.Write(t[:])
	var l Label
	copy(l[:], h.Sum(nil))
	return l
}

// Garbled is the public part that the garbler sends to the evaluator.
type Garbled struct {
	Tables [][4]Label // one per AND gate, in circuit order
	Decode []byte     // per output wire: permute bit of its zero label
}

// Secret is what the garbler keeps: free-XOR offset and the zero label of every input.
type Secret struct {
	Delta Label
	In0   []Label
}

// Label returns the label that encodes bit on input wire i.
func (s *Secret) Label(i int, bit bool) Label {
	if bit {
		return xorLabel(s.In0[i], s.Delta)
	}
	return s.In0[i]
}

// Pair returns both labels of input wire i (for the oblivious transfer).
func (s *Secret) Pair(i int) (Label, Label) {
	return s.In0[i], xorLabel(s.In0[i], s.Delta)
}

func randLabel(r io.Reader) (Label, error) {
	var l Label
	_, err := io.ReadFull(r, l[:])
	return l, err
}

func Garble(c *Circuit, rng io.Reader) (*Garbled, *Secret, error) {
	delta, err := randLabel(rng)
	if err != nil {
		return nil, nil, err
	}
	delta[0] |= 1 // lsb(delta)=1 so that the two labels of a wire have different permute bits

	zero := make([]Label, c.NumWires)
	sec := &Secret{Delta: delta, In0: make([]Label, c.NumInputs)}
	for i := 0; i < c.NumInputs; i++ {
		if zero[i], err = randLabel(rng); err != nil {
			return nil, nil, err
		}
		sec.In0[i] = zero[i]
	}

	g := &Garbled{Tables: make([][4]Label, 0, c.NumAND())}
	var gid uint64
	for _, gate := range c.Gates {
		switch gate.Op {
		case OpXOR:
			zero[gate.Out] = xorLabel(zero[gate.A], zero[gate.B])
		case OpNOT:
			// The evaluator keeps the same label; only its meaning flips.
			zero[gate.Out] = xorLabel(zero[gate.A], delta)
		case OpAND:
			out0, err := randLabel(rng)
			if err != nil {
				return nil, nil, err
			}
			zero[gate.Out] = out0
			var table [4]Label
			for va := 0; va < 2; va++ {
				for vb := 0; vb < 2; vb++ {
					la, lb := zero[gate.A], zero[gate.B]
					if va == 1 {
						la = xorLabel(la, delta)
					}
					if vb == 1 {
						lb = xorLabel(lb, delta)
					}
					lo := out0
					if va&vb == 1 {
						lo = xorLabel(lo, delta)
					}
					idx := int(lsb(la))<<1 | int(lsb(lb))
					table[idx] = xorLabel(hashRow(la, lb, gid), lo)
				}
			}
			g.Tables = append(g.Tables, table)
			gid++
		default:
			return nil, nil, fmt.Errorf("unknown gate op %d", gate.Op)
		}
	}
	g.Decode = make([]byte, len(c.Outputs))
	for i, o := range c.Outputs {
		g.Decode[i] = lsb(zero[o])
	}
	return g, sec, nil
}

// Evaluate runs the garbled circuit on one active label per input wire and returns the output bits.
func Evaluate(c *Circuit, g *Garbled, inputs []Label) ([]bool, error) {
	if len(inputs) != c.NumInputs {
		return nil, fmt.Errorf("expected %d input labels, got %d", c.NumInputs, len(inputs))
	}
	if len(g.Tables) != c.NumAND() || len(g.Decode) != len(c.Outputs) {
		return nil, errors.New("garbled circuit does not match the circuit")
	}
	w := make([]Label, c.NumWires)
	copy(w, inputs)
	var gid uint64
	for _, gate := range c.Gates {
		switch gate.Op {
		case OpXOR:
			w[gate.Out] = xorLabel(w[gate.A], w[gate.B])
		case OpNOT:
			w[gate.Out] = w[gate.A]
		case OpAND:
			la, lb := w[gate.A], w[gate.B]
			idx := int(lsb(la))<<1 | int(lsb(lb))
			w[gate.Out] = xorLabel(g.Tables[gid][idx], hashRow(la, lb, gid))
			gid++
		}
	}
	out := make([]bool, len(c.Outputs))
	for i, o := range c.Outputs {
		out[i] = lsb(w[o])^g.Decode[i] == 1
	}
	return out, nil
}

// ---- serialization ----

func (g *Garbled) MarshalBinary() ([]byte, error) {
	b := make([]byte, 0, 8+len(g.Tables)*4*LabelSize+len(g.Decode))
	b = binary.BigEndian.AppendUint32(b, uint32(len(g.Tables)))
	for _, t := range g.Tables {
		for _, l := range t {
			b = append(b, l[:]...)
		}
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(g.Decode)))
	b = append(b, g.Decode...)
	return b, nil
}

// UnmarshalGarbled parses a Garbled and checks it against the expected circuit shape.
func UnmarshalGarbled(b []byte, c *Circuit) (*Garbled, error) {
	if len(b) < 4 {
		return nil, errors.New("garbled circuit too short")
	}
	nt := int(binary.BigEndian.Uint32(b))
	if nt != c.NumAND() {
		return nil, errors.New("unexpected number of garbled tables")
	}
	b = b[4:]
	if len(b) < nt*4*LabelSize+4 {
		return nil, errors.New("garbled circuit truncated")
	}
	g := &Garbled{Tables: make([][4]Label, nt)}
	for i := range g.Tables {
		for j := 0; j < 4; j++ {
			copy(g.Tables[i][j][:], b)
			b = b[LabelSize:]
		}
	}
	nd := int(binary.BigEndian.Uint32(b))
	b = b[4:]
	if nd != len(c.Outputs) || len(b) != nd {
		return nil, errors.New("bad output decoding table")
	}
	g.Decode = append([]byte(nil), b...)
	for _, d := range g.Decode {
		if d > 1 {
			return nil, errors.New("bad output decoding bit")
		}
	}
	return g, nil
}

func EncodeLabels(ls []Label) []byte {
	b := make([]byte, 0, len(ls)*LabelSize)
	for _, l := range ls {
		b = append(b, l[:]...)
	}
	return b
}

func DecodeLabels(b []byte, n int) ([]Label, error) {
	if len(b) != n*LabelSize {
		return nil, fmt.Errorf("expected %d labels (%d bytes), got %d bytes", n, n*LabelSize, len(b))
	}
	ls := make([]Label, n)
	for i := range ls {
		copy(ls[i][:], b[i*LabelSize:])
	}
	return ls, nil
}

// Bytes / SecretFromBytes let the garbler survive a page reload between protocol rounds.
func (s *Secret) Bytes() []byte {
	return EncodeLabels(append([]Label{s.Delta}, s.In0...))
}

func SecretFromBytes(b []byte, numInputs int) (*Secret, error) {
	ls, err := DecodeLabels(b, numInputs+1)
	if err != nil {
		return nil, err
	}
	return &Secret{Delta: ls[0], In0: ls[1:]}, nil
}
