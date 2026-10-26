package gc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// 1-out-of-2 oblivious transfer in the style of Chou-Orlandi ("The Simplest
// Protocol for Oblivious Transfer") on edwards25519, for n parallel transfers
// that share one sender message A. Semi-honest model.
//
//	sender   a <- random, A = aB                      sends A
//	receiver R_i = c_i*A + b_i*B                      sends R_1..R_n
//	sender   k0 = H(i, aR_i), k1 = H(i, a(R_i - A))   sends e0_i = m0_i ^ k0, e1_i = m1_i ^ k1
//	receiver k_c = H(i, b_i*A), m_c = e_c ^ k_c

const pointSize = 32

func randScalar() (*edwards25519.Scalar, error) {
	var buf [64]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, err
	}
	return edwards25519.NewScalar().SetUniformBytes(buf[:])
}

func parsePoint(b []byte) (*edwards25519.Point, error) {
	p, err := edwards25519.NewIdentityPoint().SetBytes(b)
	if err != nil {
		return nil, err
	}
	// reject points of small order (identity after clearing the cofactor)
	if edwards25519.NewIdentityPoint().MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, errors.New("OT: small-order point")
	}
	return p, nil
}

func otKey(ctx []byte, i int, p *edwards25519.Point) Label {
	h := sha256.New()
	h.Write([]byte("fhe-gc-ot-v1"))
	h.Write(ctx)
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], uint32(i))
	h.Write(idx[:])
	h.Write(p.Bytes())
	var l Label
	copy(l[:], h.Sum(nil))
	return l
}

// ---- sender ----

type OTSender struct {
	ctx []byte
	a   *edwards25519.Scalar
	A   *edwards25519.Point
}

// NewOTSender returns the sender and its first message A.
func NewOTSender(ctx []byte) (*OTSender, []byte, error) {
	a, err := randScalar()
	if err != nil {
		return nil, nil, err
	}
	A := edwards25519.NewIdentityPoint().ScalarBaseMult(a)
	return &OTSender{ctx: ctx, a: a, A: A}, A.Bytes(), nil
}

// Respond answers the receiver's R_i with the encrypted label pairs: e0_i || e1_i for each i.
func (s *OTSender) Respond(rs []byte, m0, m1 []Label) ([]byte, error) {
	n := len(m0)
	if len(m1) != n || len(rs) != n*pointSize {
		return nil, errors.New("OT: message count mismatch")
	}
	out := make([]byte, 0, n*2*LabelSize)
	for i := 0; i < n; i++ {
		R, err := parsePoint(rs[i*pointSize : (i+1)*pointSize])
		if err != nil {
			return nil, err
		}
		p0 := edwards25519.NewIdentityPoint().ScalarMult(s.a, R)
		p1 := edwards25519.NewIdentityPoint().ScalarMult(s.a, edwards25519.NewIdentityPoint().Subtract(R, s.A))
		e0 := xorLabel(m0[i], otKey(s.ctx, i, p0))
		e1 := xorLabel(m1[i], otKey(s.ctx, i, p1))
		out = append(out, e0[:]...)
		out = append(out, e1[:]...)
	}
	return out, nil
}

func (s *OTSender) Bytes() []byte { return s.a.Bytes() }

func OTSenderFromBytes(ctx, b []byte) (*OTSender, error) {
	a, err := edwards25519.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		return nil, err
	}
	return &OTSender{ctx: ctx, a: a, A: edwards25519.NewIdentityPoint().ScalarBaseMult(a)}, nil
}

// ---- receiver ----

type OTReceiver struct {
	ctx     []byte
	A       *edwards25519.Point
	choices []bool
	b       []*edwards25519.Scalar
}

// NewOTReceiver consumes the sender's A and returns the receiver and its message R_1..R_n.
func NewOTReceiver(ctx, aBytes []byte, choices []bool) (*OTReceiver, []byte, error) {
	A, err := parsePoint(aBytes)
	if err != nil {
		return nil, nil, err
	}
	r := &OTReceiver{ctx: ctx, A: A, choices: choices, b: make([]*edwards25519.Scalar, len(choices))}
	out := make([]byte, 0, len(choices)*pointSize)
	for i, c := range choices {
		b, err := randScalar()
		if err != nil {
			return nil, nil, err
		}
		r.b[i] = b
		R := edwards25519.NewIdentityPoint().ScalarBaseMult(b)
		if c {
			R.Add(R, A)
		}
		out = append(out, R.Bytes()...)
	}
	return r, out, nil
}

// Finish decrypts the chosen label of each transfer.
func (r *OTReceiver) Finish(es []byte) ([]Label, error) {
	n := len(r.choices)
	if len(es) != n*2*LabelSize {
		return nil, errors.New("OT: bad sender response length")
	}
	out := make([]Label, n)
	for i := 0; i < n; i++ {
		var e Label
		off := i * 2 * LabelSize
		if r.choices[i] {
			off += LabelSize
		}
		copy(e[:], es[off:off+LabelSize])
		k := otKey(r.ctx, i, edwards25519.NewIdentityPoint().ScalarMult(r.b[i], r.A))
		out[i] = xorLabel(e, k)
	}
	return out, nil
}

// Bytes: A || n || choices (1 byte each) || b_i (32 bytes each).
func (r *OTReceiver) Bytes() []byte {
	out := append([]byte(nil), r.A.Bytes()...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(r.choices)))
	for _, c := range r.choices {
		if c {
			out = append(out, 1)
		} else {
			out = append(out, 0)
		}
	}
	for _, b := range r.b {
		out = append(out, b.Bytes()...)
	}
	return out
}

func OTReceiverFromBytes(ctx, data []byte) (*OTReceiver, error) {
	if len(data) < pointSize+4 {
		return nil, errors.New("OT: state too short")
	}
	A, err := parsePoint(data[:pointSize])
	if err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(data[pointSize:]))
	rest := data[pointSize+4:]
	if len(rest) != n+n*32 {
		return nil, fmt.Errorf("OT: state has wrong length")
	}
	r := &OTReceiver{ctx: ctx, A: A, choices: make([]bool, n), b: make([]*edwards25519.Scalar, n)}
	for i := 0; i < n; i++ {
		r.choices[i] = rest[i] == 1
		if r.b[i], err = edwards25519.NewScalar().SetCanonicalBytes(rest[n+i*32 : n+(i+1)*32]); err != nil {
			return nil, err
		}
	}
	return r, nil
}
