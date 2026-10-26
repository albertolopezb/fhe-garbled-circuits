package main

import (
	"crypto/rand"
	"errors"

	"lattigo-auth-ui-demo/internal/demo"
	"lattigo-auth-ui-demo/internal/gc"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty/mpbgv"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// Δ never leaves this file in the clear. The two parties first turn Enc(Δ) into
// additive shares modulo t (encryption-to-shares, E2S) and then compare the
// shares inside a garbled circuit. The suspect garbles, the police evaluates,
// so only the police learns the outcome and only as a classification.

var e2sNoise = ring.DiscreteGaussian{Sigma: 1 << 30, Bound: 6 * (1 << 30)}

func newE2S() (mpbgv.EncToShareProtocol, error) {
	return mpbgv.NewEncToShareProtocol(state.params, e2sNoise)
}

func decodeSlot0(poly ring.Poly, scale rlwe.Scale) (uint64, error) {
	values := make([]uint64, state.params.MaxSlots())
	if err := state.encoder.DecodeRingT(poly, scale, values); err != nil {
		return 0, err
	}
	return values[0], nil
}

// remember stores a produced message; if the step already ran it returns the stored one.
func remember(key, value string) string {
	if state.msgs == nil {
		state.msgs = map[string]string{}
	}
	if old, ok := state.msgs[key]; ok {
		return old
	}
	state.msgs[key] = value
	return value
}

func recall(key string) (string, bool) {
	v, ok := state.msgs[key]
	return v, ok
}

// e2sGenShare: this party picks a random mask M_i and publishes (its decryption share - M_i).
func e2sGenShare(ctDeltaB64 string) response {
	if err := requireInit(); err != nil {
		return fail(err)
	}
	if v, ok := recall("e2sShare"); ok {
		return response{OK: true, Role: state.role, E2SShare: v, Message: "E2S share ya generada"}
	}
	ct, err := parseCiphertext(ctDeltaB64)
	if err != nil {
		return fail(err)
	}
	e2s, err := newE2S()
	if err != nil {
		return fail(err)
	}
	mask := mpbgv.NewAdditiveShare(state.params)
	pub := e2s.AllocateShare(ct.Level())
	e2s.GenShare(state.sk, ct, &mask, &pub)
	pubB64, err := demo.MarshalB64(pub)
	if err != nil {
		return fail(err)
	}
	state.e2sMask = &mask
	return response{OK: true, Role: state.role, E2SShare: remember("e2sShare", pubB64), Message: "E2S share generada; la máscara aditiva permanece local"}
}

// e2sFinish turns the aggregated public share into this party's additive share of Δ.
// The suspect adds its own mask back (GetShare); the police simply keeps its mask.
// The share stays inside the WASM instance and is never returned to JavaScript.
func e2sFinish(ctDeltaB64, aggB64 string) response {
	if err := requireInit(); err != nil {
		return fail(err)
	}
	if state.hasShare {
		return response{OK: true, Role: state.role, Message: "share aditiva de Δ lista"}
	}
	if state.e2sMask == nil {
		return response{OK: false, Error: "primero hay que generar la E2S share", Role: state.role}
	}
	var poly ring.Poly
	var scale rlwe.Scale
	ct, err := parseCiphertext(ctDeltaB64)
	if err != nil {
		return fail(err)
	}
	scale = ct.Scale

	if state.role == "suspect" {
		e2s, err := newE2S()
		if err != nil {
			return fail(err)
		}
		agg := e2s.AllocateShare(ct.Level())
		data, err := demo.FromB64(aggB64)
		if err != nil {
			return fail(err)
		}
		if err := agg.UnmarshalBinary(data); err != nil {
			return fail(err)
		}
		out := mpbgv.NewAdditiveShare(state.params)
		e2s.GetShare(state.e2sMask, agg, ct, &out)
		poly = out.Value
	} else {
		poly = state.e2sMask.Value
	}
	v, err := decodeSlot0(poly, scale)
	if err != nil {
		return fail(err)
	}
	state.share, state.hasShare = v, true
	state.e2sMask = nil // the mask is no longer needed
	return response{OK: true, Role: state.role, Message: "share aditiva de Δ lista; Δ no fue reconstruido"}
}

func requireShareRole(role string) error {
	if err := requireInit(); err != nil {
		return err
	}
	if state.role != role {
		return errors.New("esta operación corresponde al rol " + role)
	}
	if !state.hasShare {
		return errors.New("todavía no existe la share aditiva de Δ")
	}
	return nil
}

// gcGarble (suspect): garble the comparison circuit, encode our own share bits and start the OT.
func gcGarble(ctx string) response {
	if err := requireShareRole("suspect"); err != nil {
		return fail(err)
	}
	if ctx == "" {
		return response{OK: false, Error: "ctx vacío", Role: state.role}
	}
	if g, ok := recall("garbled"); ok {
		l, _ := recall("gcLabels")
		a, _ := recall("otA")
		return response{OK: true, Role: state.role, Garbled: g, GCLabels: l, OTA: a, Message: "circuito ya garbleado"}
	}
	c := gc.ShareCompareCircuit()
	g, sec, err := gc.Garble(c, rand.Reader)
	if err != nil {
		return fail(err)
	}
	raw, err := g.MarshalBinary()
	if err != nil {
		return fail(err)
	}
	labels := make([]gc.Label, gc.ShareBits)
	for i, bit := range gc.Bits(state.share, gc.ShareBits) {
		labels[i] = sec.Label(i, bit)
	}
	sender, msgA, err := gc.NewOTSender([]byte(ctx))
	if err != nil {
		return fail(err)
	}
	state.gcCtx, state.gcSecret, state.otSender = ctx, sec, sender
	return response{
		OK:       true,
		Role:     state.role,
		Garbled:  remember("garbled", demo.B64(raw)),
		GCLabels: remember("gcLabels", demo.B64(gc.EncodeLabels(labels))),
		OTA:      remember("otA", demo.B64(msgA)),
		Message:  "circuito garbleado localmente; solo se envían tablas y labels",
	}
}

// gcOTChoose (police): choose, bit by bit, the label for our share without revealing the bits.
func gcOTChoose(ctx, otAB64 string) response {
	if err := requireShareRole("police"); err != nil {
		return fail(err)
	}
	if v, ok := recall("otR"); ok {
		return response{OK: true, Role: state.role, OTR: v, Message: "OT ya iniciada"}
	}
	a, err := demo.FromB64(otAB64)
	if err != nil {
		return fail(err)
	}
	recv, msgR, err := gc.NewOTReceiver([]byte(ctx), a, gc.Bits(state.share, gc.ShareBits))
	if err != nil {
		return fail(err)
	}
	state.gcCtx, state.otRecv = ctx, recv
	return response{OK: true, Role: state.role, OTR: remember("otR", demo.B64(msgR)), Message: "OT: selección enviada sin revelar los bits de la share"}
}

// gcOTRespond (suspect): answer the OT with both labels of every evaluator input wire, encrypted.
func gcOTRespond(otRB64 string) response {
	if err := requireShareRole("suspect"); err != nil {
		return fail(err)
	}
	if v, ok := recall("otE"); ok {
		return response{OK: true, Role: state.role, OTE: v, Message: "OT ya respondida"}
	}
	if state.gcSecret == nil || state.otSender == nil {
		return response{OK: false, Error: "el circuito todavía no fue garbleado en este navegador", Role: state.role}
	}
	rs, err := demo.FromB64(otRB64)
	if err != nil {
		return fail(err)
	}
	m0 := make([]gc.Label, gc.ShareBits)
	m1 := make([]gc.Label, gc.ShareBits)
	for i := range m0 {
		m0[i], m1[i] = state.gcSecret.Pair(gc.ShareBits + i)
	}
	es, err := state.otSender.Respond(rs, m0, m1)
	if err != nil {
		return fail(err)
	}
	return response{OK: true, Role: state.role, OTE: remember("otE", demo.B64(es)), Message: "OT respondida"}
}

// gcEvaluate (police): evaluate the garbled circuit and classify. Only the output bits are decoded.
func gcEvaluate(garbledB64, labelsB64, otEB64 string) response {
	if err := requireShareRole("police"); err != nil {
		return fail(err)
	}
	if state.otRecv == nil {
		return response{OK: false, Error: "la OT no fue iniciada en este navegador", Role: state.role}
	}
	c := gc.ShareCompareCircuit()
	raw, err := demo.FromB64(garbledB64)
	if err != nil {
		return fail(err)
	}
	g, err := gc.UnmarshalGarbled(raw, c)
	if err != nil {
		return fail(err)
	}
	lb, err := demo.FromB64(labelsB64)
	if err != nil {
		return fail(err)
	}
	garblerLabels, err := gc.DecodeLabels(lb, gc.ShareBits)
	if err != nil {
		return fail(err)
	}
	es, err := demo.FromB64(otEB64)
	if err != nil {
		return fail(err)
	}
	mine, err := state.otRecv.Finish(es)
	if err != nil {
		return fail(err)
	}
	out, err := gc.Evaluate(c, g, append(garblerLabels, mine...))
	if err != nil {
		return fail(err)
	}

	classification := "FUERA DEL RADIO"
	if out[gc.OutInside] {
		classification = "DENTRO DEL RADIO"
	} else if out[gc.OutZero] {
		classification = "EXACTAMENTE EN EL LIMITE"
	}
	return response{OK: true, Role: state.role, Class: classification, Message: "resultado obtenido del circuito garbleado; Δ nunca se reconstruyó"}
}

// ---- persistence across page reloads ----

func exportProtocolState(s *localStateSnapshot) error {
	if state.e2sMask != nil {
		b, err := state.e2sMask.Value.MarshalBinary()
		if err != nil {
			return err
		}
		s.E2SMask = demo.B64(b)
	}
	s.HasShare, s.Share = state.hasShare, state.share
	s.GCCtx = state.gcCtx
	if state.gcSecret != nil {
		s.GCSecret = demo.B64(state.gcSecret.Bytes())
	}
	if state.otSender != nil {
		s.OTSender = demo.B64(state.otSender.Bytes())
	}
	if state.otRecv != nil {
		s.OTRecv = demo.B64(state.otRecv.Bytes())
	}
	s.Msgs = state.msgs
	return nil
}

func importProtocolState(s *localStateSnapshot) error {
	if s.E2SMask != "" {
		b, err := demo.FromB64(s.E2SMask)
		if err != nil {
			return err
		}
		mask := mpbgv.NewAdditiveShare(state.params)
		if err := mask.Value.UnmarshalBinary(b); err != nil {
			return err
		}
		state.e2sMask = &mask
	}
	state.hasShare, state.share = s.HasShare, s.Share
	state.gcCtx = s.GCCtx
	state.msgs = s.Msgs
	if s.GCSecret != "" {
		b, err := demo.FromB64(s.GCSecret)
		if err != nil {
			return err
		}
		if state.gcSecret, err = gc.SecretFromBytes(b, 2*gc.ShareBits); err != nil {
			return err
		}
	}
	if s.OTSender != "" {
		b, err := demo.FromB64(s.OTSender)
		if err != nil {
			return err
		}
		if state.otSender, err = gc.OTSenderFromBytes([]byte(s.GCCtx), b); err != nil {
			return err
		}
	}
	if s.OTRecv != "" {
		b, err := demo.FromB64(s.OTRecv)
		if err != nil {
			return err
		}
		if state.otRecv, err = gc.OTReceiverFromBytes([]byte(s.GCCtx), b); err != nil {
			return err
		}
	}
	return nil
}
