//go:build js && wasm

// Ablation 4 of 4 for E9: only the garbled circuit and the oblivious transfer.
package main

import (
	"crypto/rand"
	"syscall/js"

	"lattigo-auth-ui-demo/internal/gc"
)

func main() {
	js.Global().Set("ablate", js.FuncOf(func(js.Value, []js.Value) any {
		c := gc.ShareCompareCircuit()
		g, sec, _ := gc.Garble(c, rand.Reader)
		sender, a, _ := gc.NewOTSender([]byte("ablate"))
		recv, r, _ := gc.NewOTReceiver([]byte("ablate"), a, gc.Bits(5, gc.ShareBits))
		m0, m1 := make([]gc.Label, gc.ShareBits), make([]gc.Label, gc.ShareBits)
		for i := range m0 {
			m0[i], m1[i] = sec.Pair(gc.ShareBits + i)
		}
		e, _ := sender.Respond(r, m0, m1)
		labels, _ := recv.Finish(e)
		in := make([]gc.Label, 0, c.NumInputs)
		for i, b := range gc.Bits(7, gc.ShareBits) {
			in = append(in, sec.Label(i, b))
		}
		out, _ := gc.Evaluate(c, g, append(in, labels...))
		return out[0]
	}))
	select {}
}
