//go:build js && wasm

// Ablation 2 of 4 for E9: adds single-key BGV (parameters, keygen, encrypt, multiply).
package main

import (
	"syscall/js"

	"lattigo-auth-ui-demo/internal/demo"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func main() {
	js.Global().Set("ablate", js.FuncOf(func(js.Value, []js.Value) any {
		params, _ := demo.Parameters()
		kgen := rlwe.NewKeyGenerator(params)
		sk, pk := kgen.GenKeyPairNew()
		rlk := kgen.GenRelinearizationKeyNew(sk)
		enc := rlwe.NewEncryptor(params, pk)
		ct, _ := demo.EncryptScalar(params, bgv.NewEncoder(params), enc, 3)
		ev := bgv.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(rlk), true)
		out, _ := demo.ProximityDelta(params, ev, ct, ct, ct, ct, 1)
		return out.Level()
	}))
	select {}
}
