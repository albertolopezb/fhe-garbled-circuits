//go:build js && wasm

// Ablation 3 of 4 for E9: adds the multiparty protocols (CKG, RKG, E2S).
package main

import (
	"syscall/js"

	"lattigo-auth-ui-demo/internal/demo"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/multiparty/mpbgv"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

func main() {
	js.Global().Set("ablate", js.FuncOf(func(js.Value, []js.Value) any {
		params, _ := demo.Parameters()
		crs, _ := sampling.NewKeyedPRNG([]byte("ablate"))
		sk := rlwe.NewKeyGenerator(params).GenSecretKeyNew()
		ckg := multiparty.NewPublicKeyGenProtocol(params)
		crp := ckg.SampleCRP(crs)
		share := ckg.AllocateShare()
		ckg.GenShare(sk, crp, &share)
		pk := rlwe.NewPublicKey(params)
		ckg.GenPublicKey(share, crp, pk)
		rkg := multiparty.NewRelinearizationKeyGenProtocol(params)
		rcrp := rkg.SampleCRP(crs)
		eph, r1, r2 := rkg.AllocateShare()
		rkg.GenShareRoundOne(sk, rcrp, eph, &r1)
		rkg.GenShareRoundTwo(eph, sk, r1, &r2)
		rlk := rlwe.NewRelinearizationKey(params)
		rkg.GenRelinearizationKey(r1, r2, rlk)
		ct, _ := demo.EncryptScalar(params, bgv.NewEncoder(params), rlwe.NewEncryptor(params, pk), 3)
		ev := bgv.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(rlk), true)
		out, _ := demo.ProximityDelta(params, ev, ct, ct, ct, ct, 1)
		e2s, _ := mpbgv.NewEncToShareProtocol(params, ring.DiscreteGaussian{Sigma: 1 << 30, Bound: 6 * (1 << 30)})
		mask := mpbgv.NewAdditiveShare(params)
		pub := e2s.AllocateShare(out.Level())
		e2s.GenShare(sk, out, &mask, &pub)
		e2s.GetShare(&mask, pub, out, &mask)
		return out.Level()
	}))
	select {}
}
