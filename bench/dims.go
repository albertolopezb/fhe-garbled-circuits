package bench

import (
	"fmt"

	"lattigo-auth-ui-demo/internal/demo"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// The three ways E5 computes delta = sum_i (p_i - u_i)^2 - R^2 in d dimensions.
const (
	// One ciphertext per coordinate, relinearize after every square (what the
	// application does for d = 2).
	VariantScalarEach = "scalar_relin_each"
	// One ciphertext per coordinate, add the degree-2 squares, relinearize once.
	VariantScalarOnce = "scalar_relin_once"
	// One ciphertext per party with the d coordinates in slots 0..d-1, one
	// square, then an inner sum that needs collective rotation keys.
	VariantPacked = "packed_rotations"
)

// DimResult adds the dimension-specific measurements to a Result.
type DimResult struct {
	*Result
	CiphertextsPerParty int
	UploadBytesPerParty int
}

// RotationKeys is the cost of generating the collective Galois keys.
type RotationKeys struct {
	Keys        int
	GenSharePMs float64 // Police: all its shares
	GenShareUMs float64 // User: all its shares
	ServerMs    float64 // CRPs, aggregation, key assembly
	ShareBytes  int     // one share of one key
	KeyBytes    int     // one assembled Galois key
}

// AddRotationKeys runs the two-party Galois key generation for the rotations
// an inner sum over d slots needs, and installs the keys in the environment.
func (e *Env) AddRotationKeys(d int, crsSeed []byte) (RotationKeys, error) {
	var rk RotationKeys
	crs, err := sampling.NewKeyedPRNG(crsSeed)
	if err != nil {
		return rk, err
	}
	gkg := multiparty.NewGaloisKeyGenProtocol(e.Params)
	galEls := e.Params.GaloisElementsForInnerSum(1, sumWidth(d))
	keys := make([]*rlwe.GaloisKey, 0, len(galEls))
	for _, galEl := range galEls {
		lap := Now()
		crp := gkg.SampleCRP(crs)
		sP, sU, sC := gkg.AllocateShare(), gkg.AllocateShare(), gkg.AllocateShare()
		rk.ServerMs += SinceMs(lap)

		lap = Now()
		if err := gkg.GenShare(e.SkP, galEl, crp, &sP); err != nil {
			return rk, err
		}
		rk.GenSharePMs += SinceMs(lap)
		lap = Now()
		if err := gkg.GenShare(e.SkU, galEl, crp, &sU); err != nil {
			return rk, err
		}
		rk.GenShareUMs += SinceMs(lap)

		lap = Now()
		if err := gkg.AggregateShares(sP, sU, &sC); err != nil {
			return rk, err
		}
		gk := rlwe.NewGaloisKey(e.Params)
		if err := gkg.GenGaloisKey(sC, crp, gk); err != nil {
			return rk, err
		}
		rk.ServerMs += SinceMs(lap)
		rk.ShareBytes, rk.KeyBytes = sP.BinarySize(), gk.BinarySize()
		keys = append(keys, gk)
	}
	rk.Keys = len(keys)
	e.EVK = rlwe.NewMemEvaluationKeySet(e.RLK, keys...)
	return rk, nil
}

// sumWidth is the number of slots the inner sum covers: d rounded up to a
// power of two, because Lattigo's InnerSum requires a width that divides the
// slot count. The extra slots hold zero in both inputs, so they add nothing.
func sumWidth(d int) int {
	w := 1
	for w < d {
		w <<= 1
	}
	return w
}

// OracleDims is the plaintext reference in d dimensions.
func OracleDims(p, u []int64, r int64) (delta int64, class string) {
	for i := range p {
		diff := p[i] - u[i]
		delta += diff * diff
	}
	delta -= r * r
	return delta, Class(delta < 0, delta == 0)
}

// RunDims executes one evaluation in len(p) dimensions with the chosen
// variant, then the usual E2S and garbled circuit. VariantPacked requires
// AddRotationKeys to have been called with at least len(p).
func (e *Env) RunDims(p, u []int64, r int64, variant string, measureNoise bool) (*DimResult, error) {
	d := len(p)
	if len(u) != d || d == 0 {
		return nil, fmt.Errorf("p and u must have the same non-zero length")
	}
	res := &DimResult{Result: &Result{}}
	enc := rlwe.NewEncryptor(e.Params, e.CPK)
	ev := bgv.NewEvaluator(e.Params, e.EVK, true)
	radius := make([]int64, e.Params.MaxSlots())
	radius[0] = r * r
	var ctDelta, fresh *rlwe.Ciphertext

	switch variant {
	case VariantScalarEach, VariantScalarOnce:
		start := Now()
		cp, cu := make([]*rlwe.Ciphertext, d), make([]*rlwe.Ciphertext, d)
		var err error
		for i := range p {
			if cp[i], err = demo.EncryptScalar(e.Params, e.Encoder, enc, p[i]); err != nil {
				return nil, fmt.Errorf("encrypt: %w", err)
			}
		}
		res.EncryptPMs = SinceMs(start)
		lap := Now()
		for i := range u {
			if cu[i], err = demo.EncryptScalar(e.Params, e.Encoder, enc, u[i]); err != nil {
				return nil, fmt.Errorf("encrypt: %w", err)
			}
		}
		res.EncryptUMs = SinceMs(lap)
		res.EncryptMs = SinceMs(start)
		fresh = cp[0]
		res.CiphertextsPerParty = d
		res.CiphertextBytes = cp[0].BinarySize()

		start = Now()
		var sum *rlwe.Ciphertext
		for i := range p {
			diff, err := ev.SubNew(cp[i], cu[i])
			if err != nil {
				return nil, fmt.Errorf("eval: %w", err)
			}
			var sq *rlwe.Ciphertext
			if variant == VariantScalarEach {
				sq, err = ev.MulRelinNew(diff, diff)
			} else {
				sq, err = ev.MulNew(diff, diff) // stays at degree 2
			}
			if err != nil {
				return nil, fmt.Errorf("eval: %w", err)
			}
			if sum == nil {
				sum = sq
			} else if sum, err = ev.AddNew(sum, sq); err != nil {
				return nil, fmt.Errorf("eval: %w", err)
			}
		}
		if variant == VariantScalarOnce {
			var err error
			if sum, err = ev.RelinearizeNew(sum); err != nil {
				return nil, fmt.Errorf("eval: %w", err)
			}
		}
		if ctDelta, err = ev.SubNew(sum, radius); err != nil {
			return nil, fmt.Errorf("eval: %w", err)
		}
		res.EvalMs = SinceMs(start)

	case VariantPacked:
		start := Now()
		cp, err := e.encryptSlots(enc, p)
		if err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
		res.EncryptPMs = SinceMs(start)
		lap := Now()
		cu, err := e.encryptSlots(enc, u)
		if err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
		res.EncryptUMs = SinceMs(lap)
		res.EncryptMs = SinceMs(start)
		fresh = cp
		res.CiphertextsPerParty = 1
		res.CiphertextBytes = cp.BinarySize()

		start = Now()
		diff, err := ev.SubNew(cp, cu)
		if err != nil {
			return nil, fmt.Errorf("eval: %w", err)
		}
		sq, err := ev.MulRelinNew(diff, diff)
		if err != nil {
			return nil, fmt.Errorf("eval: %w", err)
		}
		sum := sq
		if d > 1 {
			sum = bgv.NewCiphertext(e.Params, 1, sq.Level())
			if err := ev.InnerSum(sq, 1, sumWidth(d), sum); err != nil {
				return nil, fmt.Errorf("inner sum: %w", err)
			}
		}
		// Keep slot 0 only, so the shares carry nothing but delta.
		mask := make([]uint64, e.Params.MaxSlots())
		mask[0] = 1
		if sum, err = ev.MulNew(sum, mask); err != nil {
			return nil, fmt.Errorf("mask: %w", err)
		}
		if ctDelta, err = ev.SubNew(sum, radius); err != nil {
			return nil, fmt.Errorf("eval: %w", err)
		}
		res.EvalMs = SinceMs(start)

	default:
		return nil, fmt.Errorf("unknown variant %q", variant)
	}

	res.UploadBytesPerParty = res.CiphertextsPerParty * res.CiphertextBytes
	if err := e.finish(res.Result, ctDelta, fresh, measureNoise); err != nil {
		return nil, err
	}
	return res, nil
}

// encryptSlots encrypts values into slots 0..len(values)-1 of one ciphertext.
func (e *Env) encryptSlots(enc *rlwe.Encryptor, values []int64) (*rlwe.Ciphertext, error) {
	t := e.Params.PlaintextModulus()
	slots := make([]uint64, e.Params.MaxSlots())
	for i, v := range values {
		slots[i] = demo.ToMod(v, t)
	}
	pt := bgv.NewPlaintext(e.Params, e.Params.MaxLevel())
	if err := e.Encoder.Encode(slots, pt); err != nil {
		return nil, err
	}
	ct := bgv.NewCiphertext(e.Params, 1, e.Params.MaxLevel())
	if err := enc.Encrypt(pt, ct); err != nil {
		return nil, err
	}
	return ct, nil
}
