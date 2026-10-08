package demo

import (
	"encoding/base64"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func Parameters() (bgv.Parameters, error) {
	return bgv.NewParametersFromLiteral(
		bgv.ParametersLiteral{
			LogN:             14,
			LogQ:             []int{56, 55, 55, 54, 54, 54},
			LogP:             []int{55, 55},
			PlaintextModulus: 65537,
		},
	)
}

func ToMod(x int64, t uint64) uint64 {
	if x >= 0 {
		return uint64(x) % t
	}
	v := uint64(-x) % t
	if v == 0 {
		return 0
	}
	return t - v
}

func Centered(x, t uint64) int64 {
	if x > t/2 {
		return int64(x) - int64(t)
	}
	return int64(x)
}

func EncryptScalar(params bgv.Parameters, encoder *bgv.Encoder, encryptor *rlwe.Encryptor, value int64) (*rlwe.Ciphertext, error) {
	values := make([]uint64, params.MaxSlots())
	values[0] = ToMod(value, params.PlaintextModulus())

	pt := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(values, pt); err != nil {
		return nil, err
	}

	ct := bgv.NewCiphertext(params, 1, params.MaxLevel())
	if err := encryptor.Encrypt(pt, ct); err != nil {
		return nil, err
	}
	return ct, nil
}

func B64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func FromB64(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("binary payload vacío")
	}
	return base64.StdEncoding.DecodeString(s)
}

func MarshalB64(v interface{ MarshalBinary() ([]byte, error) }) (string, error) {
	b, err := v.MarshalBinary()
	if err != nil {
		return "", err
	}
	return B64(b), nil
}
