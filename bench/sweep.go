package bench

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// HEStd2018Ternary128 is the largest log2(q) that the Homomorphic Encryption
// Standard (Nov. 2018) lists for 128-bit classical security with a uniform
// ternary secret and error sigma ~ 3.2, keyed by log2(N).
// Source: Table 1 (cost model BKZ.sieve), distribution (-1, 1), read from
// https://homomorphicencryption.github.io/assets/HomomorphicEncryptionStandard2018.pdf
// on 2026-11-12. The harness compares log2(QP), the largest modulus a key
// switching key is defined over, against this bound.
// The table does NOT cover sparse (fixed Hamming weight) secrets.
var HEStd2018Ternary128 = map[int]int{10: 27, 11: 54, 12: 109, 13: 218, 14: 438, 15: 881}

// ParamSet is one point of the E4 sweep.
type ParamSet struct {
	LogN       int
	LogQ, LogP []int
	Xs         string // "ternary_p2/3" (Lattigo default, uniform ternary) or "ternary_h<weight>"
}

// ID is a compact name such as "N14_Q56-55_P55_ternary_p2/3".
func (s ParamSet) ID() string {
	return fmt.Sprintf("N%d_Q%s_P%s_%s", s.LogN, joinInts(s.LogQ, "-"), joinInts(s.LogP, "-"), s.Xs)
}

// Build asks Lattigo for the parameters, with t = 65537. It fails when no
// suitable NTT-friendly primes exist or the literal is invalid.
func (s ParamSet) Build() (bgv.Parameters, error) {
	lit := bgv.ParametersLiteral{LogN: s.LogN, LogQ: s.LogQ, LogP: s.LogP, PlaintextModulus: 65537}
	switch {
	case s.Xs == "ternary_p2/3":
		lit.Xs = ring.Ternary{P: 2.0 / 3.0}
	case strings.HasPrefix(s.Xs, "ternary_h"):
		h, err := strconv.Atoi(strings.TrimPrefix(s.Xs, "ternary_h"))
		if err != nil {
			return bgv.Parameters{}, fmt.Errorf("bad secret distribution %q", s.Xs)
		}
		lit.Xs = ring.Ternary{H: h}
	default:
		return bgv.Parameters{}, fmt.Errorf("unknown secret distribution %q", s.Xs)
	}
	return bgv.NewParametersFromLiteral(lit)
}

// SecurityCheck compares the set against HEStd2018Ternary128. status is
// "within" or "exceeds" for the uniform ternary secret and "not_covered" for
// sparse secrets, which the standard leaves out.
func (s ParamSet) SecurityCheck(logQP float64) (bound int, status string) {
	bound = HEStd2018Ternary128[s.LogN]
	switch {
	case s.Xs != "ternary_p2/3":
		return bound, "not_covered"
	case logQP <= float64(bound)+0.5: // moduli are a hair under their nominal bit size
		return bound, "within"
	default:
		return bound, "exceeds"
	}
}

// DefaultSets is the E4 grid: LogN 12-15, six modulus chains from 109 to 438
// bits of QP, and two secret distributions.
func DefaultSets() []ParamSet {
	chains := []struct{ q, p []int }{
		{[]int{56}, []int{53}},                         // 109 bits: the N=2^12 bound
		{[]int{60}, []int{49}},                         // 109 bits, larger Q
		{[]int{60}, []int{60}},                         // 120 bits
		{[]int{56, 55}, []int{55}},                     // 166 bits
		{[]int{56, 54, 54}, []int{54}},                 // 218 bits: the N=2^13 bound
		{[]int{56, 55, 55, 54, 54, 54}, []int{55, 55}}, // 438 bits: the application's chain
	}
	var sets []ParamSet
	for _, xs := range []string{"ternary_p2/3", "ternary_h192"} {
		for logN := 12; logN <= 15; logN++ {
			for _, c := range chains {
				sets = append(sets, ParamSet{LogN: logN, LogQ: c.q, LogP: c.p, Xs: xs})
			}
		}
	}
	return sets
}

// ParseInts reads "56-55-55" back into a slice.
func ParseInts(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, "-") {
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func joinInts(v []int, sep string) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, sep)
}
