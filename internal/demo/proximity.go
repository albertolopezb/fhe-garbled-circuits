package demo

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// Coordinates and radii in [0, 100] keep Delta in [-10000, 20000].
const MaxProximityInput = 100

func ProximityDelta(params bgv.Parameters, ev *bgv.Evaluator, px, py, qx, qy *rlwe.Ciphertext, radius int64) (*rlwe.Ciphertext, error) {
	dx, err := ev.SubNew(px, qx)
	if err != nil {
		return nil, err
	}
	dy, err := ev.SubNew(py, qy)
	if err != nil {
		return nil, err
	}
	dx2, err := ev.MulRelinNew(dx, dx)
	if err != nil {
		return nil, err
	}
	dy2, err := ev.MulRelinNew(dy, dy)
	if err != nil {
		return nil, err
	}
	dist2, err := ev.AddNew(dx2, dy2)
	if err != nil {
		return nil, err
	}
	radiusSquared := make([]int64, params.MaxSlots())
	radiusSquared[0] = radius * radius
	return ev.SubNew(dist2, radiusSquared)
}
