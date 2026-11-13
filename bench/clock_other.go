//go:build !windows

package bench

import "time"

var clockBase = time.Now()

// Now returns a monotonic timestamp in nanoseconds.
func Now() int64 { return int64(time.Since(clockBase)) }

// ClockResolutionNs is the nominal resolution of the monotonic clock.
func ClockResolutionNs() float64 { return 1 }
