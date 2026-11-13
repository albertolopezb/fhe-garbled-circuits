//go:build !windows

package bench

// ProcessMemory is only implemented on Windows; elsewhere it returns zeros.
func ProcessMemory() (peakWorkingSet, peakCommit uint64) { return 0, 0 }

// ProcessCPUMs is only implemented on Windows; elsewhere it returns zero.
func ProcessCPUMs() float64 { return 0 }
