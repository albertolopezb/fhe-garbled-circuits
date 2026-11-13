//go:build windows

package bench

import (
	"syscall"
	"unsafe"
)

// Go's monotonic clock on Windows advances in steps of about 0.5 ms or more,
// which reads as 0 for the garbling and circuit-evaluation phases. The
// harness therefore reads QueryPerformanceCounter directly.
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	procQPC  = kernel32.NewProc("QueryPerformanceCounter")
	procQPF  = kernel32.NewProc("QueryPerformanceFrequency")
	qpcFreq  int64
)

func init() {
	procQPF.Call(uintptr(unsafe.Pointer(&qpcFreq)))
}

// Now returns a monotonic timestamp in nanoseconds from the Windows
// performance counter.
func Now() int64 {
	var c int64
	procQPC.Call(uintptr(unsafe.Pointer(&c)))
	return c/qpcFreq*1e9 + c%qpcFreq*1e9/qpcFreq
}

// ClockResolutionNs is the size of one performance-counter tick in nanoseconds.
func ClockResolutionNs() float64 { return 1e9 / float64(qpcFreq) }
