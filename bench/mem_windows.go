//go:build windows

package bench

import (
	"syscall"
	"unsafe"
)

// processMemoryCounters mirrors the Win32 PROCESS_MEMORY_COUNTERS struct.
type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
}

var procGetProcessMemoryInfo = kernel32.NewProc("K32GetProcessMemoryInfo")

// ProcessMemory returns this process's peak working set and peak commit
// (pagefile usage) in bytes, as Windows reports them. The working set is the
// Windows counterpart of RSS, not an identical quantity.
func ProcessMemory() (peakWorkingSet, peakCommit uint64) {
	var c processMemoryCounters
	c.cb = uint32(unsafe.Sizeof(c))
	self := ^uintptr(0) // pseudo-handle of the current process
	ret, _, _ := procGetProcessMemoryInfo.Call(self, uintptr(unsafe.Pointer(&c)), uintptr(c.cb))
	if ret == 0 {
		return 0, 0
	}
	return uint64(c.peakWorkingSetSize), uint64(c.peakPagefileUsage)
}

// ProcessCPUMs returns the user + kernel CPU time used by this process, in ms.
func ProcessCPUMs() float64 {
	var creation, exit, kernel, user syscall.Filetime
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0
	}
	if err := syscall.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return 0
	}
	ticks := func(f syscall.Filetime) float64 { return float64(uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime)) }
	return (ticks(kernel) + ticks(user)) / 1e4 // 100 ns units -> ms
}
