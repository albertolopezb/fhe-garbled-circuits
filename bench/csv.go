package bench

import (
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Header is the shared column list of the E1-E3 result files: one row per run.
var Header = []string{
	"experiment", "run_id", "case", "seed", "key_id", "commit", "dirty", "go_version",
	"logN", "logQ", "logP", "t",
	"px", "py", "ux", "uy", "r",
	"delta_true", "delta_decoded", "class_expected", "class_observed", "ok", "error",
	"t_keygen_ms", "t_encrypt_ms", "t_eval_ms", "t_e2s_ms", "t_garble_ms", "t_ot_ms", "t_gc_eval_ms", "t_total_ms",
	"garbled_bytes", "heap_alloc_bytes", "heap_sys_bytes",
	"q_bits", "raw_norm_bits", "fresh_bits", "delta_bits", "delta_std_bits", "e2s_bits",
	"budget_delta_bits", "budget_e2s_bits", "flood_margin_bits",
}

// Writer appends rows to a CSV file and flushes after every row, so a crash
// keeps everything measured so far.
type Writer struct {
	f *os.File
	w *csv.Writer
}

// Open creates path (and its directory) and writes the header.
func Open(path string, header []string) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := &Writer{f: f, w: csv.NewWriter(f)}
	return w, w.Row(header)
}

// OpenAppend opens path for appending and writes the header only if the file
// is new or empty. Several processes may append to one file in turn.
func OpenAppend(path string, header []string) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	w := &Writer{f: f, w: csv.NewWriter(f)}
	if info, err := f.Stat(); err == nil && info.Size() == 0 {
		return w, w.Row(header)
	}
	return w, nil
}

// Row writes one record and flushes it to disk.
func (w *Writer) Row(rec []string) error {
	if err := w.w.Write(rec); err != nil {
		return err
	}
	w.w.Flush()
	return w.w.Error()
}

// Close flushes and closes the file.
func (w *Writer) Close() error {
	w.w.Flush()
	return w.f.Close()
}

// Meta is the build and parameter context repeated on every row.
type Meta struct {
	Commit, GoVersion string
	Dirty             bool
	LogN              int
	LogQ, LogP        string
	T                 uint64
}

// GitCommit returns the current commit hash and whether tracked files differ from it.
func GitCommit() (hash string, dirty bool) {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "unknown", false
	}
	status, _ := exec.Command("git", "status", "--porcelain", "--untracked-files=no").Output()
	return strings.TrimSpace(string(out)), len(strings.TrimSpace(string(status))) > 0
}

// HeapNow returns the live heap and the heap obtained from the OS, sampled at
// the moment of the call (after a run), not a true peak.
func HeapNow() (alloc, sys uint64) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc, m.HeapSys
}

// F formats a float for the CSV with fixed precision.
func F(v float64) string { return strconv.FormatFloat(v, 'f', 4, 64) }

// Ints formats an int slice as "56 55 55" so it fits one CSV cell.
func Ints(v []int) string { return strings.Trim(fmt.Sprint(v), "[]") }
