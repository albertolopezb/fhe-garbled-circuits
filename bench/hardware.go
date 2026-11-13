package bench

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// windowsProbe collects the machine facts the measurement protocol asks for.
// It only reads; it changes no setting.
const windowsProbe = `
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$cs  = Get-CimInstance Win32_ComputerSystem
$os  = Get-CimInstance Win32_OperatingSystem
$bat = Get-CimInstance Win32_Battery | Select-Object -First 1
$def = try { (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled } catch { $null }
$chrome = (Get-Item "$env:ProgramFiles\Google\Chrome\Application\chrome.exe" -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
[ordered]@{
  manufacturer = $cs.Manufacturer
  model        = $cs.Model
  ram_bytes    = [uint64]$cs.TotalPhysicalMemory
  memory_modules = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object { [ordered]@{ capacity_bytes = [uint64]$_.Capacity; speed_mhz = $_.Speed } })
  cpus = @(Get-CimInstance Win32_Processor | ForEach-Object { [ordered]@{
      name = $_.Name.Trim(); physical_cores = $_.NumberOfCores; logical_cores = $_.NumberOfLogicalProcessors
      max_clock_mhz = $_.MaxClockSpeed; current_clock_mhz = $_.CurrentClockSpeed } })
  os = $os.Caption; os_version = $os.Version; os_build = $os.BuildNumber
  power_scheme = (powercfg /getactivescheme | Out-String).Trim()
  on_ac_power  = if ($bat) { $bat.BatteryStatus -eq 2 } else { $true }
  battery_status_code = if ($bat) { $bat.BatteryStatus } else { $null }
  battery_percent = if ($bat) { $bat.EstimatedChargeRemaining } else { $null }
  defender_realtime_enabled = $def
  chrome_version = $chrome
} | ConvertTo-Json -Depth 4
`

// Hardware is the content of results/hardware.json.
type Hardware struct {
	Date        string          `json:"date"`
	GitCommit   string          `json:"git_commit"`
	GitDirty    bool            `json:"git_dirty"`
	GoVersion   string          `json:"go_version"`
	GOOS        string          `json:"goos"`
	GOARCH      string          `json:"goarch"`
	NumCPU      int             `json:"go_num_cpu"`
	NodeVersion string          `json:"node_version"`
	Chromium    string          `json:"playwright_chromium_version"`
	Machine     json.RawMessage `json:"machine"`
	ProbeError  string          `json:"probe_error,omitempty"`
}

// CollectHardware gathers the record. On Windows the machine block comes from
// CIM, powercfg and Defender; elsewhere it is left null.
func CollectHardware() Hardware {
	hash, dirty := GitCommit()
	h := Hardware{
		Date: time.Now().Format(time.RFC3339), GitCommit: hash, GitDirty: dirty,
		GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, NumCPU: runtime.NumCPU(),
		NodeVersion: firstLine("node", "--version"),
		Chromium:    "not installed (Playwright missing at Phase 0)",
		Machine:     json.RawMessage("null"),
	}
	if runtime.GOOS == "windows" {
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", windowsProbe).Output()
		switch {
		case err != nil:
			h.ProbeError = err.Error()
		case !json.Valid(out):
			h.ProbeError = "probe output is not valid JSON"
		default:
			h.Machine = json.RawMessage(strings.TrimSpace(string(out)))
		}
	}
	return h
}

// WriteHardware writes the record to path as indented JSON.
func WriteHardware(path string) (Hardware, error) {
	h := CollectHardware()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return h, err
	}
	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return h, err
	}
	return h, os.WriteFile(path, append(data, '\n'), 0o644)
}

func firstLine(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "not found"
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
}
