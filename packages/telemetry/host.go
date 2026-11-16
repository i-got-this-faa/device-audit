package telemetry

import "runtime"

const hostRole = "development_or_ci_not_physical_target"

// HostInfo describes the machine that ran the harness. It omits hostnames,
// serials, users and device identifiers.
type HostInfo struct {
	Role               string `json:"role"`
	GoVersion          string `json:"go_version"`
	GOOS               string `json:"goos"`
	GOARCH             string `json:"goarch"`
	OSFamily           string `json:"os_family"`
	OSVersion          string `json:"os_version"`
	CPUModel           string `json:"cpu_model,omitempty"`
	CoreCount          int    `json:"core_count"`
	TotalPhysicalBytes uint64 `json:"total_physical_bytes,omitempty"`
}

// CurrentHost reads the local OS description. Missing optional fields stay empty.
func CurrentHost() HostInfo {
	info := HostInfo{
		Role:      hostRole,
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		CoreCount: runtime.NumCPU(),
	}
	family, version, model, total := readHostDetails()
	info.OSFamily = family
	info.OSVersion = version
	info.CPUModel = model
	info.TotalPhysicalBytes = total
	if info.OSFamily == "" {
		info.OSFamily = runtime.GOOS
	}
	if info.OSVersion == "" {
		info.OSVersion = "unknown"
	}
	return info
}
