//go:build !linux && !windows

package telemetry

func readHostDetails() (family, version, model string, total uint64) {
	return "", "", "", 0
}
