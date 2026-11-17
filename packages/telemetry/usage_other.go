//go:build !linux && !windows

package telemetry

func sampleProcessOS() (osSample, error) {
	return osSample{}, ErrProcessUsageUnsupported
}
