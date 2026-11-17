//go:build !windows

package telemetry

import "context"

// PlatformSensorSources returns sources that report sensor_unavailable. V1
// selects only the Windows target (#14); no Linux or macOS endpoint sensor
// provider is implemented or claimed.
func PlatformSensorSources() []SensorSource {
	sources := SensorSourceSpecs()
	for i := range sources {
		sources[i].Read = func(context.Context) ([]SensorReading, error) {
			return nil, sensorErr(ErrSensorUnavailable, "platform_not_selected")
		}
	}
	return sources
}
