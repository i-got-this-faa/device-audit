package telemetry

import (
	"errors"
	"runtime"
	"time"
)

// ErrProcessUsageUnsupported means this OS has no process CPU and RSS sample.
var ErrProcessUsageUnsupported = errors.New("telemetry: process cpu and rss are not supported on this OS")

// ProcessUsage is one sample of this process only. It excludes provider-host
// processes and child tools. Sequential samples must not be added together.
type ProcessUsage struct {
	CPU       time.Duration
	RSS       uint64
	HeapAlloc uint64
	HeapInuse uint64
	CoreCount int
}

type osSample struct {
	CPU time.Duration
	RSS uint64
}

// SampleProcess reads this process. CoreCount is runtime.NumCPU, which is the
// normalization basis for machine-wide CPU percent.
func SampleProcess() (ProcessUsage, error) {
	os, err := sampleProcessOS()
	if err != nil {
		return ProcessUsage{}, err
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	cores := runtime.NumCPU()
	if cores < 1 {
		return ProcessUsage{}, errors.New("telemetry: core count is required")
	}
	if os.RSS == 0 {
		return ProcessUsage{}, errors.New("telemetry: process rss sample is zero")
	}
	return ProcessUsage{
		CPU:       os.CPU,
		RSS:       os.RSS,
		HeapAlloc: mem.HeapAlloc,
		HeapInuse: mem.HeapInuse,
		CoreCount: cores,
	}, nil
}

// filetimeTicksToDuration converts a Windows FILETIME duration, which is a
// count of 100-nanosecond intervals, into a Go duration. It does not treat the
// value as a calendar timestamp.
func filetimeTicksToDuration(high, low uint32) time.Duration {
	ticks := int64(high)<<32 + int64(low)
	return time.Duration(ticks) * 100
}

// cpuPercents normalizes a CPU delta to elapsed wall time.
// oneCore is percent of a single core (100 means one core was busy).
// machine divides that by the reported core count.
func cpuPercents(cpu, wall time.Duration, cores int) (oneCore, machine float64, err error) {
	if wall <= 0 {
		return 0, 0, errors.New("telemetry: wall time must be positive")
	}
	if cpu < 0 {
		return 0, 0, errors.New("telemetry: cpu time must not be negative")
	}
	if cores < 1 {
		return 0, 0, errors.New("telemetry: core count must be positive")
	}
	oneCore = float64(cpu) / float64(wall) * 100
	machine = oneCore / float64(cores)
	return oneCore, machine, nil
}

func cpuDelta(start, end time.Duration) (time.Duration, error) {
	if end < start {
		return 0, errors.New("telemetry: process cpu counter moved backwards")
	}
	return end - start, nil
}
