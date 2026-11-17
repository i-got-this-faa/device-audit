//go:build linux

package telemetry

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func sampleProcessOS() (osSample, error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return osSample{}, fmt.Errorf("telemetry: read process stat: %w", err)
	}
	utime, stime, rssPages, err := parseProcStat(string(data))
	if err != nil {
		return osSample{}, err
	}
	ticks, err := clockTicksPerSecond()
	if err != nil || ticks <= 0 {
		return osSample{}, fmt.Errorf("telemetry: clock tick: %w", err)
	}
	page := unix.Getpagesize()
	if page <= 0 {
		return osSample{}, fmt.Errorf("telemetry: page size %d is invalid", page)
	}
	cpu := time.Duration(utime+stime) * time.Second / time.Duration(ticks)
	sample := osSample{CPU: cpu, RSS: uint64(rssPages) * uint64(page)}
	// The high-water mark is optional; a missing field leaves it zero.
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		sample.PeakRSS = parseVmHWM(string(status))
	}
	return sample, nil
}

// parseVmHWM returns the VmHWM line of /proc/self/status in bytes, or 0.
func parseVmHWM(status string) uint64 {
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmHWM:" && fields[2] == "kB" {
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil || kb > 1<<44 {
				return 0
			}
			return kb * 1024
		}
	}
	return 0
}

// parseProcStat reads utime, stime and rss from /proc/self/stat.
// The comm field is wrapped in parentheses and may contain spaces.
func parseProcStat(stat string) (utime, stime, rss int64, err error) {
	closeParen := strings.LastIndex(stat, ")")
	if closeParen < 0 || closeParen+2 >= len(stat) {
		return 0, 0, 0, fmt.Errorf("telemetry: process stat has no command field")
	}
	fields := strings.Fields(stat[closeParen+2:])
	// After comm: state is 0, utime is 11, stime is 12, rss is 21.
	if len(fields) <= 21 {
		return 0, 0, 0, fmt.Errorf("telemetry: process stat is missing cpu or rss fields")
	}
	utime, err = strconv.ParseInt(fields[11], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("telemetry: utime: %w", err)
	}
	stime, err = strconv.ParseInt(fields[12], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("telemetry: stime: %w", err)
	}
	rss, err = strconv.ParseInt(fields[21], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("telemetry: rss: %w", err)
	}
	if utime < 0 || stime < 0 || rss < 0 {
		return 0, 0, 0, fmt.Errorf("telemetry: process stat counters are negative")
	}
	return utime, stime, rss, nil
}

// clockTicksPerSecond reads AT_CLKTCK from the process auxiliary vector.
// Linux does not expose sysconf without cgo in the pinned x/sys package.
func clockTicksPerSecond() (int64, error) {
	const atClktck = 17
	data, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return 0, err
	}
	width := strconv.IntSize / 8
	for len(data) >= width*2 {
		var tag, value uint64
		if width == 8 {
			tag = binary.NativeEndian.Uint64(data[:8])
			value = binary.NativeEndian.Uint64(data[8:16])
		} else {
			tag = uint64(binary.NativeEndian.Uint32(data[:4]))
			value = uint64(binary.NativeEndian.Uint32(data[4:8]))
		}
		if tag == atClktck {
			if value == 0 {
				return 0, fmt.Errorf("telemetry: clock tick is zero")
			}
			return int64(value), nil
		}
		data = data[width*2:]
	}
	return 0, fmt.Errorf("telemetry: AT_CLKTCK is missing")
}
