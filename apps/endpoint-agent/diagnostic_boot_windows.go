package main

import (
	"errors"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

func diagnosticBootID() (string, error) {
	// SYSTEM_TIMEOFDAY_INFORMATION starts with the kernel boot timestamp.
	// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntexapi.h
	var info struct {
		BootTime      int64
		CurrentTime   int64
		TimeZoneBias  int64
		TimeZoneID    uint32
		Reserved      uint32
		BootTimeBias  uint64
		SleepTimeBias uint64
	}
	err := windows.NtQuerySystemInformation(windows.SystemTimeOfDayInformation, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), nil)
	if err != nil || info.BootTime <= 0 || info.BootTime > info.CurrentTime {
		return "", errors.New("read Windows diagnostic boot time")
	}
	return "windows-boot:" + strconv.FormatInt(info.BootTime, 16), nil
}
