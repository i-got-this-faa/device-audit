package main

import (
	"time"

	"golang.org/x/sys/windows"
)

func exhaustInferenceTestBudget(mode string) {
	if mode == "cpu" {
		for {
		}
	}
	for range 40 {
		if _, err := windows.VirtualAlloc(0, 2<<20, windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE); err != nil {
			break
		}
	}
	time.Sleep(time.Minute)
}
