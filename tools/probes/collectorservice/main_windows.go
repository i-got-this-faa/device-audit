//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
)

func main() {
	config := ""
	serviceName := ""
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "--config":
			config = args[i+1]
			i++
		case "--service":
			serviceName = args[i+1]
			i++
		}
	}
	if config == "" || (serviceName != "DeviceAuditLocal" && serviceName != "DeviceAuditDenied") {
		fmt.Fprintln(os.Stderr, "collectorservice: --service DeviceAuditLocal|DeviceAuditDenied and --config are required")
		os.Exit(2)
	}
	inService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !inService {
		fmt.Fprintln(os.Stderr, "collectorservice: refusing an interactive session; install it as a service")
		os.Exit(2)
	}
	if err := svc.Run(serviceName, &serviceHandler{configPath: config}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
