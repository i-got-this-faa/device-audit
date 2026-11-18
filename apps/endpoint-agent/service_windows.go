//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/i-got-this-faa/device-audit/packages/telemetry"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// Service-specific exit codes. A non-zero code triggers the SCM recovery
// actions the installer configures, so a failed pipeline is restarted.
const (
	exitConfig   = 1
	exitAccount  = 2
	exitPipeline = 3
	exitShutdown = 4
	// stopTimeout bounds how long Stop waits for the workers.
	stopTimeout = 25 * time.Second
)

// allowedServicePrivileges is the documented privilege set. The installer
// restricts the service to it with `sc.exe privs`; the service refuses to run
// with any other privilege present, enabled or not.
var allowedServicePrivileges = []string{"SeChangeNotifyPrivilege"}

// runService hands control to the SCM. It refuses an interactive session.
func runService(configPath string) error {
	inService, err := svc.IsWindowsService()
	if err != nil {
		return errors.New("cannot determine the Windows session type")
	}
	if !inService {
		return errors.New("--service runs only under the Windows service control manager; install it with tools/service/Install-EndpointService.ps1")
	}
	return svc.Run(serviceName, &endpointService{configPath: configPath})
}

type endpointService struct{ configPath string }

func (h *endpointService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	cfg, err := loadServiceConfig(h.configPath)
	if err != nil {
		// No trusted log location exists yet; the SCM records the exit code.
		return true, exitConfig
	}
	log := &serviceLog{path: filepath.Join(cfg.EvidenceDir, serviceLogFile)}
	token, err := checkServiceToken()
	if err != nil {
		log.printf("refusing to start: %s", err)
		return true, exitAccount
	}
	log.printf("starting: %s", token)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runServicePipeline(ctx, cfg, telemetry.NewScheduler, log.printf) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			// The pipeline only returns on its own when it fails.
			log.printf("pipeline failed: %s", errorText(err))
			return true, exitPipeline
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32((stopTimeout + 5*time.Second).Milliseconds())}
				cancel()
				select {
				case err := <-done:
					if err != nil {
						log.printf("pipeline failed while stopping: %s", err)
						return true, exitPipeline
					}
					log.printf("stopped cleanly")
					return false, 0
				case <-time.After(stopTimeout):
					log.printf("workers did not stop within %s", stopTimeout)
					return true, exitShutdown
				}
			}
		}
	}
}

func errorText(err error) string {
	if err == nil {
		return "pipeline ended without a stop request"
	}
	return err.Error()
}

// checkServiceToken requires NT AUTHORITY\LocalService, an enabled
// per-service SID, no elevation and no privilege outside the documented set.
// It returns a one-line description for the service log.
func checkServiceToken() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", errors.New("read service account")
	}
	switch sid := user.User.Sid.String(); sid {
	case "S-1-5-19":
	case "S-1-5-18":
		return "", errors.New("service mode refuses LocalSystem; run as NT AUTHORITY\\LocalService")
	case "S-1-5-20":
		return "", errors.New("service mode refuses NetworkService; run as NT AUTHORITY\\LocalService")
	default:
		return "", errors.New("service mode requires NT AUTHORITY\\LocalService")
	}
	// Privileges first: Windows marks a token holding a sensitive privilege
	// such as SeImpersonatePrivilege as elevated, and the privilege is the
	// actionable cause.
	privileges, err := tokenPrivileges(token)
	if err != nil {
		return "", err
	}
	for _, p := range privileges {
		if name, _, _ := strings.Cut(p, "("); !slices.Contains(allowedServicePrivileges, name) {
			return "", fmt.Errorf("service token holds %s outside the documented privileges; reinstall with sc.exe privs", name)
		}
	}
	if token.IsElevated() {
		return "", errors.New("service mode refuses an elevated token")
	}
	serviceSID, err := storagePrincipal()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("account=LocalService elevated=false service_sid=%s privileges=%s", serviceSID, strings.Join(privileges, ",")), nil
}

// tokenPrivileges lists each privilege as Name(enabled) or Name(disabled).
func tokenPrivileges(token windows.Token) ([]string, error) {
	size := uint32(1024)
	for range 4 {
		buf := make([]byte, size)
		err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buf[0], size, &size)
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if err != nil {
			return nil, errors.New("read service privileges")
		}
		privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
		out := make([]string, 0, privileges.PrivilegeCount)
		for _, p := range privileges.AllPrivileges() {
			name, err := privilegeName(p.Luid)
			if err != nil {
				return nil, err
			}
			state := "disabled"
			if p.Attributes&windows.SE_PRIVILEGE_ENABLED != 0 {
				state = "enabled"
			}
			out = append(out, name+"("+state+")")
		}
		return out, nil
	}
	return nil, errors.New("service privileges did not fit")
}

var procLookupPrivilegeNameW = windows.NewLazySystemDLL("advapi32.dll").NewProc("LookupPrivilegeNameW")

func privilegeName(luid windows.LUID) (string, error) {
	n := uint32(64)
	buf := make([]uint16, n)
	if r, _, _ := procLookupPrivilegeNameW.Call(0, uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r == 0 {
		return "", errors.New("look up privilege name")
	}
	return windows.UTF16ToString(buf[:n]), nil
}
