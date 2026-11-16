//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

type privilegeInfo struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type groupInfo struct {
	Name    string `json:"name"`
	SID     string `json:"sid"`
	Enabled bool   `json:"enabled"`
}

// Attestation is the process token that actually ran the measurements.
// Hostnames, machine SIDs and logon SIDs are redacted before it is written.
type Attestation struct {
	Schema            string          `json:"schema"`
	HostRole          string          `json:"host_role"`
	Service           string          `json:"service"`
	Account           string          `json:"account"`
	AccountSID        string          `json:"account_sid"`
	Elevated          bool            `json:"elevated"`
	ServiceSIDPresent bool            `json:"service_sid_present"`
	ServiceSID        string          `json:"service_sid,omitempty"`
	Administrators    bool            `json:"administrators_group"`
	IntegritySID      string          `json:"integrity_sid,omitempty"`
	Privileges        []privilegeInfo `json:"privileges"`
	Groups            []groupInfo     `json:"groups"`
	WhoamiAll         string          `json:"whoami_all"`
	Host              any             `json:"host,omitempty"`
}

func writeAttestation(path, service, host, pwsh string) error {
	token, err := openCurrentToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	accountSID := user.User.Sid.String()
	account, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		account, domain = "", ""
	}
	groups, serviceSID, administrators, integrity, err := tokenGroups(token, host)
	if err != nil {
		return err
	}
	privileges, err := tokenPrivileges(token)
	if err != nil {
		return err
	}
	whoami, err := whoamiAll(pwsh, host)
	if err != nil {
		return err
	}
	record := Attestation{
		Schema:            "device-audit.service-token-attestation.v1",
		HostRole:          HostedRunnerRole,
		Service:           service,
		Account:           redactAccount(account, domain, host),
		AccountSID:        RedactEvidence(accountSID, host),
		Elevated:          token.IsElevated(),
		ServiceSIDPresent: serviceSID != "",
		ServiceSID:        serviceSID,
		Administrators:    administrators,
		IntegritySID:      integrity,
		Privileges:        privileges,
		Groups:            groups,
		WhoamiAll:         whoami,
	}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o644)
}

func openCurrentToken() (windows.Token, error) {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	return token, err
}

func tokenGroups(token windows.Token, host string) ([]groupInfo, string, bool, string, error) {
	groups, err := token.GetTokenGroups()
	if err != nil {
		return nil, "", false, "", err
	}
	var out []groupInfo
	var serviceSID, integrity string
	administrators := false
	for _, group := range groups.AllGroups() {
		sid := group.Sid.String()
		account, domain, _, lookupErr := group.Sid.LookupAccount("")
		name := sid
		if lookupErr == nil {
			name = redactAccount(account, domain, host)
		}
		enabled := group.Attributes&windows.SE_GROUP_ENABLED != 0
		out = append(out, groupInfo{Name: RedactEvidence(name, host), SID: RedactEvidence(sid, host), Enabled: enabled})
		switch {
		case len(sid) >= len("S-1-5-80-") && sid[:len("S-1-5-80-")] == "S-1-5-80-":
			serviceSID = sid
		case sid == "S-1-5-32-544":
			administrators = true
		case len(sid) >= len("S-1-16-") && sid[:len("S-1-16-")] == "S-1-16-":
			integrity = sid
		}
	}
	return out, serviceSID, administrators, integrity, nil
}

func tokenPrivileges(token windows.Token) ([]privilegeInfo, error) {
	size := uint32(4096)
	var buf []byte
	var err error
	for {
		buf = make([]byte, size)
		err = windows.GetTokenInformation(token, windows.TokenPrivileges, &buf[0], uint32(len(buf)), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER || size <= uint32(len(buf)) {
			return nil, err
		}
	}
	privs := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	out := make([]privilegeInfo, 0, privs.PrivilegeCount)
	for _, priv := range privs.AllPrivileges() {
		name, err := lookupPrivilegeName(priv.Luid)
		if err != nil {
			return nil, err
		}
		out = append(out, privilegeInfo{
			Name:    name,
			Enabled: priv.Attributes&windows.SE_PRIVILEGE_ENABLED != 0,
		})
	}
	return out, nil
}

func lookupPrivilegeName(luid windows.LUID) (string, error) {
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("LookupPrivilegeNameW")
	var nameLen uint32 = 64
	for range 4 {
		buf := make([]uint16, nameLen)
		r, _, callErr := proc.Call(0, uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&nameLen)))
		if r != 0 {
			return windows.UTF16ToString(buf), nil
		}
		if callErr != windows.ERROR_INSUFFICIENT_BUFFER {
			return "", fmt.Errorf("collectorservice: privilege name: %v", callErr)
		}
	}
	return "", fmt.Errorf("collectorservice: privilege name did not fit")
}

func whoamiAll(pwsh, host string) (string, error) {
	cmd := exec.Command(pwsh, "-NoLogo", "-NoProfile", "-Command", "whoami /all")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("collectorservice: whoami /all: %w", err)
	}
	if len(out) > 256*1024 {
		return "", fmt.Errorf("collectorservice: whoami output is larger than 256KiB")
	}
	return RedactEvidence(string(out), host), nil
}

func computerName() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}
