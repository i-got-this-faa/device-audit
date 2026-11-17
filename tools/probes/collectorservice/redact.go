package main

import (
	"regexp"
	"strings"
)

var (
	machineSIDPattern = regexp.MustCompile(`S-1-5-21-\d+-\d+-\d+-`)
	logonSIDPattern   = regexp.MustCompile(`S-1-5-5-\d+-\d+`)
	logonNamePattern  = regexp.MustCompile(`LogonSessionId_\d+_\d+`)
)

// RedactEvidence hides the computer name, local machine SID, and logon SID.
// Well-known SIDs, including LocalService and per-service SIDs, stay intact.
func RedactEvidence(text, host string) string {
	if host != "" {
		text = regexp.MustCompile(`(?i)`+regexp.QuoteMeta(host)).ReplaceAllString(text, "<host>")
	}
	text = machineSIDPattern.ReplaceAllString(text, "S-1-5-21-<local>-")
	text = logonSIDPattern.ReplaceAllString(text, "S-1-5-5-<logon>")
	text = logonNamePattern.ReplaceAllString(text, "LogonSessionId_<logon>")
	return text
}

func redactAccount(account, domain, host string) string {
	if host != "" && strings.EqualFold(domain, host) {
		domain = "<host>"
	}
	account = RedactEvidence(account, host)
	domain = RedactEvidence(domain, host)
	switch {
	case account == "":
		return domain
	case domain == "":
		return account
	default:
		return domain + `\` + account
	}
}
