package main

import (
	"strings"
	"testing"
)

func TestRedactEvidence(t *testing.T) {
	raw := "HOST\\deviceaudit-denied S-1-5-21-111-222-333-513 S-1-5-5-0-9 LogonSessionId_0_2430882 S-1-5-19 S-1-5-80-1-2 NT AUTHORITY\\LOCAL SERVICE"
	got := RedactEvidence(raw, "HOST")
	for _, hidden := range []string{"HOST\\", "111-222-333", "S-1-5-5-0-9", "2430882"} {
		if strings.Contains(got, hidden) {
			t.Fatalf("redaction left %q in %s", hidden, got)
		}
	}
	for _, keep := range []string{"<host>\\deviceaudit-denied", "S-1-5-21-<local>-513", "S-1-5-5-<logon>", "LogonSessionId_<logon>", "S-1-5-19", "S-1-5-80-1-2", "NT AUTHORITY\\LOCAL SERVICE"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("missing %q in %s", keep, got)
		}
	}
	if got := redactAccount("deviceaudit-denied", "RunnerHost", "runnerhost"); got != `<host>\deviceaudit-denied` {
		t.Fatalf("account = %s", got)
	}
}
