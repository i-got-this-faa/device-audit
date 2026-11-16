package telemetry

import (
	"errors"
	"slices"
	"testing"
)

func TestCatalogRejectsUnrestrictedRights(t *testing.T) {
	seen := map[string]bool{}
	for _, spec := range Catalog() {
		if seen[spec.Source] {
			t.Fatalf("duplicate source %s", spec.Source)
		}
		seen[spec.Source] = true
		if err := spec.validate(); err != nil {
			t.Fatal(err)
		}
		for _, cap := range spec.Required {
			if unrestrictedCapability(cap) {
				t.Fatalf("%s requires unrestricted capability %s", spec.Source, cap)
			}
		}
	}
	for _, name := range []string{"cpu", "memory", "disk", "network", "battery", "thermal", "gpu", "events"} {
		if !seen[name] {
			t.Fatalf("catalog is missing %s", name)
		}
	}
	if slices.Contains(PlanningToken().Capabilities, CapSecurityLog) {
		t.Fatal("planned profile includes the security log")
	}
}

func TestPlanningAndDeniedProfiles(t *testing.T) {
	planned := PlanningToken()
	denied := DeniedToken()
	rows, err := Compare(planned, denied)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(Catalog()) {
		t.Fatalf("rows = %d", len(rows))
	}
	for _, row := range rows {
		if row.Planned != "allowed" || row.Denied != "permission_denied" {
			t.Fatalf("%s planned=%s denied=%s", row.Source, row.Planned, row.Denied)
		}
		if row.ExtraGrantSelected || row.UnrestrictedExecution || row.ServiceAccessQualified {
			t.Fatalf("%s claims an extra grant or qualification", row.Source)
		}
	}
	if QualifiesServiceAccess(planned, denied, 2) {
		t.Fatal("two targets qualified service access without attestation")
	}
	attested := planned
	attested.Attested = true
	if QualifiesServiceAccess(attested, denied, 2) {
		t.Fatal("attested arguments qualified service access")
	}
	if err := attested.Validate(); !errors.Is(err, ErrNativeTokenUnattested) {
		t.Fatalf("attested token error = %v", err)
	}
}

func TestMissingCapabilityDeniesOnlyThatSource(t *testing.T) {
	token := PlanningToken()
	filtered := make([]Capability, 0, len(token.Capabilities))
	for _, cap := range token.Capabilities {
		if cap != CapExistingNvidiaSMI {
			filtered = append(filtered, cap)
		}
	}
	token.Capabilities = filtered
	for _, spec := range Catalog() {
		err := token.Allows(spec)
		if spec.Source == "gpu" {
			if !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("gpu error = %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", spec.Source, err)
		}
	}
}

func TestUnrestrictedTokenIsRejected(t *testing.T) {
	token := PlanningToken()
	token.Capabilities = append(token.Capabilities, CapAdministrator)
	if err := token.Validate(); !errors.Is(err, ErrUnrestrictedCapability) {
		t.Fatalf("error = %v", err)
	}
	token = PlanningToken()
	token.Capabilities = append(token.Capabilities, Capability("se_tcb"))
	if err := token.Validate(); err == nil {
		t.Fatal("unknown capability was accepted")
	}
}

func TestNativeAttestationIsUnavailable(t *testing.T) {
	_, err := AttestNativeToken()
	if !errors.Is(err, ErrNativeTokenUnattested) {
		t.Fatalf("error = %v", err)
	}
}
