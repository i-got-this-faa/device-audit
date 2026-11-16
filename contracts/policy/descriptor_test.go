package policy

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

type policyVector struct {
	Name          string          `json:"name"`
	Valid         bool            `json:"valid"`
	EvidenceClass string          `json:"evidence_class"`
	Descriptor    json.RawMessage `json:"descriptor"`
}

func TestCommittedReleaseDescriptor(t *testing.T) {
	data, err := os.ReadFile("../release-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.Enabled {
		t.Fatal("committed release descriptor is enabled")
	}
	class, err := descriptor.EvidenceClass()
	if err != nil {
		t.Fatal(err)
	}
	if class != EvidenceSelectedRelease {
		t.Fatalf("evidence class %s", class)
	}
	if descriptor.ChainID != MainnetChainID || descriptor.AdapterID != MainnetAdapterID {
		t.Fatal("committed descriptor is not Base Mainnet")
	}
	if descriptor.MaxTotalFeeWei != MaxTransactionFeeWei || descriptor.Rolling24hFeeBudgetWei != MaxDailyFeeWei {
		t.Fatal("committed ceilings differ from the selected policy")
	}
	if descriptor.AdministratorThreshold != AdministratorThreshold || descriptor.AdministratorOwnerCount != AdministratorOwners {
		t.Fatal("committed administrator is not 2-of-3")
	}
	if descriptor.ReleaseDeploymentObserved() {
		t.Fatal("descriptor validation observed a deployment")
	}
	for _, value := range []*string{
		descriptor.ContractAddress,
		descriptor.RuntimeCodeKeccak256,
		descriptor.DeploymentTransactionHash,
		descriptor.DeploymentBlockHash,
		descriptor.AdministratorMultisig,
		descriptor.WriterAddress,
		descriptor.SignerServiceReference,
		descriptor.TrustedVerifierReference,
		descriptor.IndependentRPCReference,
	} {
		if value != nil {
			t.Fatal("committed descriptor contains deployment material")
		}
	}
}

func TestDescriptorVectors(t *testing.T) {
	data, err := os.ReadFile("../fixtures/policy/v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var collection struct {
		Vectors []policyVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &collection); err != nil {
		t.Fatal(err)
	}
	if len(collection.Vectors) == 0 {
		t.Fatal("no policy vectors")
	}
	seenRelease := false
	seenTestnet := false
	seenLocal := false
	for _, vector := range collection.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			descriptor, err := Parse(vector.Descriptor)
			if vector.Valid != (err == nil) {
				t.Fatalf("valid=%v err=%v", vector.Valid, err)
			}
			if !vector.Valid {
				return
			}
			if descriptor.ReleaseDeploymentObserved() {
				t.Fatal("fixture validation observed a deployment")
			}
			class, err := descriptor.EvidenceClass()
			if err != nil {
				t.Fatal(err)
			}
			if class != vector.EvidenceClass {
				t.Fatalf("evidence class %s, want %s", class, vector.EvidenceClass)
			}
			switch class {
			case EvidenceSelectedRelease:
				seenRelease = true
			case EvidenceIntegrationTestnet:
				seenTestnet = true
			case EvidenceLocalTest:
				seenLocal = true
			default:
				t.Fatalf("unknown evidence class %s", class)
			}
		})
	}
	if !seenRelease || !seenTestnet || !seenLocal {
		t.Fatal("fixtures do not separate release, testnet, and local descriptors")
	}
}

func TestDescriptorEncodingRejections(t *testing.T) {
	committed, err := os.ReadFile("../release-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(string(committed), `"policy_version"`, `"policy_version":"device-audit.chain-policy.v1","policy_version"`, 1)
	fractional := strings.Replace(string(committed), `"chain_id": 8453`, `"chain_id": 8453.0`, 1)
	nullEnabled := strings.Replace(string(committed), `"enabled": false`, `"enabled": null`, 1)
	trailing := string(committed) + "\n{}"
	for _, test := range []struct {
		name string
		raw  string
	}{
		{"duplicate field", duplicate},
		{"fractional chain id", fractional},
		{"null enabled", nullEnabled},
		{"trailing value", trailing},
		{"array", "[]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse([]byte(test.raw)); err == nil {
				t.Fatal("accepted invalid encoding")
			}
		})
	}
}

func TestObservationRules(t *testing.T) {
	data, err := os.ReadFile("../fixtures/policy/observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Rules []ObservationRule `json:"rules"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	rules := Observations()
	if !reflect.DeepEqual(rules, file.Rules) {
		t.Fatalf("observation fixture drift: got %#v", rules)
	}
	finalityClaims := 0
	names := map[string]bool{}
	for _, rule := range rules {
		if names[rule.Name] {
			t.Fatalf("duplicate rule %s", rule.Name)
		}
		names[rule.Name] = true
		if !rule.PreservesHistory {
			t.Fatalf("%s drops history", rule.Name)
		}
		if rule.ClaimsFinality {
			finalityClaims++
			if rule.Name != "verified_finalized_inclusion" || rule.AnchorState != AnchorFinalized || rule.ReceiptState != AnchorFinalized || rule.Reason != "" {
				t.Fatalf("finality claim is not the verified inclusion rule: %#v", rule)
			}
		}
		if rule.Reason != "" && rule.Reason != ReasonTransactionFailed && rule.Reason != ReasonReorganized && rule.Reason != ReasonCommitmentAbsent {
			t.Fatalf("reason outside CT09 vocabulary: %s", rule.Reason)
		}
	}
	if finalityClaims != 1 {
		t.Fatalf("finality claims = %d", finalityClaims)
	}
	byName := map[string]ObservationRule{}
	for _, rule := range rules {
		byName[rule.Name] = rule
	}
	if byName["not_submitted_or_outage"].ReceiptState != "" || byName["not_submitted_or_outage"].AnchorState != AnchorUnverified {
		t.Fatal("outage fabricated a receipt or a successful anchor")
	}
	if byName["source_disagreement_or_unverified_deployment"].AnchorState != AnchorUnverified || byName["source_disagreement_or_unverified_deployment"].RetryAllowed {
		t.Fatal("disagreement was treated as a revert or a retry")
	}
	if byName["lost_canonical_inclusion"].AnchorState != AnchorReverted || byName["lost_canonical_inclusion"].ClaimsFinality {
		t.Fatal("reorg kept current finality")
	}
	if byName["digest_conflict"].AnchorState != "" || byName["digest_conflict"].RetryAllowed {
		t.Fatal("digest conflict assigned an anchor or a retry")
	}
	for _, required := range []string{
		"not_submitted_or_outage",
		"unknown_result_or_unfinalized_inclusion",
		"verified_finalized_inclusion",
		"failed_execution",
		"lost_canonical_inclusion",
		"commitment_absent_after_invalidation",
		"source_disagreement_or_unverified_deployment",
		"digest_conflict",
	} {
		if !names[required] {
			t.Fatalf("missing rule %s", required)
		}
	}
}
