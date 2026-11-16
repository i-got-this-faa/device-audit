// Package policy checks the CHAIN01 release-chain descriptor.
// Validation is a local configuration check. It does not connect to a signer,
// RPC endpoint, or chain, and it never establishes deployment or finality.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"
)

const (
	// PolicyVersion is the reviewed CHAIN01 descriptor version.
	PolicyVersion = "device-audit.chain-policy.v1"
	// MainnetAdapterID is the disabled Base Mainnet release adapter.
	MainnetAdapterID = "base-mainnet-registry-v1"
	// SepoliaAdapterID is the Base Sepolia integration adapter.
	SepoliaAdapterID = "base-sepolia-registry-v1"
	// LocalAdapterID is the local EVM test adapter.
	LocalAdapterID = "local-evm-registry-v1"

	// MainnetChainID is Base Mainnet. Local and testnet descriptors cannot use it.
	MainnetChainID uint64 = 8453
	// SepoliaChainID is Base Sepolia.
	SepoliaChainID uint64 = 84532
	// EthereumMainnetChainID is rejected for every adapter in this policy.
	EthereumMainnetChainID uint64 = 1

	// FinalityRule is the only accepted finality algorithm name.
	FinalityRule = "verified-canonical-l2-at-or-below-l1-derived-finalized-head"

	// MaxTransactionFeeWei is 0.0001 ETH, the selected per-transaction ceiling.
	MaxTransactionFeeWei = "100000000000000"
	// MaxDailyFeeWei is 0.001 ETH, the selected rolling 24-hour ceiling.
	MaxDailyFeeWei = "1000000000000000"

	// AdministratorThreshold is the selected multisig threshold.
	AdministratorThreshold = 2
	// AdministratorOwners is the selected multisig owner count.
	AdministratorOwners = 3

	// EvidenceSelectedRelease is the selected release network, not a deployment.
	EvidenceSelectedRelease = "selected-release-network"
	// EvidenceIntegrationTestnet is Base Sepolia integration configuration.
	EvidenceIntegrationTestnet = "integration-testnet"
	// EvidenceLocalTest is a local EVM fixture configuration.
	EvidenceLocalTest = "local-test"
)

var (
	addressPattern   = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	hashPattern      = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
	weiPattern       = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`)
	integerPattern   = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	referencePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	secretPattern    = regexp.MustCompile(`(?i)(private[-_]?key|api[-_]?key|secret|password|credential)`)
	identityPattern  = regexp.MustCompile(`(?i)(ed25519|x25519|oidc|mesh|psk)`)
)

var descriptorFields = []string{
	"policy_version",
	"adapter_id",
	"environment",
	"chain_id",
	"enabled",
	"contract_address",
	"runtime_code_keccak256",
	"deployment_transaction_hash",
	"deployment_block_hash",
	"administrator_multisig",
	"administrator_threshold",
	"administrator_owner_count",
	"writer_address",
	"signer_service_reference",
	"trusted_verifier_reference",
	"independent_rpc_reference",
	"finality",
	"max_total_fee_wei",
	"rolling_24h_fee_budget_wei",
}

// Descriptor is the reviewed chain-policy configuration template.
// Nil deployment fields are absent. A populated field is still not chain evidence.
type Descriptor struct {
	PolicyVersion             string  `json:"policy_version"`
	AdapterID                 string  `json:"adapter_id"`
	Environment               string  `json:"environment"`
	ChainID                   uint64  `json:"chain_id"`
	Enabled                   bool    `json:"enabled"`
	ContractAddress           *string `json:"contract_address"`
	RuntimeCodeKeccak256      *string `json:"runtime_code_keccak256"`
	DeploymentTransactionHash *string `json:"deployment_transaction_hash"`
	DeploymentBlockHash       *string `json:"deployment_block_hash"`
	AdministratorMultisig     *string `json:"administrator_multisig"`
	AdministratorThreshold    uint32  `json:"administrator_threshold"`
	AdministratorOwnerCount   uint32  `json:"administrator_owner_count"`
	WriterAddress             *string `json:"writer_address"`
	SignerServiceReference    *string `json:"signer_service_reference"`
	TrustedVerifierReference  *string `json:"trusted_verifier_reference"`
	IndependentRPCReference   *string `json:"independent_rpc_reference"`
	Finality                  string  `json:"finality"`
	MaxTotalFeeWei            string  `json:"max_total_fee_wei"`
	Rolling24hFeeBudgetWei    string  `json:"rolling_24h_fee_budget_wei"`
}

// Parse decodes one descriptor and applies the release policy rules.
func Parse(data []byte) (Descriptor, error) {
	fields, err := decodeObject(data)
	if err != nil {
		return Descriptor{}, err
	}
	if len(fields) != len(descriptorFields) {
		return Descriptor{}, fmt.Errorf("descriptor field set mismatch")
	}
	for _, name := range descriptorFields {
		if _, ok := fields[name]; !ok {
			return Descriptor{}, fmt.Errorf("missing field %s", name)
		}
	}
	if !integerPattern.Match(bytes.TrimSpace(fields["chain_id"])) {
		return Descriptor{}, fmt.Errorf("chain_id must be a canonical integer")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var descriptor Descriptor
	if err := decoder.Decode(&descriptor); err != nil {
		return Descriptor{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Descriptor{}, fmt.Errorf("trailing JSON")
	}
	if err := descriptor.Validate(); err != nil {
		return Descriptor{}, err
	}
	return descriptor, nil
}

// Validate checks a decoded descriptor. It does not contact a network.
func (d Descriptor) Validate() error {
	if d.PolicyVersion != PolicyVersion {
		return fmt.Errorf("unsupported policy version")
	}
	if d.Finality != FinalityRule {
		return fmt.Errorf("finality policy must be the L1-derived finalized-head rule")
	}
	if d.AdministratorThreshold != AdministratorThreshold || d.AdministratorOwnerCount != AdministratorOwners {
		return fmt.Errorf("administrator must be 2-of-3")
	}
	if err := d.validateNetwork(); err != nil {
		return err
	}
	maxFee, err := parseWei(d.MaxTotalFeeWei)
	if err != nil {
		return fmt.Errorf("max_total_fee_wei: %w", err)
	}
	dailyFee, err := parseWei(d.Rolling24hFeeBudgetWei)
	if err != nil {
		return fmt.Errorf("rolling_24h_fee_budget_wei: %w", err)
	}
	txCeiling, _ := parseWei(MaxTransactionFeeWei)
	dailyCeiling, _ := parseWei(MaxDailyFeeWei)
	if maxFee.Cmp(txCeiling) > 0 || dailyFee.Cmp(dailyCeiling) > 0 || maxFee.Cmp(dailyFee) > 0 {
		return fmt.Errorf("fee ceiling exceeds the selected policy or the daily budget")
	}
	if d.Enabled {
		return d.validateEnabled()
	}
	return d.validateDisabled()
}

func (d Descriptor) validateNetwork() error {
	switch d.Environment {
	case "mainnet":
		if d.AdapterID != MainnetAdapterID || d.ChainID != MainnetChainID {
			return fmt.Errorf("mainnet descriptor must bind Base Mainnet")
		}
	case "testnet":
		if d.AdapterID != SepoliaAdapterID || d.ChainID != SepoliaChainID {
			return fmt.Errorf("testnet descriptor must bind Base Sepolia")
		}
	case "local":
		if d.AdapterID != LocalAdapterID {
			return fmt.Errorf("local descriptor must use the local adapter")
		}
		if d.ChainID == 0 || d.ChainID == EthereumMainnetChainID || d.ChainID == MainnetChainID || d.ChainID == SepoliaChainID {
			return fmt.Errorf("local chain id cannot impersonate a public chain")
		}
	default:
		return fmt.Errorf("unknown environment")
	}
	return nil
}

func (d Descriptor) validateDisabled() error {
	absent := []struct {
		name  string
		value *string
	}{
		{"contract_address", d.ContractAddress},
		{"runtime_code_keccak256", d.RuntimeCodeKeccak256},
		{"deployment_transaction_hash", d.DeploymentTransactionHash},
		{"deployment_block_hash", d.DeploymentBlockHash},
		{"administrator_multisig", d.AdministratorMultisig},
		{"writer_address", d.WriterAddress},
		{"signer_service_reference", d.SignerServiceReference},
		{"trusted_verifier_reference", d.TrustedVerifierReference},
		{"independent_rpc_reference", d.IndependentRPCReference},
	}
	for _, field := range absent {
		if field.value != nil {
			return fmt.Errorf("disabled descriptor must leave %s absent", field.name)
		}
	}
	return nil
}

func (d Descriptor) validateEnabled() error {
	contract, err := requiredAddress("contract_address", d.ContractAddress)
	if err != nil {
		return err
	}
	admin, err := requiredAddress("administrator_multisig", d.AdministratorMultisig)
	if err != nil {
		return err
	}
	writer, err := requiredAddress("writer_address", d.WriterAddress)
	if err != nil {
		return err
	}
	if _, err := requiredHash("runtime_code_keccak256", d.RuntimeCodeKeccak256); err != nil {
		return err
	}
	if _, err := requiredHash("deployment_transaction_hash", d.DeploymentTransactionHash); err != nil {
		return err
	}
	if _, err := requiredHash("deployment_block_hash", d.DeploymentBlockHash); err != nil {
		return err
	}
	if writer == admin || writer == contract || admin == contract {
		return fmt.Errorf("writer, administrator, and registry addresses must be distinct")
	}
	signer, err := requiredReference("signer_service_reference", d.SignerServiceReference, "signer:")
	if err != nil {
		return err
	}
	verifier, err := requiredReference("trusted_verifier_reference", d.TrustedVerifierReference, "verifier:")
	if err != nil {
		return err
	}
	rpc, err := requiredReference("independent_rpc_reference", d.IndependentRPCReference, "rpc:")
	if err != nil {
		return err
	}
	if signer == verifier || signer == rpc || verifier == rpc {
		return fmt.Errorf("signer, verifier, and RPC references must be distinct")
	}
	return nil
}

func requiredAddress(name string, value *string) (string, error) {
	if value == nil {
		return "", fmt.Errorf("enabled descriptor requires %s", name)
	}
	if !addressPattern.MatchString(*value) || zeroHex(*value) {
		return "", fmt.Errorf("invalid address %s", name)
	}
	return *value, nil
}

func requiredHash(name string, value *string) (string, error) {
	if value == nil {
		return "", fmt.Errorf("enabled descriptor requires %s", name)
	}
	if !hashPattern.MatchString(*value) || zeroHex(*value) {
		return "", fmt.Errorf("invalid hash %s", name)
	}
	return *value, nil
}

func requiredReference(name string, value *string, prefix string) (string, error) {
	if value == nil {
		return "", fmt.Errorf("enabled descriptor requires %s", name)
	}
	reference := *value
	if !strings.HasPrefix(reference, prefix) || !referencePattern.MatchString(reference) || secretPattern.MatchString(reference) || identityPattern.MatchString(reference) {
		return "", fmt.Errorf("invalid configuration reference %s", name)
	}
	return reference, nil
}

func zeroHex(value string) bool {
	for _, char := range value {
		if char != '0' && char != 'x' {
			return false
		}
	}
	return true
}

func parseWei(value string) (*big.Int, error) {
	if !weiPattern.MatchString(value) {
		return nil, fmt.Errorf("invalid wei amount")
	}
	amount := new(big.Int)
	if _, ok := amount.SetString(value, 10); !ok {
		return nil, fmt.Errorf("invalid wei amount")
	}
	return amount, nil
}

// EvidenceClass separates the selected release network from testnet and local
// fixtures. The class is a configuration label, not deployment evidence.
func (d Descriptor) EvidenceClass() (string, error) {
	if err := d.Validate(); err != nil {
		return "", err
	}
	switch d.Environment {
	case "mainnet":
		return EvidenceSelectedRelease, nil
	case "testnet":
		return EvidenceIntegrationTestnet, nil
	case "local":
		return EvidenceLocalTest, nil
	default:
		return "", fmt.Errorf("unknown environment")
	}
}

// ReleaseDeploymentObserved reports whether validation observed a live deployment.
// It is always false: this package performs no chain, signer, or RPC call.
func (d Descriptor) ReleaseDeploymentObserved() bool {
	return false
}

func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return nil, fmt.Errorf("descriptor must be a JSON object")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("descriptor field name must be a string")
		}
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("duplicate JSON field %s", key)
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, err
		}
		fields[key] = raw
	}
	end, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if end != json.Delim('}') {
		return nil, fmt.Errorf("descriptor must be a JSON object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	return fields, nil
}
