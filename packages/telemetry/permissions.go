package telemetry

import (
	"errors"
	"fmt"
	"slices"
)

// Capability is a narrow read right the collector may require. It is a planning
// label, not a Windows privilege, group membership or ACL that this process holds.
type Capability string

const (
	CapPerfOSProcessor             Capability = "read_perfos_processor"
	CapOSMemory                    Capability = "read_os_memory"
	CapFixedVolumeSpace            Capability = "read_fixed_volume_space"
	CapLocalInterfaceCounters      Capability = "read_local_interface_counters"
	CapBatteryCharge               Capability = "read_battery_charge"
	CapACPIThermal                 Capability = "read_acpi_thermal_zone"
	CapGPUEngine                   Capability = "read_gpu_engine"
	CapExistingNvidiaSMI           Capability = "read_existing_nvidia_smi"
	CapSystemLogMetadata           Capability = "read_system_log_metadata"
	CapApplicationLogMetadata      Capability = "read_application_log_metadata"
	CapSystemLogErrorPresence      Capability = "read_system_log_error_presence"
	CapApplicationLogErrorPresence Capability = "read_application_log_error_presence"
)

// Unrestricted capabilities are rejected. Selecting them would require
// administrator rights, LocalSystem, a broad group, an ACL change or the
// Security log. None of those are part of the steady-state collector.
const (
	CapAdministrator        Capability = "administrator"
	CapLocalSystem          Capability = "local_system"
	CapSeDebug              Capability = "se_debug_privilege"
	CapEventLogReadersGroup Capability = "event_log_readers_group"
	CapWMINamespaceACL      Capability = "wmi_namespace_acl_change"
	CapSecurityLog          Capability = "security_log"
)

// ErrPermissionDenied means the supplied token is missing a required capability.
// Callers keep the source null and continue with later sources.
var ErrPermissionDenied = errors.New("telemetry: permission denied")

// ErrUnrestrictedCapability means a token includes a right this design refuses.
var ErrUnrestrictedCapability = errors.New("telemetry: unrestricted capability is not selected")

// ErrNativeTokenUnattested means no caller has a measured LocalService or
// denied-principal token. Planning profiles cannot be relabeled as attested.
var ErrNativeTokenUnattested = errors.New("telemetry: native service token is not attested")

// SourceSpec is the minimum read set for one collector source.
// Extra grants and unrestricted execution stay false for every selected source.
type SourceSpec struct {
	Source   string       `json:"source"`
	Metric   string       `json:"metric"`
	Unit     string       `json:"unit"`
	Provider string       `json:"provider"`
	Required []Capability `json:"required_capabilities"`
	Nullable bool         `json:"nullable"`
}

// Token is an explicit capability set supplied by the caller. Attested must
// stay false until a native token measurement exists; Validate rejects true.
type Token struct {
	Name         string
	Capabilities []Capability
	Attested     bool
}

// Catalog is the fixed source list shared with the Windows probe. Order is stable.
func Catalog() []SourceSpec {
	return []SourceSpec{
		{Source: "cpu", Metric: "cpu_utilization", Unit: "percent", Required: []Capability{CapPerfOSProcessor},
			Provider: "CIM:root/cimv2:Win32_PerfFormattedData_PerfOS_Processor.PercentProcessorTime(_Total)"},
		{Source: "memory", Metric: "memory_used", Unit: "percent", Required: []Capability{CapOSMemory},
			Provider: "CIM:root/cimv2:Win32_OperatingSystem.TotalVisibleMemorySize,FreePhysicalMemory"},
		{Source: "disk", Metric: "disk_used", Unit: "percent", Required: []Capability{CapFixedVolumeSpace},
			Provider: "CIM:root/cimv2:Win32_LogicalDisk.Size,FreeSpace(DriveType=3)"},
		{Source: "network", Metric: "network_interface_rates", Unit: "bytes_per_second", Required: []Capability{CapLocalInterfaceCounters},
			Provider: ".NET:NetworkInterface.GetIPStatistics:250ms counter delta"},
		{Source: "battery", Metric: "battery_charge", Unit: "percent", Nullable: true, Required: []Capability{CapBatteryCharge},
			Provider: "CIM:root/cimv2:Win32_Battery.EstimatedChargeRemaining"},
		{Source: "thermal", Metric: "acpi_zone_temperature", Unit: "celsius", Nullable: true, Required: []Capability{CapACPIThermal},
			Provider: "CIM:root/wmi:MSAcpi_ThermalZoneTemperature.CurrentTemperature"},
		{Source: "gpu", Metric: "gpu_engine_and_nvidia", Unit: "percent", Nullable: true, Required: []Capability{CapGPUEngine, CapExistingNvidiaSMI},
			Provider: "CIM:root/cimv2:Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine.UtilizationPercentage; NVIDIA:nvidia-smi:utilization.gpu,temperature.gpu"},
		{Source: "events", Metric: "event_log_metadata_and_error_presence", Unit: "boolean", Required: []Capability{CapSystemLogMetadata, CapApplicationLogMetadata, CapSystemLogErrorPresence, CapApplicationLogErrorPresence},
			Provider: "Get-WinEvent:-ListProvider/-ListLog System,Application; bounded Level 1,2 query (metadata/boolean only)"},
	}
}

// PlanningToken is the selected default-privilege attempt set. It is not a
// measured LocalService token. Every catalog source may be attempted; a later
// denial stays permission_denied instead of widening this set.
func PlanningToken() Token {
	var caps []Capability
	seen := map[Capability]bool{}
	for _, spec := range Catalog() {
		for _, cap := range spec.Required {
			if !seen[cap] {
				seen[cap] = true
				caps = append(caps, cap)
			}
		}
	}
	return Token{Name: "planned_local_service_default_unattested", Capabilities: caps}
}

// DeniedToken has none of the catalog capabilities. It models a separately
// provisioned denied principal. It is not itself that principal.
func DeniedToken() Token {
	return Token{Name: "denied_permission_unattested"}
}

// Validate rejects attested tokens, duplicates, unknown names and unrestricted rights.
func (t Token) Validate() error {
	if t.Attested {
		return ErrNativeTokenUnattested
	}
	if t.Name == "" {
		return errors.New("telemetry: token name is required")
	}
	seen := map[Capability]bool{}
	for _, cap := range t.Capabilities {
		if seen[cap] {
			return fmt.Errorf("telemetry: duplicate capability %s", cap)
		}
		seen[cap] = true
		if !knownCapability(cap) {
			return fmt.Errorf("telemetry: unknown capability %s", cap)
		}
		if unrestrictedCapability(cap) {
			return fmt.Errorf("%w: %s", ErrUnrestrictedCapability, cap)
		}
	}
	return nil
}

// Allows reports whether token holds every capability spec requires.
func (t Token) Allows(spec SourceSpec) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if err := spec.validate(); err != nil {
		return err
	}
	have := map[Capability]bool{}
	for _, cap := range t.Capabilities {
		have[cap] = true
	}
	for _, need := range spec.Required {
		if !have[need] {
			return fmt.Errorf("%w: %s requires %s", ErrPermissionDenied, spec.Source, need)
		}
	}
	return nil
}

// AccessComparison is one source under the planned profile and the denied profile.
type AccessComparison struct {
	Source                 string       `json:"source"`
	Metric                 string       `json:"metric"`
	Unit                   string       `json:"unit"`
	Provider               string       `json:"provider"`
	Required               []Capability `json:"required_capabilities"`
	Nullable               bool         `json:"nullable"`
	Planned                string       `json:"planned_service_profile"`
	Denied                 string       `json:"denied_profile"`
	ExtraGrantSelected     bool         `json:"extra_grant_selected"`
	UnrestrictedExecution  bool         `json:"unrestricted_execution"`
	ServiceAccessQualified bool         `json:"service_access_qualified"`
}

// Compare evaluates the catalog under two unattested profiles.
// service_access_qualified is always false.
func Compare(planned, denied Token) ([]AccessComparison, error) {
	if err := planned.Validate(); err != nil {
		return nil, err
	}
	if err := denied.Validate(); err != nil {
		return nil, err
	}
	catalog := Catalog()
	out := make([]AccessComparison, 0, len(catalog))
	for _, spec := range catalog {
		out = append(out, AccessComparison{
			Source:                 spec.Source,
			Metric:                 spec.Metric,
			Unit:                   spec.Unit,
			Provider:               spec.Provider,
			Required:               slices.Clone(spec.Required),
			Nullable:               spec.Nullable,
			Planned:                accessOutcome(planned, spec),
			Denied:                 accessOutcome(denied, spec),
			ExtraGrantSelected:     false,
			UnrestrictedExecution:  false,
			ServiceAccessQualified: QualifiesServiceAccess(planned, denied, 0),
		})
	}
	return out, nil
}

// AttestNativeToken would return a measured LocalService or denied-principal
// token. No implementation can do that from this process, on any OS.
func AttestNativeToken() (Token, error) {
	return Token{}, ErrNativeTokenUnattested
}

// QualifiesServiceAccess reports whether a pair of tokens and a target count
// satisfy TEL04. Native attestation is not implemented, so this is false even
// when a caller sets the arguments that would otherwise be necessary.
func QualifiesServiceAccess(planned, denied Token, physicalTargets int) bool {
	if planned.Attested || denied.Attested || physicalTargets >= 2 {
		return false
	}
	return false
}

func accessOutcome(token Token, spec SourceSpec) string {
	if err := token.Allows(spec); err != nil {
		if errors.Is(err, ErrPermissionDenied) {
			return "permission_denied"
		}
		return "collection_error"
	}
	return "allowed"
}

func (s SourceSpec) validate() error {
	if s.Source == "" || s.Metric == "" || s.Unit == "" || s.Provider == "" || len(s.Required) == 0 {
		return fmt.Errorf("telemetry: source %q is incomplete", s.Source)
	}
	seen := map[Capability]bool{}
	for _, cap := range s.Required {
		if seen[cap] || !knownCapability(cap) || unrestrictedCapability(cap) {
			return fmt.Errorf("telemetry: source %s has invalid capability %s", s.Source, cap)
		}
		seen[cap] = true
	}
	return nil
}

func knownCapability(cap Capability) bool {
	switch cap {
	case CapPerfOSProcessor, CapOSMemory, CapFixedVolumeSpace, CapLocalInterfaceCounters,
		CapBatteryCharge, CapACPIThermal, CapGPUEngine, CapExistingNvidiaSMI,
		CapSystemLogMetadata, CapApplicationLogMetadata, CapSystemLogErrorPresence,
		CapApplicationLogErrorPresence, CapAdministrator, CapLocalSystem, CapSeDebug,
		CapEventLogReadersGroup, CapWMINamespaceACL, CapSecurityLog:
		return true
	default:
		return false
	}
}

func unrestrictedCapability(cap Capability) bool {
	switch cap {
	case CapAdministrator, CapLocalSystem, CapSeDebug, CapEventLogReadersGroup, CapWMINamespaceACL, CapSecurityLog:
		return true
	default:
		return false
	}
}
