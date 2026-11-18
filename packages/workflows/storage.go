package workflows

import (
	"encoding/binary"
	"errors"
)

// NVMeHealthLogBytes is the size of the NVMe SMART / health information log.
const NVMeHealthLogBytes = 512

// Bus types from STORAGE_BUS_TYPE. Unlisted values are reported as "other".
var busTypes = map[uint32]string{
	1: "scsi", 2: "atapi", 3: "ata", 7: "usb", 8: "raid", 10: "sas", 11: "sata",
	12: "sd", 13: "mmc", 14: "virtual", 15: "file_backed_virtual", 16: "spaces", 17: "nvme", 18: "scm", 19: "ufs",
}

// Bus types that are removable, virtual or file-backed are not eligible
// storage components even when their media reports itself as fixed.
var ineligibleBus = map[uint32]bool{7: true, 12: true, 13: true, 14: true, 15: true}

const busNVMe = 17

func busName(bus uint32) string {
	if name, ok := busTypes[bus]; ok {
		return name
	}
	return "other"
}

// ParseNVMeHealthLog decodes the fields NVMeHealth keeps from one 512-byte log
// page. A 128-bit counter whose high half is set is rejected, not truncated.
func ParseNVMeHealthLog(log []byte) (NVMeHealth, error) {
	if len(log) != NVMeHealthLogBytes {
		return NVMeHealth{}, errors.New("workflows: NVMe health log has the wrong size")
	}
	counter := func(at int) (uint64, error) {
		if binary.LittleEndian.Uint64(log[at+8:]) != 0 {
			return 0, errors.New("workflows: NVMe counter exceeds 64 bits")
		}
		return binary.LittleEndian.Uint64(log[at:]), nil
	}
	h := NVMeHealth{
		CriticalWarningFlags:    log[0],
		AvailableSparePercent:   log[3],
		SpareThresholdPercent:   log[4],
		PercentageUsed:          log[5],
		WarningTemperatureMins:  binary.LittleEndian.Uint32(log[192:]),
		CriticalTemperatureMins: binary.LittleEndian.Uint32(log[196:]),
	}
	// Composite temperature is in kelvin; zero means the drive reports none.
	if kelvin := binary.LittleEndian.Uint16(log[1:]); kelvin != 0 {
		celsius := int(kelvin) - 273
		h.TemperatureCelsius = &celsius
	}
	var err error
	for _, f := range []struct {
		at  int
		dst *uint64
	}{{128, &h.PowerOnHours}, {144, &h.UnsafeShutdowns}, {160, &h.MediaErrors}, {176, &h.ErrorLogEntries}} {
		if *f.dst, err = counter(f.at); err != nil {
			return NVMeHealth{}, err
		}
	}
	return h, nil
}
