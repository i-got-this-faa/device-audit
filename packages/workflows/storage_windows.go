//go:build windows

package workflows

import (
	"context"
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/i-got-this-faa/device-audit/packages/telemetry"
	"golang.org/x/sys/windows"
)

const (
	ioctlStorageQueryProperty     = 0x002d1400
	storageDeviceProperty         = 0
	storageDeviceProtocolProperty = 50
	protocolTypeNVMe              = 3
	nvmeDataTypeLogPage           = 2
	nvmeLogPageHealth             = 0x02
	// STORAGE_PROPERTY_QUERY header plus STORAGE_PROTOCOL_SPECIFIC_DATA.
	propertyQueryHeader = 8
	protocolDataHeader  = 40
)

// platformDiskReader reads storage through IOCTL_STORAGE_QUERY_PROPERTY on a
// handle opened with no access rights. That needs no administrator right and
// cannot read or write disk contents. It never asks for more access on denial.
type platformDiskReader struct{}

func (platformDiskReader) Health(_ context.Context, n int) (StorageHealth, error) {
	if n < 0 || n > MaxStorageDisk {
		return StorageHealth{}, ErrComponentNotFound
	}
	// The path is built from a bounded integer, never from caller text.
	name, err := windows.UTF16PtrFromString(`\\.\PhysicalDrive` + strconv.Itoa(n))
	if err != nil {
		return StorageHealth{}, ErrComponentNotFound
	}
	h, err := windows.CreateFile(name, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return StorageHealth{}, openError(err)
	}
	defer windows.CloseHandle(h)
	query := make([]byte, 12)
	binary.LittleEndian.PutUint32(query, storageDeviceProperty)
	desc, err := deviceIoControl(h, query, 1024)
	// STORAGE_DEVICE_DESCRIPTOR: RemovableMedia at 10, BusType at 28.
	if err != nil {
		return StorageHealth{}, ioctlError(err)
	}
	if len(desc) < 32 {
		return StorageHealth{}, errors.New("workflows: short storage descriptor")
	}
	bus := binary.LittleEndian.Uint32(desc[28:])
	if desc[10] != 0 || ineligibleBus[bus] {
		return StorageHealth{}, ErrComponentNotFound
	}
	health := StorageHealth{BusType: busName(bus)}
	if bus != busNVMe {
		health.MissingReason = telemetry.ReasonNotApplicable
		return health, nil
	}
	log, err := nvmeHealthLog(h)
	switch {
	case errors.Is(err, windows.ERROR_NOT_SUPPORTED), errors.Is(err, windows.ERROR_INVALID_FUNCTION), errors.Is(err, windows.ERROR_INVALID_PARAMETER):
		health.MissingReason = telemetry.ReasonSensorUnavailable
		return health, nil
	case err != nil:
		return StorageHealth{}, ioctlError(err)
	}
	parsed, err := ParseNVMeHealthLog(log)
	if err != nil {
		return StorageHealth{}, err
	}
	health.NVMe = &parsed
	return health, nil
}

// nvmeHealthLog asks the in-box NVMe driver for log page 0x02.
func nvmeHealthLog(h windows.Handle) ([]byte, error) {
	in := make([]byte, propertyQueryHeader+protocolDataHeader+NVMeHealthLogBytes)
	binary.LittleEndian.PutUint32(in[0:], storageDeviceProtocolProperty)
	p := in[propertyQueryHeader:]
	binary.LittleEndian.PutUint32(p[0:], protocolTypeNVMe)
	binary.LittleEndian.PutUint32(p[4:], nvmeDataTypeLogPage)
	binary.LittleEndian.PutUint32(p[8:], nvmeLogPageHealth)
	binary.LittleEndian.PutUint32(p[16:], protocolDataHeader)
	binary.LittleEndian.PutUint32(p[20:], NVMeHealthLogBytes)
	out, err := deviceIoControl(h, in, len(in))
	if err != nil {
		return nil, err
	}
	// STORAGE_PROTOCOL_DATA_DESCRIPTOR: Version, Size, then the protocol data
	// whose DataOffset is relative to its own start.
	if len(out) < propertyQueryHeader+protocolDataHeader {
		return nil, errors.New("workflows: short NVMe protocol descriptor")
	}
	offset := int(binary.LittleEndian.Uint32(out[propertyQueryHeader+16:]))
	length := int(binary.LittleEndian.Uint32(out[propertyQueryHeader+20:]))
	start := propertyQueryHeader + offset
	if length < NVMeHealthLogBytes || offset < protocolDataHeader || start+NVMeHealthLogBytes > len(out) {
		return nil, errors.New("workflows: NVMe log outside the returned buffer")
	}
	return out[start : start+NVMeHealthLogBytes], nil
}

func deviceIoControl(h windows.Handle, in []byte, outSize int) ([]byte, error) {
	out := make([]byte, outSize)
	var n uint32
	if err := windows.DeviceIoControl(h, ioctlStorageQueryProperty, &in[0], uint32(len(in)), &out[0], uint32(len(out)), &n, nil); err != nil {
		return nil, err
	}
	return out[:n], nil
}

func openError(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return ErrComponentNotFound
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return telemetry.ErrPermissionDenied
	default:
		return errors.New("workflows: open storage device failed")
	}
}

func ioctlError(err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return telemetry.ErrPermissionDenied
	}
	return errors.New("workflows: storage query failed")
}
