//go:build !windows

package workflows

import "context"

// platformDiskReader has no storage provider outside Windows, the only
// selected endpoint platform. Every component is reported as not found.
type platformDiskReader struct{}

func (platformDiskReader) Health(context.Context, int) (StorageHealth, error) {
	return StorageHealth{}, ErrComponentNotFound
}
