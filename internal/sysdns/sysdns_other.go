// SPDX-License-Identifier: MIT

//go:build !darwin && !linux && !windows

package sysdns

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
)

// unsupportedReason is what every operation on this platform says. It names what app-tail
// will not do rather than what the platform is, because the answer for the user is to point
// their resolver themselves.
const unsupportedReason = "app-tail does not know how to change this machine's resolver on this operating system. " +
	"Point your resolver at app-tail's listening address by hand, or leave the system-wide DNS switch off."

// DefaultRecordPath keeps the record beside whatever state directory this platform has, so
// the shape of the manager is the same everywhere even where it does nothing.
func DefaultRecordPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return RecordFileName
	}
	return filepath.Join(dir, "app-tail", RecordFileName)
}

func newMachineResolver(func(format string, args ...any)) machineResolver {
	return unsupportedResolver{}
}

// unsupportedResolver refuses every operation with the same sentence. It exists so the
// record-keeping above -- which is where the mistakes that lose someone's settings live --
// compiles and is exercised on every platform, and so a caller here gets a reason instead
// of a build that does not have the feature at all.
type unsupportedResolver struct{}

func (unsupportedResolver) supported() (bool, string) { return false, unsupportedReason }

func (unsupportedResolver) services(context.Context) ([]Service, error) {
	return nil, errors.New(unsupportedReason)
}

func (unsupportedResolver) get(context.Context, Service) ([]netip.Addr, error) {
	return nil, errors.New(unsupportedReason)
}

func (unsupportedResolver) set(context.Context, Service, []netip.Addr) error {
	return errors.New(unsupportedReason)
}

func (unsupportedResolver) base(context.Context, Service) (Base, error) {
	return Base{}, errors.New(unsupportedReason)
}

func (unsupportedResolver) flush(context.Context) error { return errors.New(unsupportedReason) }

func (unsupportedResolver) holdLoopback(context.Context, netip.Addr) error {
	return errors.New(unsupportedReason)
}

func (unsupportedResolver) releaseLoopback(context.Context, netip.Addr) error {
	return errors.New(unsupportedReason)
}
