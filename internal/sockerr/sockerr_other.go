// SPDX-License-Identifier: MIT

//go:build !windows

package sockerr

import (
	"errors"
	"io/fs"
	"syscall"
)

func refused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

func permissionDenied(err error) bool { return errors.Is(err, fs.ErrPermission) }

func addressNotAssigned(err error) bool { return errors.Is(err, syscall.EADDRNOTAVAIL) }
