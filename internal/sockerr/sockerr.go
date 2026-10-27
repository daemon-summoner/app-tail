// SPDX-License-Identifier: MIT

// Package sockerr recognises the socket failures app-tail acts on differently from the rest.
//
// It exists because the POSIX error names Go defines on Windows -- syscall.ECONNREFUSED and
// its neighbours -- are invented values based at APPLICATION_ERROR that no Windows API ever
// returns. Winsock answers with its own numbers, and nothing in the standard library maps
// between the two families, so a plain errors.Is against the POSIX name is a branch that can
// never be taken there. Every predicate here is the same question asked in the terms each
// platform answers in.
package sockerr

// Refused reports a connection the other end actively refused, which is what nothing
// listening on the port looks like.
func Refused(err error) bool { return refused(err) }

// PermissionDenied reports a bind or a connect this process was not allowed to make. It is a
// fact about the rights this process holds -- or about a firewall's opinion of it -- rather
// than about the address, so a caller asking who holds an address learns nothing from it.
func PermissionDenied(err error) bool { return permissionDenied(err) }

// AddressNotAssigned reports a bind to an address this machine does not carry. It is
// arranged rather than reported: the address is added to the loopback interface and the bind
// tried again.
func AddressNotAssigned(err error) bool { return addressNotAssigned(err) }
