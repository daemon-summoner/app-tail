// SPDX-License-Identifier: MIT

//go:build !linux && !darwin

package peeraccount

// skipsCheck is true where every local connection is accepted; see peeraccount_other.go.
const skipsCheck = true
