// SPDX-License-Identifier: MIT

// Package fileowntest arranges and checks file ownership for tests, on each platform in the
// terms that platform uses.
//
// Mode bits say who may reach a file everywhere but Windows, where the answer is the file's
// access list and the bits are inert: a chmod refuses nothing there, and a file created with
// 0600 is readable by whoever can read its directory. A test about "only this account" or
// "nothing may write here" therefore needs a different arrangement per platform, and this
// package holds both so the test itself reads the same on each.
package fileowntest
