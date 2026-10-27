// SPDX-License-Identifier: MIT

// Package udpsock carries the adjustments a UDP listener needs before a read loop on it is
// safe, where a platform's datagram sockets do not already behave that way.
package udpsock
