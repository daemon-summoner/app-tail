// SPDX-License-Identifier: MIT

package hostnet

import (
	"bufio"
	"net"
	"os"

	"github.com/tailscale/wireguard-go/tun"
)

// Windows has no helper, so nothing here is ever reached. It exists because the client
// and the socket path are one package with the rest, and a build that excluded them would
// have to fork the Host interface as well.
//
// The reason there is no helper is not the transport: it is that the wintun adapter's
// handle is not exposed by the Go binding in a form another process could take over, so a
// helper would have to host the entire engine rather than hand back one descriptor. The
// process elevates itself instead, which on Windows keeps the same user and the same
// %APPDATA% and so costs far less than it would on macOS.

func writeWithFile(*net.UnixConn, response, *os.File) error {
	return errNoHelperOnThisPlatform
}

func readWithFile(net.Conn, *bufio.Reader) (response, *os.File, error) {
	return response{}, nil, errNoHelperOnThisPlatform
}

// SocketPath is where the helper listens. There is none, and the empty string is what
// turns a dial into ErrUnsupported rather than a connection refused on a made-up path.
func SocketPath() string { return "" }

// peerIsOwner reports whether the process at the other end of a connection may command
// this one. With no helper there is no connection to check.
func peerIsOwner(net.Conn) (bool, error) { return false, errNoHelperOnThisPlatform }

// ListenHelper opens the helper's socket. There is no helper to open one for.
func ListenHelper(string) (*net.UnixListener, error) { return nil, errNoHelperOnThisPlatform }

// deviceFromFile turns a descriptor received from the helper into an interface. A wintun
// adapter is a driver handle rather than a descriptor and cannot be reconstructed this
// way, which is the concrete reason Windows elevates instead of delegating.
func deviceFromFile(*os.File) (tun.Device, error) { return nil, errNoHelperOnThisPlatform }

// HasHelper reports whether this platform runs the privileged side out of process.
func HasHelper() bool { return false }
