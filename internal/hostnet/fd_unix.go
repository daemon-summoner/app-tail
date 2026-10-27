// SPDX-License-Identifier: MIT

//go:build unix

package hostnet

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

// A descriptor is passed as ancillary data on a unix socket, which is the one way one
// process can hand another an open file it had no right to open. The message it rides on
// is the ordinary reply; the two arrive together or not at all.

// writeWithFile sends a reply and a descriptor in one message.
//
// The descriptor is attached to a message that carries at least one byte of ordinary
// data, because a control message with no payload can be dropped: the receiver's read
// returns zero bytes and the ancillary data with it, which several implementations treat
// as end-of-file. The reply itself is that payload, so the requirement is met by
// construction rather than by a filler byte.
func writeWithFile(conn *net.UnixConn, resp response, file *os.File) error {
	raw, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("encode the reply: %w", err)
	}
	raw = append(raw, '\n')

	rights := unix.UnixRights(int(file.Fd()))
	n, _, err := conn.WriteMsgUnix(raw, rights, nil)
	if err != nil {
		return fmt.Errorf("send the interface descriptor: %w", err)
	}
	if n != len(raw) {
		return fmt.Errorf("sent %d of %d bytes of the reply, so the descriptor arrived without it", n, len(raw))
	}
	return nil
}

// readWithFile reads a reply that carries a descriptor.
//
// It reads from the socket directly rather than through the buffered reader, because
// ancillary data is attached to a datagram the buffered reader cannot ask for. Anything
// the reader had already buffered is drained first: it would otherwise be the reply, and
// this read would block waiting for one that had already arrived.
func readWithFile(conn net.Conn, r *bufio.Reader) (response, *os.File, error) {
	if r.Buffered() > 0 {
		return response{}, nil, errors.New("the helper sent data before the descriptor, so the two cannot be told apart")
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return response{}, nil, fmt.Errorf("a descriptor cannot be received over a %T", conn)
	}

	buf := make([]byte, maxMessage)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := uc.ReadMsgUnix(buf, oob)
	if err != nil {
		return response{}, nil, fmt.Errorf("read the reply carrying the descriptor: %w", err)
	}
	if n == 0 {
		return response{}, nil, io.ErrUnexpectedEOF
	}

	var resp response
	if err := json.Unmarshal(trimNewline(buf[:n]), &resp); err != nil {
		return response{}, nil, fmt.Errorf("read the reply carrying the descriptor: %w", err)
	}
	// A refusal carries no descriptor, and that is not a failure to receive one.
	if resp.Error != "" {
		return resp, nil, nil
	}

	file, err := fileFromControl(oob[:oobn])
	if err != nil {
		return response{}, nil, err
	}
	return resp, file, nil
}

// fileFromControl takes the single descriptor out of a control message.
//
// Every descriptor past the first is closed rather than leaked. Nothing here sends more
// than one, so a second would mean the peer is not the helper this expects -- and a
// descriptor left open by a process that did not mean to hold it is exactly the kind of
// thing that keeps an interface alive after everything visible has been shut down.
func fileFromControl(oob []byte) (*os.File, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("read the descriptor the helper attached: %w", err)
	}
	var fds []int
	for _, msg := range msgs {
		got, err := unix.ParseUnixRights(&msg)
		if err != nil {
			continue
		}
		fds = append(fds, got...)
	}
	if len(fds) == 0 {
		return nil, errors.New("the helper's reply carried no interface descriptor")
	}
	var extras []error
	for _, extra := range fds[1:] {
		if err := unix.Close(extra); err != nil {
			extras = append(extras, err)
		}
	}
	if len(extras) > 0 {
		// The first goes with them: this process cannot account for what it was sent, and
		// a descriptor held by a process that did not mean to hold it is what keeps an
		// interface alive after everything visible has been shut down.
		extras = append(extras, unix.Close(fds[0]))
		return nil, fmt.Errorf("close the extra descriptors the helper sent: %w", errors.Join(extras...))
	}
	return os.NewFile(uintptr(fds[0]), "app-tail-tun"), nil
}

// deviceFromFile wraps a descriptor the helper opened, taking ownership of it: on success
// the returned device holds it, and on failure it is closed here.
//
// No MTU is applied. The helper set one when it created the interface, and applying one from
// this side is a privileged operation -- not holding those rights is the whole reason the
// helper created it.
func deviceFromFile(file *os.File) (tun.Device, error) {
	dev, err := tun.CreateTUNFromFile(file, 0)
	if err == nil {
		return dev, nil
	}
	// Whether the wrapper closes what it was given when it fails is a per-platform detail, so
	// the close belongs here. One it already closed says so instead of closing a descriptor
	// this process has since reused, which is the reason that answer is not an error.
	if closeErr := file.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
		return nil, errors.Join(err, closeErr)
	}
	return nil, err
}

// HasHelper reports whether this platform runs the privileged side out of process.
func HasHelper() bool { return true }

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
