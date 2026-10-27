// SPDX-License-Identifier: MIT

package forward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

// timeoutErr is a net.Error whose Timeout reports true, standing in for a socket
// i/o deadline that is not context.DeadlineExceeded.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

func TestDialFailureExplainsTheLikelyCause(t *testing.T) {
	const target = "services.example.ts.net:8100"
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"context deadline", context.DeadlineExceeded, "timed out"},
		{"wrapped deadline", fmt.Errorf("dial: %w", context.DeadlineExceeded), "timed out"},
		{"socket timeout", net.Error(timeoutErr{}), "timed out"},
		{"connection refused", errRefused, "refused the connection"},
		{"wrapped refused", fmt.Errorf("dial tcp: %w", errRefused), "refused the connection"},
		{"dns failure", &net.DNSError{Err: "no such host", Name: "services.example.ts.net"}, "could not resolve"},
		{"anything else", errors.New("network is unreachable"), "could not reach"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dialFailure(target, tc.err)
			if got == nil {
				t.Fatal("dialFailure returned nil")
			}
			if !strings.Contains(got.Error(), tc.want) {
				t.Errorf("dialFailure(%v) = %q, want it to contain %q", tc.err, got, tc.want)
			}
			// Every message must name the target so the user knows what to check.
			if !strings.Contains(got.Error(), target) {
				t.Errorf("message %q does not name the target %q", got, target)
			}
		})
	}
}
