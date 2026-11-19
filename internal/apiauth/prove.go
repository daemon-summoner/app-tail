// SPDX-License-Identifier: MIT

package apiauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
)

// maxProofReplyBytes bounds the answer to the identity check, which is one short string.
const maxProofReplyBytes = 4096

// ErrNotProven reports a listener that answered the identity check without showing it
// holds the token: something other than the agent the token belongs to.
var ErrNotProven = errors.New("the listener did not prove it holds the API token")

// ProveListener challenges the listener at baseURL to show it holds token, for a client to
// call before it sends the token there. The dashboard-address record outlives a crashed
// agent, and whatever binds the port next would otherwise receive the token and every
// request carrying it.
//
// The proof is checked against the address the connection actually reached, which the
// agent signs from its own side of the same socket, so a squatter relaying the challenge
// to the real agent on another port gets back an answer naming that other port.
//
// A listener that fails the check is ErrNotProven. One that could not be reached at all
// comes back as the error client.Do gave, a *url.Error, unwrapped.
func ProveListener(ctx context.Context, client *http.Client, baseURL, token string) error {
	nonce, err := NewNonce()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(map[string]string{"nonce": nonce})
	if err != nil {
		return fmt.Errorf("encode the identity check: %w", err)
	}
	var reached string
	traced := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { reached = info.Conn.RemoteAddr().String() },
	})
	req, err := http.NewRequestWithContext(traced, http.MethodPost, baseURL+"/api/auth/hello", bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("build the identity check: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxProofReplyBytes))
	if err != nil {
		return fmt.Errorf("read the agent's identity check: %w", err)
	}

	var answer struct {
		Proof string `json:"proof"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(payload, &answer) != nil ||
		!VerifyProof(token, nonce, reached, answer.Proof) {
		return ErrNotProven
	}
	return nil
}
