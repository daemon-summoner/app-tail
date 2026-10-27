// SPDX-License-Identifier: MIT

package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// A brand-new device on a lock-enabled tailnet is cut off from every peer until an
// administrator signs it. The two keys and the command are the entire remedy, so a view
// that carries the state without them leaves the user with a diagnosis and no cure.
func TestAnUnsignedDeviceIsToldExactlyHowToGetSigned(t *testing.T) {
	h := newHarness(t)

	view := decode[LockView](t, h.do(t, http.MethodGet, "/api/lock", nil))

	if !view.Enabled || view.Signed {
		t.Fatalf("enabled = %v signed = %v, want the locked-out state carried through",
			view.Enabled, view.Signed)
	}
	if view.NodeKey == "" || view.LockKey == "" {
		t.Errorf("nodeKey = %q lockKey = %q, want both keys the administrator has to type",
			view.NodeKey, view.LockKey)
	}
	if !strings.Contains(view.SignCommand, view.NodeKey) {
		t.Errorf("sign command = %q, want it to carry this device's own key", view.SignCommand)
	}
	if view.Capability.Reason == "" {
		t.Error("the view gives no reason, so a Running node with no peers stays unexplained")
	}
}

// Peers the tailnet shows us but lock will not let us talk to are the other half of the
// unexplainable "online but nothing connects". They are named rather than counted because
// the user has to go look at those specific devices.
func TestPeersHeldBackByLockArriveNamed(t *testing.T) {
	h := newHarness(t)

	view := decode[LockView](t, h.do(t, http.MethodGet, "/api/lock", nil))

	if len(view.Filtered) != 1 {
		t.Fatalf("filtered = %+v, want the peer lock is holding back", view.Filtered)
	}
	if view.Filtered[0].Name != "laptop" {
		t.Errorf("filtered peer = %q, want it named", view.Filtered[0].Name)
	}
	if view.Visible != 4 {
		t.Errorf("visible = %d, want the count the netmap carries", view.Visible)
	}
}

// The key authority's history is a round trip per read. The dashboard polls the view
// continuously, so folding the log into it would run that round trip forever.
func TestTheLockLogIsOnlyReadWhenItIsAsked(t *testing.T) {
	h := newHarness(t)

	h.do(t, http.MethodGet, "/api/lock", nil)
	if h.lock.reads != 0 {
		t.Errorf("reading the view read the log %d times, want a view read to fetch nothing",
			h.lock.reads)
	}

	entries := decode[[]LockUpdate](t, h.do(t, http.MethodGet, "/api/lock/log", nil))
	if h.lock.reads != 1 {
		t.Errorf("the log endpoint read %d times, want exactly one", h.lock.reads)
	}
	if len(entries) != 1 || entries[0].Hash != "abcdef" {
		t.Fatalf("log = %+v, want the entry the authority carries", entries)
	}
}

// A tailnet whose lock has never changed still has to answer with a list. `null` makes a
// client that iterates the reply throw rather than render an empty history.
func TestAnEmptyLockLogIsAListRatherThanNull(t *testing.T) {
	h := newHarness(t)
	h.lock.log = nil

	rec := h.do(t, http.MethodGet, "/api/lock/log", nil)
	requireStatus(t, rec, http.StatusOK)

	if body := strings.TrimSpace(rec.Body.String()); body != "[]" {
		t.Errorf("body = %s, want an empty list", body)
	}
}

// A log that could not be read is a failure of the request, not a tailnet whose lock was
// never touched. Reporting the two the same way hides a backend that stopped answering.
func TestALogThatCouldNotBeReadIsReportedAsAFailure(t *testing.T) {
	h := newHarness(t)
	h.lock.logErr = errors.New("the key authority is not answering")

	rec := h.do(t, http.MethodGet, "/api/lock/log", nil)

	if rec.Code < 400 {
		t.Fatalf("GET /api/lock/log = %d for a read that failed, want an error: %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not answering") {
		t.Errorf("the response does not carry the backend's own reason: %s", rec.Body.String())
	}
}

// Signing authorizes another device onto a locked tailnet. Both keys reach the backend
// exactly as sent: trimming is for the whitespace a copy-paste carries, not for the key.
func TestSigningPassesBothKeysThroughUntouched(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/lock/sign", map[string]string{
		"nodeKey":     "  nodekey:beef  ",
		"rotationKey": " nlpub:cafe ",
	})
	requireStatus(t, rec, http.StatusOK)

	if len(h.lock.signed) != 1 {
		t.Fatalf("the backend was asked to sign %d times, want exactly one", len(h.lock.signed))
	}
	if got := h.lock.signed[0]; got[0] != "nodekey:beef" || got[1] != "nlpub:cafe" {
		t.Errorf("signed %q with rotation key %q, want both trimmed and otherwise whole",
			got[0], got[1])
	}
	// The reply is the state after the signature, so a dashboard renders the result
	// rather than the state it just replaced.
	if view := decode[LockView](t, rec); !view.Signed {
		t.Error("the reply still reports the device as unsigned")
	}
}

// A signature with no device to sign is a typo, and it must be refused before the backend
// is asked -- an empty key there produces a parse error naming nothing the user typed.
func TestSigningWithNoDeviceKeyIsRefusedBeforeTheBackendIsAsked(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/lock/sign", map[string]string{"nodeKey": "   "})

	requireStatus(t, rec, http.StatusBadRequest)
	if len(h.lock.signed) != 0 {
		t.Error("the backend was asked to sign with no device key")
	}
	if body := decode[errorBody](t, rec); !strings.Contains(body.Error, "nodeKey") {
		t.Errorf("refusal = %q, want it to name the missing field", body.Error)
	}
}

// The rotation key is what lets a device re-sign itself after a key rotation without an
// administrator present. It is genuinely optional, so requiring it would make the common
// one-key case impossible.
func TestSigningWithoutARotationKeyIsAccepted(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/lock/sign", map[string]string{"nodeKey": "nodekey:beef"})
	requireStatus(t, rec, http.StatusOK)

	if len(h.lock.signed) != 1 || h.lock.signed[0][1] != "" {
		t.Errorf("signed = %+v, want the one key that was sent", h.lock.signed)
	}
}

// A backend that refuses the signature -- a key this device is not trusted to sign with,
// a malformed key -- must surface its own sentence. Reporting success would leave the
// other device cut off with nothing saying why.
func TestASignatureTheBackendRefusesIsReportedAsAFailure(t *testing.T) {
	h := newHarness(t)
	h.lock.signErr = errors.New("this node is not trusted to sign")

	rec := h.do(t, http.MethodPost, "/api/lock/sign", map[string]string{"nodeKey": "nodekey:beef"})

	if rec.Code < 400 {
		t.Fatalf("POST /api/lock/sign = %d for a refused signature, want an error: %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not trusted to sign") {
		t.Errorf("the response does not carry the backend's own reason: %s", rec.Body.String())
	}
}

// Forgetting local lock state is destructive enough to need intent on the wire. A client
// is free to skip its own dialog, so the confirmation has to live at the layer that
// cannot be bypassed.
func TestForgettingLocalLockStateNeedsTheTypedConfirmation(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/lock/disable-local", map[string]string{"confirm": "yes"})

	requireStatus(t, rec, http.StatusBadRequest)
	if h.lock.disabled != 0 {
		t.Error("the backend forgot the lock state without the confirmation")
	}
	body := decode[errorBody](t, rec)
	if !strings.Contains(body.Error, disableLocalWord) {
		t.Errorf("refusal = %q, want it to name the word that confirms", body.Error)
	}
	// The refusal is also where the blast radius is stated: a user reading "disable" has
	// every reason to think this turns their tailnet's lock off.
	if !strings.Contains(body.Error, "no other device") {
		t.Errorf("refusal = %q, want it to say the rest of the tailnet is untouched", body.Error)
	}
}

func TestForgettingLocalLockStateWithTheConfirmationRuns(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/lock/disable-local",
		map[string]string{"confirm": disableLocalWord})
	requireStatus(t, rec, http.StatusOK)

	if h.lock.disabled != 1 {
		t.Fatalf("the backend was asked %d times, want exactly one", h.lock.disabled)
	}
	if view := decode[LockView](t, rec); view.Enabled {
		t.Error("the reply reports lock state this device has just forgotten")
	}
}

// A backend that could not forget the state must say so. Answering 200 would leave a
// device whose copy has diverged still diverged, with the UI claiming it was reset.
func TestAForgetTheBackendRefusesIsReportedAsAFailure(t *testing.T) {
	h := newHarness(t)
	h.lock.disableErr = errors.New("the state file is read-only")

	rec := h.do(t, http.MethodPost, "/api/lock/disable-local",
		map[string]string{"confirm": disableLocalWord})

	if rec.Code < 400 {
		t.Fatalf("POST /api/lock/disable-local = %d for a refused reset, want an error: %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "read-only") {
		t.Errorf("the response does not carry the backend's own reason: %s", rec.Body.String())
	}
}

// Both of these change tailnet-wide or device-wide state, so a body that could not be
// read has to stop before the backend rather than fall through to a zero-valued request:
// a zero sign request reaches the key check, but a zero confirmation is a word that never
// matches -- and the day that check moves, an unreadable body would forget the lock state.
func TestALockRequestThatCouldNotBeReadNeverReachesTheBackend(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
	}{
		{"authorizing a device, truncated json", "/api/lock/sign", `{"nodeKey":`},
		{"authorizing a device, not an object", "/api/lock/sign", `["nodekey:beef"]`},
		{"forgetting local state, truncated json", "/api/lock/disable-local", `{"confirm":`},
		{"forgetting local state, unknown field", "/api/lock/disable-local", `{"noSuchField":"x"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			rec := h.doRaw(t, http.MethodPost, tc.path, tc.body)

			requireStatus(t, rec, http.StatusBadRequest)
			if body := decode[errorBody](t, rec); !strings.Contains(body.Error, "JSON") {
				t.Errorf("error = %q, want it to say the body could not be parsed", body.Error)
			}
			if len(h.lock.signed) != 0 {
				t.Errorf("an unreadable body still signed %v", h.lock.signed)
			}
			if h.lock.disabled != 0 {
				t.Error("an unreadable body still forgot this device's lock state")
			}
		})
	}
}
