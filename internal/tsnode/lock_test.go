// SPDX-License-Identifier: MIT

package tsnode

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

// lockKey mints a distinct tailnet-lock key; only its identity is asserted on.
func lockKey(t *testing.T) key.NLPublic {
	t.Helper()
	return key.NewNLPrivate().Public()
}

// The whole point of reading lock status is the state nothing else explains: lock on,
// this node unsigned, every peer gone. The two facts the card is built from are Enabled
// and Signed, and the two keys are what the administrator's `tailscale lock sign` command
// is assembled from -- without both, the instruction on screen cannot be run.
func TestALockedOutNodeReportsBothKeysTheAdministratorNeeds(t *testing.T) {
	self := lockKey(t)
	nodeKey := key.NewNode().Public()
	st := &ipnstate.NetworkLockStatus{
		Enabled:       true,
		NodeKeySigned: false,
		NodeKey:       &nodeKey,
		PublicKey:     self,
	}

	got := lockStatusFrom(st)

	if !got.Enabled {
		t.Error("lock reports itself off for a tailnet that has it on")
	}
	if got.Signed {
		t.Error("an unsigned node reports itself signed, so nothing would explain its empty peer list")
	}
	if got.NodeKey != nodeKey.String() {
		t.Errorf("NodeKey = %q, want this device's own %q to sign", got.NodeKey, nodeKey)
	}
	if got.LockKey != self.CLIString() {
		t.Errorf("LockKey = %q, want this device's own %q", got.LockKey, self.CLIString())
	}
}

// A node that has not logged in has no node key at all, and the backend sends a nil
// pointer for it. Dereferencing that crashes the poll that reads it; reporting some other
// device's key would be worse, so the field has to be empty and the card has to say the
// device is not enrolled yet rather than print a signing command with a blank key in it.
func TestANodeWithNoKeyYetReportsNoKeyRatherThanCrashing(t *testing.T) {
	got := lockStatusFrom(&ipnstate.NetworkLockStatus{Enabled: true})

	if got.NodeKey != "" {
		t.Errorf("NodeKey = %q for a node that has not logged in, want nothing", got.NodeKey)
	}
	if got.LockKey != "" {
		t.Errorf("LockKey = %q for a node with no lock key, want nothing", got.LockKey)
	}
	if got.Head != "" {
		t.Errorf("Head = %q with no authority head reported, want nothing", got.Head)
	}
}

// Signing another device is offered only where it can succeed. The condition is this
// device's own lock key being one the tailnet trusts -- offering the action anywhere else
// produces a button that always fails, and hiding it on a device that does hold a trusted
// key hides the only way out for every locked-out device on the tailnet.
func TestOnlyADeviceHoldingATrustedKeyReportsItCanSign(t *testing.T) {
	self, other := lockKey(t), lockKey(t)

	// This device's key is listed first and another follows it, so an answer that only
	// remembers the last key examined -- rather than whether any of them matched --
	// reports a signing device as unable to sign.
	trusted := lockStatusFrom(&ipnstate.NetworkLockStatus{
		Enabled:     true,
		PublicKey:   self,
		TrustedKeys: []ipnstate.TKAKey{{Key: self, Votes: 2}, {Key: other, Votes: 1}},
	})
	if !trusted.CanSign {
		t.Error("a device whose own key the tailnet trusts reports it cannot sign")
	}
	if len(trusted.Trusted) != 2 {
		t.Fatalf("%d trusted keys reported, want both", len(trusted.Trusted))
	}
	if !trusted.Trusted[0].Self {
		t.Error("this device's own signing key is not marked as its own, so the list shows no way to sign")
	}
	if trusted.Trusted[0].Votes != 2 {
		t.Errorf("Votes = %d, want the 2 the tailnet recorded", trusted.Trusted[0].Votes)
	}
	if trusted.Trusted[1].Self {
		t.Error("another device's signing key is marked as this device's own")
	}

	untrusted := lockStatusFrom(&ipnstate.NetworkLockStatus{
		Enabled:     true,
		PublicKey:   self,
		TrustedKeys: []ipnstate.TKAKey{{Key: other, Votes: 1}},
	})
	if untrusted.CanSign {
		t.Error("a device the tailnet does not trust reports it can sign; the action would always fail")
	}

	// A device with no lock key of its own must not match a trusted key by both being
	// zero -- that would offer signing on exactly the devices least able to do it.
	noKey := lockStatusFrom(&ipnstate.NetworkLockStatus{
		Enabled:     true,
		TrustedKeys: []ipnstate.TKAKey{{}},
	})
	if noKey.CanSign {
		t.Error("a device with no lock key matched a trusted key by both being empty")
	}
	if noKey.Trusted[0].Self {
		t.Error("an empty trusted key was marked as this device's own")
	}
}

// The metadata keys are open-ended -- `purpose`/`authkey_stableid` today, more later --
// so projecting onto named fields would silently drop whatever the tailnet actually
// recorded. Carrying the map whole is what lets the list say "(pre-auth key ...)" the way
// the admin console does.
func TestWhateverTheTailnetRecordedAgainstAKeyIsCarriedWhole(t *testing.T) {
	meta := map[string]string{"purpose": "pre-auth key", "authkey_stableid": "kSomething"}

	got := lockStatusFrom(&ipnstate.NetworkLockStatus{
		Enabled:     true,
		TrustedKeys: []ipnstate.TKAKey{{Key: lockKey(t), Kind: "25519", Votes: 1, Metadata: meta}},
	})

	if len(got.Trusted) != 1 {
		t.Fatalf("%d keys reported, want 1", len(got.Trusted))
	}
	if got.Trusted[0].Kind != "25519" {
		t.Errorf("Kind = %q, want the backend's own %q", got.Trusted[0].Kind, "25519")
	}
	for k, want := range meta {
		if got.Trusted[0].Meta[k] != want {
			t.Errorf("Meta[%q] = %q, want %q", k, got.Trusted[0].Meta[k], want)
		}
	}
}

// Peers lock removed are the other state nothing explains: they are in the netmap, they
// are online, and every connection to them fails because *they* are unsigned. Each one
// has to arrive with the name a person recognises and the key an administrator signs, or
// the list says only that some unnamed number of devices is unreachable.
func TestPeersLockRemovedArriveNamedAndAddressed(t *testing.T) {
	filtered := key.NewNode().Public()
	got := lockStatusFrom(&ipnstate.NetworkLockStatus{
		Enabled: true,
		VisiblePeers: []*ipnstate.TKAPeer{
			{Name: "alpha", StableID: tailcfg.StableNodeID("nA")},
			{Name: "beta", StableID: tailcfg.StableNodeID("nB")},
		},
		FilteredPeers: []*ipnstate.TKAPeer{{
			Name:         "gamma.tail1234.ts.net",
			StableID:     tailcfg.StableNodeID("nG"),
			NodeKey:      filtered,
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.7"), netip.MustParseAddr("fd7a::7")},
		}},
	})

	if got.Visible != 2 {
		t.Errorf("Visible = %d, want the 2 peers lock let through", got.Visible)
	}
	if len(got.Filtered) != 1 {
		t.Fatalf("%d peers reported as removed by lock, want 1", len(got.Filtered))
	}
	peer := got.Filtered[0]
	if peer.Name != "gamma.tail1234.ts.net" {
		t.Errorf("Name = %q, want the name the device is recognised by", peer.Name)
	}
	if peer.ID != "nG" {
		t.Errorf("ID = %q, want the stable id nG that survives re-registering", peer.ID)
	}
	if peer.NodeKey != filtered.String() {
		t.Errorf("NodeKey = %q, want the %q an administrator would sign", peer.NodeKey, filtered)
	}
	if len(peer.IPs) != 2 || peer.IPs[0] != "100.64.0.7" || peer.IPs[1] != "fd7a::7" {
		t.Errorf("IPs = %v, want both of the device's tailnet addresses", peer.IPs)
	}
}

// The head hash is what two devices compare to tell whether they agree about lock state,
// so it has to be the readable text of the bytes rather than whatever a []byte prints as.
func TestTheAuthorityHeadIsReportedAsReadableText(t *testing.T) {
	var head [32]byte
	head[0], head[31] = 0xab, 0x0f

	got := lockStatusFrom(&ipnstate.NetworkLockStatus{Enabled: true, Head: &head})

	const want = "ab0000000000000000000000000000000000000000000000000000000000000f"
	if got.Head != want {
		t.Errorf("Head = %q, want %q", got.Head, want)
	}
}

// A backend that answered with nothing is the window during a restart. Every field would
// be a guess, and the one that matters most -- lock enabled -- must not default to true,
// or a tailnet without lock at all grows a card telling its user to go and be signed.
func TestNoLockStatusAtAllReportsLockOff(t *testing.T) {
	got := lockStatusFrom(nil)

	if got.Enabled || got.Signed || got.CanSign {
		t.Errorf("a missing status produced enabled=%v signed=%v canSign=%v, want all false",
			got.Enabled, got.Signed, got.CanSign)
	}
	if got.Trusted != nil || got.Filtered != nil {
		t.Errorf("a missing status produced trusted=%v filtered=%v, want nothing", got.Trusted, got.Filtered)
	}
}

// Every lock operation must refuse before the node is up rather than panic on a nil
// client. This is the whole window between the process starting and the backend being
// ready, and the dashboard polls lock status inside it.
func TestEveryLockOperationRefusesWhileTheNodeIsDown(t *testing.T) {
	n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)

	if _, err := n.NetworkLock(t.Context()); !errors.Is(err, ErrNotRunning) {
		t.Errorf("reading lock status while down = %v, want %v", err, ErrNotRunning)
	}
	if _, err := n.LockLog(t.Context(), 10); !errors.Is(err, ErrNotRunning) {
		t.Errorf("reading the lock log while down = %v, want %v", err, ErrNotRunning)
	}
	if _, err := n.NodesSignedBy(t.Context(), "tlpub:00"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("reading affected devices while down = %v, want %v", err, ErrNotRunning)
	}
	if err := n.DisableLockLocally(t.Context()); !errors.Is(err, ErrNotRunning) {
		t.Errorf("forgetting local lock state while down = %v, want %v", err, ErrNotRunning)
	}
	if err := n.SignNode(t.Context(), key.NewNode().Public().String(), ""); !errors.Is(err, ErrNotRunning) {
		t.Errorf("signing a device while down = %v, want %v", err, ErrNotRunning)
	}
}

// A key is pasted in by hand, so the failure that matters is a typo. It has to be named
// as a bad key with the form it should have taken -- an administrator who sees a generic
// backend failure goes looking at the tailnet instead of at what they pasted.
func TestAMistypedKeyIsRefusedByNameBeforeAnythingIsSigned(t *testing.T) {
	// Reaching the backend at all is the failure: a key that cannot be read is refused
	// here, not turned into a request the tailnet has to reject.
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		t.Errorf("a key that could not be read still reached the backend at %s", r.URL.Path)
		return errorResponse(http.StatusBadRequest, "unreachable"), nil
	})

	err := n.SignNode(t.Context(), "not-a-node-key", "")
	if err == nil {
		t.Fatal("a device was signed against a node key that is not one")
	}
	if !strings.Contains(err.Error(), "nodekey:") {
		t.Errorf("error = %v, want it to name the nodekey:... form the key must take", err)
	}

	valid := key.NewNode().Public().String()
	err = n.SignNode(t.Context(), valid, "not-a-lock-key")
	if err == nil {
		t.Fatal("a device was signed against a rotation key that is not one")
	}
	if !strings.Contains(err.Error(), "tlpub:") {
		t.Errorf("error = %v, want it to name the tlpub:... form the rotation key must take", err)
	}

	if _, err := n.NodesSignedBy(t.Context(), "not-a-lock-key"); err == nil {
		t.Error("affected devices were read for a key that is not a key")
	} else if !strings.Contains(err.Error(), "tlpub:") {
		t.Errorf("error = %v, want it to name the tlpub:... form the key must take", err)
	}
}

// The log is the only record of who changed lock and when, so each entry has to arrive
// with a hash a person can compare against the head -- raw bytes render as mojibake -- and
// the change the backend named. A caller that asks for no particular depth still gets
// entries: a limit of zero would fetch an empty log and read as "lock was never changed".
func TestTheLockLogArrivesReadableAndIsNeverFetchedEmpty(t *testing.T) {
	var asked string
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		asked = r.URL.Query().Get("limit")
		return jsonResponse(`[
			{"Hash":[171,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,15],
			 "Change":"add-key"},
			{"Hash":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2],
			 "Change":"checkpoint"}]`), nil
	})

	got, err := n.LockLog(t.Context(), 0)
	if err != nil {
		t.Fatalf("read the lock log: %v", err)
	}
	if asked == "0" || asked == "" {
		t.Errorf("the backend was asked for %q entries, so the log would come back empty", asked)
	}
	if len(got) != 2 {
		t.Fatalf("%d entries reported, want both", len(got))
	}
	if got[0].Change != "add-key" || got[1].Change != "checkpoint" {
		t.Errorf("changes = %q, %q, want the backend's own words", got[0].Change, got[1].Change)
	}
	const wantHash = "ab0000000000000000000000000000000000000000000000000000000000000f"
	if got[0].Hash != wantHash {
		t.Errorf("Hash = %q, want the readable %q", got[0].Hash, wantHash)
	}
}

// Before revoking a signing key an administrator has to know which devices it holds up,
// because every one of them is locked out the moment it goes. Each has to be named by the
// node key that identifies it, not by the opaque signature blob it came wrapped in.
func TestTheDevicesASigningKeyHoldsUpAreNamedByTheirOwnKeys(t *testing.T) {
	signed := key.NewNode().Public()
	raw, err := signed.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal the signed device's key: %v", err)
	}
	sig := tka.NodeKeySignature{Pubkey: raw, SigKind: tka.SigDirect}
	blob, err := json.Marshal([]tkatype.MarshaledSignature{sig.Serialize()})
	if err != nil {
		t.Fatalf("marshal the backend's reply: %v", err)
	}
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return jsonResponse(string(blob)), nil
	})

	got, err := n.NodesSignedBy(t.Context(), lockKey(t).CLIString())
	if err != nil {
		t.Fatalf("read the devices the key holds up: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("%d devices reported, want the 1 the key signed", len(got))
	}
	if got[0] != signed.String() {
		t.Errorf("device = %q, want the %q the signature covers", got[0], signed)
	}
}

// A signature the backend sent that cannot be read is a disagreement about the wire
// format, and the answer would be a list missing devices that are about to be locked out.
// A short list is worse than an error here: it reads as "revoking this key is safe".
func TestASignatureThatCannotBeReadFailsRatherThanShorteningTheList(t *testing.T) {
	blob, err := json.Marshal([]tkatype.MarshaledSignature{[]byte("not a signature")})
	if err != nil {
		t.Fatalf("marshal the backend's reply: %v", err)
	}
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return jsonResponse(string(blob)), nil
	})

	got, err := n.NodesSignedBy(t.Context(), lockKey(t).CLIString())
	if err == nil {
		t.Fatalf("an unreadable signature produced the list %v, want a failure", got)
	}
	if got != nil {
		t.Errorf("a failed read still produced %v, which a caller would render as the whole list", got)
	}
}

// A signature can be well-formed and still name a device key that is not one. The list
// exists to be read before revoking the signing key, so a device that cannot be named has
// to fail the read rather than drop out of it -- an entry silently missing reads as one
// fewer device about to be locked out.
func TestADeviceKeyThatCannotBeReadFailsRatherThanDroppingOutOfTheList(t *testing.T) {
	sig := tka.NodeKeySignature{Pubkey: []byte("not a node key"), SigKind: tka.SigDirect}
	blob, err := json.Marshal([]tkatype.MarshaledSignature{sig.Serialize()})
	if err != nil {
		t.Fatalf("marshal the backend's reply: %v", err)
	}
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return jsonResponse(string(blob)), nil
	})

	got, err := n.NodesSignedBy(t.Context(), lockKey(t).CLIString())
	if err == nil {
		t.Fatalf("a signature naming an unreadable device produced the list %v, want a failure", got)
	}
	if !strings.Contains(err.Error(), "device") {
		t.Errorf("error = %v, want it to say the device a signature covers could not be read", err)
	}
	if got != nil {
		t.Errorf("a failed read still produced %v, which a caller would render as the whole list", got)
	}
}

// The status read is what the whole lock card is built from, and on a locked tailnet it is
// the difference between "this device reaches nothing" being explained and being a mystery.
func TestReadingLockStatusFromTheBackendCarriesTheStateItReported(t *testing.T) {
	self := lockKey(t)
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		st := ipnstate.NetworkLockStatus{
			Enabled:       true,
			NodeKeySigned: false,
			PublicKey:     self,
			TrustedKeys:   []ipnstate.TKAKey{{Key: self, Votes: 1}},
		}
		body, err := json.Marshal(st)
		if err != nil {
			t.Errorf("marshal the lock status: %v", err)
			return errorResponse(http.StatusInternalServerError, "unreachable"), nil
		}
		return jsonResponse(string(body)), nil
	})

	got, err := n.NetworkLock(t.Context())
	if err != nil {
		t.Fatalf("read tailnet lock status: %v", err)
	}
	if !got.Enabled || got.Signed {
		t.Errorf("status = %+v, want lock on and this device unsigned", got)
	}
	if got.LockKey == "" {
		t.Error("the lock key is missing, so the sign command cannot be assembled")
	}
}

// Every one of these is a backend call whose failure has to reach the user as the reason
// the panel is empty. Swallowed, each leaves a card that says lock is off on a tailnet
// where it is on -- which is the one reading of an empty view somebody would act on.
func TestEveryLockCallCarriesTheBackendsOwnRefusal(t *testing.T) {
	signing := key.NewNode().Public().String()
	holder := lockKey(t).CLIString()
	cases := []struct {
		name string
		call func(n *Node) error
		want string
	}{
		{
			name: "reading status",
			call: func(n *Node) error { _, err := n.NetworkLock(t.Context()); return err },
			want: "read tailnet lock status",
		},
		{
			name: "reading the log",
			call: func(n *Node) error { _, err := n.LockLog(t.Context(), 5); return err },
			want: "read the tailnet lock log",
		},
		{
			name: "reading the devices a key holds up",
			call: func(n *Node) error { _, err := n.NodesSignedBy(t.Context(), holder); return err },
			want: "read the signatures made by",
		},
		{
			name: "signing a device",
			call: func(n *Node) error { return n.SignNode(t.Context(), signing, "") },
			want: "sign " + signing + " for tailnet lock",
		},
		{
			name: "forgetting this device's copy",
			call: func(n *Node) error { return n.DisableLockLocally(t.Context()) },
			want: "forget this device's copy of the tailnet lock state",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
				return errorResponse(http.StatusServiceUnavailable, "the key authority is unreachable"), nil
			})

			err := tc.call(n)
			if err == nil {
				t.Fatal("the backend refused and the call reported success")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to say %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "the key authority is unreachable") {
				t.Errorf("error = %v, want it to carry the backend's own reason", err)
			}
		})
	}
}

// Signing is what gets a locked-out device onto the tailnet, so it has to reach the
// backend and be reported as done. The rotation key is what lets that device re-sign
// itself after a key rotation, and dropping it silently leaves it locked out again later.
func TestSigningADeviceSendsItToTheBackendWithTheKeysGiven(t *testing.T) {
	signing := key.NewNode().Public().String()
	rotation := lockKey(t).CLIString()
	var body []byte
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		var err error
		if body, err = io.ReadAll(r.Body); err != nil {
			t.Errorf("read the signing request: %v", err)
		}
		// These two endpoints answer 200 with an empty stanza rather than 204; a stub
		// answering no-content makes an accepted command come back as a refusal.
		return jsonResponse("{}"), nil
	})

	if err := n.SignNode(t.Context(), signing, rotation); err != nil {
		t.Fatalf("sign a device for tailnet lock: %v", err)
	}
	if !strings.Contains(string(body), signing) {
		t.Errorf("the request %q does not carry the device being signed", body)
	}
}

// Forgetting this device's copy is the documented way out of a diverged local authority,
// and a caller that cannot tell it happened has to fall back to deleting the state
// directory -- which also loses the node's identity.
func TestForgettingThisDevicesLockCopyReachesTheBackend(t *testing.T) {
	reached := false
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		reached = true
		return jsonResponse("{}"), nil
	})

	if err := n.DisableLockLocally(t.Context()); err != nil {
		t.Fatalf("forget this device's lock state: %v", err)
	}
	if !reached {
		t.Error("nothing was asked of the backend, so this device's copy is untouched")
	}
}

// A peer the backend did not send is not a peer with an empty name: reading one out of a
// nil would take down the status read that the whole card depends on.
func TestAMissingPeerIsAnEmptyOneRatherThanACrash(t *testing.T) {
	if got := lockPeerFrom(nil); got.ID != "" || got.Name != "" || got.NodeKey != "" {
		t.Errorf("lockPeerFrom(nil) = %+v, want an empty peer", got)
	}
}
