// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"encoding/hex"
	"fmt"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
	"tailscale.com/types/key"
)

// defaultLockLogEntries is how far back the authority log is read when the caller does
// not say. Enough to cover the changes around this device being signed, which is what
// anyone reading the log is looking for, without pulling a tailnet's whole history.
const defaultLockLogEntries = 50

// LockStatus is what tailnet lock means for this device, in stdlib types.
//
// The one fact that matters is Signed. On a tailnet with lock enabled a brand-new node
// -- which every app-tail install is -- carries an unsigned node key until an
// administrator signs it, and until then the control plane strips every peer from its
// netmap. The node reports Running, the device list is empty, and nothing anywhere says
// why. This type exists so that state has a name.
type LockStatus struct {
	// Enabled reports lock turned on for the tailnet, which is what decides whether any
	// of this is worth showing at all.
	Enabled bool `json:"enabled"`
	// Signed reports this device's node key authorized. False while Enabled is the
	// cut-off state above.
	Signed bool `json:"signed"`
	// NodeKey is this device's current node key, in the `nodekey:...` form an
	// administrator passes to `tailscale lock sign`. Empty until the node has logged in,
	// since there is no key to sign before then.
	NodeKey string `json:"nodeKey"`
	// LockKey is this device's own tailnet-lock public key, in the `tlpub:...` form. It
	// is the second argument to `tailscale lock sign`, which is what lets this device
	// re-sign itself after a key rotation without an administrator present.
	LockKey string `json:"lockKey"`
	// Trusted is the set of keys the tailnet lets change lock state, in the order the
	// backend reports them.
	Trusted []LockKey `json:"trusted"`
	// CanSign reports this device's own lock key among the trusted ones, which is the
	// only condition under which it may sign another device.
	CanSign bool `json:"canSign"`
	// Visible counts the peers lock let through.
	Visible int `json:"visible"`
	// Filtered is the peers lock removed: devices that exist, that this node can see in
	// the netmap, and that it cannot reach because *they* are unsigned. Without this the
	// state reads as "online but nothing connects".
	Filtered []LockPeer `json:"filtered"`
	// Head identifies the newest entry in the tailnet's key authority log, which is what
	// two devices compare to tell whether they agree about lock state.
	Head string `json:"head"`
}

// LockKey is one key trusted to change tailnet lock.
type LockKey struct {
	// ID is the key's public identity, in the `tlpub:...` form the admin console and the
	// tailscale CLI both print.
	ID string `json:"id"`
	// Kind is what the key is, as the backend names it.
	Kind string `json:"kind"`
	// Votes is how much weight this key carries in a change to the authority.
	Votes int `json:"votes"`
	// Self reports this device holding the key.
	Self bool `json:"self"`
	// Meta is whatever the tailnet recorded against the key. The keys are open-ended, so
	// it is carried whole rather than projected onto fields that would silently drop the
	// rest; `purpose: pre-auth key` is the one an admin sees most.
	Meta map[string]string `json:"meta,omitempty"`
}

// LockPeer is a device tailnet lock removed from this node's netmap.
type LockPeer struct {
	// ID is the peer's stable node ID, which is what survives it re-registering.
	ID string `json:"id"`
	// Name is the peer's DNS name, which is what a person recognises it by.
	Name string `json:"name"`
	// NodeKey is the key an administrator would sign to let this peer back in.
	NodeKey string `json:"nodeKey"`
	// IPs are the peer's tailnet addresses, for a device whose name says little.
	IPs []string `json:"ips"`
}

// LockUpdate is one entry in the tailnet's key authority log.
type LockUpdate struct {
	// Hash identifies the entry; the newest one equals LockStatus.Head.
	Hash string `json:"hash"`
	// Change is what the entry did, in the backend's own vocabulary.
	Change string `json:"change"`
}

// NetworkLock reads what tailnet lock means for this device right now.
//
// It is read on demand rather than watched: lock state changes when an administrator
// acts, not when traffic moves, and a node that is cut off by it stays cut off until
// someone signs it.
func (n *Node) NetworkLock(ctx context.Context) (LockStatus, error) {
	lc := n.client()
	if lc == nil {
		return LockStatus{}, ErrNotRunning
	}
	st, err := lc.NetworkLockStatus(ctx)
	if err != nil {
		return LockStatus{}, fmt.Errorf("read tailnet lock status: %w", err)
	}
	return lockStatusFrom(st), nil
}

// lockStatusFrom projects the backend's value. It is separate from the call so the
// projection -- which is where every one of this type's meanings is decided -- is
// exercised without a running tailnet.
func lockStatusFrom(st *ipnstate.NetworkLockStatus) LockStatus {
	if st == nil {
		// The backend answered with no status at all. Reporting lock disabled is the
		// honest reading: nothing here can be shown, and every field would be a guess.
		return LockStatus{}
	}
	out := LockStatus{
		Enabled: st.Enabled,
		Signed:  st.NodeKeySigned,
		Visible: len(st.VisiblePeers),
	}
	if st.NodeKey != nil {
		out.NodeKey = st.NodeKey.String()
	}
	if !st.PublicKey.IsZero() {
		out.LockKey = st.PublicKey.CLIString()
	}
	if st.Head != nil {
		out.Head = hex.EncodeToString(st.Head[:])
	}
	for _, k := range st.TrustedKeys {
		// Compared against this device's own key rather than a flag, because "may this
		// device sign another" has exactly one answer and it is whether the tailnet
		// trusts the key this device holds.
		self := !st.PublicKey.IsZero() && k.Key.Equal(st.PublicKey)
		out.CanSign = out.CanSign || self
		out.Trusted = append(out.Trusted, LockKey{
			ID:    k.Key.CLIString(),
			Kind:  k.Kind,
			Votes: int(k.Votes),
			Self:  self,
			Meta:  k.Metadata,
		})
	}
	for _, p := range st.FilteredPeers {
		out.Filtered = append(out.Filtered, lockPeerFrom(p))
	}
	return out
}

func lockPeerFrom(p *ipnstate.TKAPeer) LockPeer {
	if p == nil {
		return LockPeer{}
	}
	peer := LockPeer{
		ID:      string(p.StableID),
		Name:    p.Name,
		NodeKey: p.NodeKey.String(),
	}
	for _, ip := range p.TailscaleIPs {
		peer.IPs = append(peer.IPs, ip.String())
	}
	return peer
}

// LockLog reads the newest entries in the tailnet's key authority log, which is the only
// record of who changed lock and when.
func (n *Node) LockLog(ctx context.Context, max int) ([]LockUpdate, error) {
	lc := n.client()
	if lc == nil {
		return nil, ErrNotRunning
	}
	if max <= 0 {
		max = defaultLockLogEntries
	}
	entries, err := lc.NetworkLockLog(ctx, max)
	if err != nil {
		return nil, fmt.Errorf("read the tailnet lock log: %w", err)
	}
	out := make([]LockUpdate, 0, len(entries))
	for _, e := range entries {
		out = append(out, LockUpdate{Hash: hex.EncodeToString(e.Hash[:]), Change: e.Change})
	}
	return out, nil
}

// NodesSignedBy reports the devices that would lose their authorization if the given
// signing key were removed from the tailnet.
//
// It is the question to answer before revoking a key, and it is read-only: nothing here
// removes a key, and the devices are named by node key so an administrator can look them
// up. Returns each device's `nodekey:...`.
func (n *Node) NodesSignedBy(ctx context.Context, lockKey string) ([]string, error) {
	lc := n.client()
	if lc == nil {
		return nil, ErrNotRunning
	}
	var parsed key.NLPublic
	if err := parsed.UnmarshalText([]byte(lockKey)); err != nil {
		return nil, fmt.Errorf("read %q as a tailnet lock key: it must be the tlpub:... text the tailnet reports: %w", lockKey, err)
	}
	sigs, err := lc.NetworkLockAffectedSigs(ctx, parsed.KeyID())
	if err != nil {
		return nil, fmt.Errorf("read the signatures made by %s: %w", lockKey, err)
	}
	out := make([]string, 0, len(sigs))
	for _, raw := range sigs {
		var sig tka.NodeKeySignature
		if err := sig.Unserialize(raw); err != nil {
			return nil, fmt.Errorf("read a signature made by %s: %w", lockKey, err)
		}
		var signed key.NodePublic
		if err := signed.UnmarshalBinary(sig.Pubkey); err != nil {
			return nil, fmt.Errorf("read the device a signature by %s covers: %w", lockKey, err)
		}
		out = append(out, signed.String())
	}
	return out, nil
}

// DisableLockLocally forgets this device's copy of the tailnet lock authority.
//
// It changes nothing for the tailnet and nothing for any other device: it is the
// documented way out of a local key authority that has diverged from the tailnet's, and
// the node rebuilds its copy from the control plane afterwards. It is offered because
// the alternative for a stuck device is deleting the state directory, which also loses
// the node's identity.
func (n *Node) DisableLockLocally(ctx context.Context) error {
	lc := n.client()
	if lc == nil {
		return ErrNotRunning
	}
	if err := lc.NetworkLockForceLocalDisable(ctx); err != nil {
		return fmt.Errorf("forget this device's copy of the tailnet lock state: %w", err)
	}
	return nil
}

// SignNode signs another device's node key with this device's lock key, letting that
// device onto a locked tailnet. It is the `tailscale lock sign` the locked-out device
// tells its user to ask for.
//
// Both keys are taken as the text that device reports, so nothing above this package
// handles a key type. rotationKey is that device's own `tlpub:...`; it is what lets the
// device re-sign itself after a key rotation, and passing it empty signs the node key
// alone.
func (n *Node) SignNode(ctx context.Context, nodeKey, rotationKey string) error {
	lc := n.client()
	if lc == nil {
		return ErrNotRunning
	}
	var signing key.NodePublic
	if err := signing.UnmarshalText([]byte(nodeKey)); err != nil {
		return fmt.Errorf("read %q as a node key: it must be the nodekey:... text the other device reports: %w", nodeKey, err)
	}
	var wrapping []byte
	if rotationKey != "" {
		var rotation key.NLPublic
		if err := rotation.UnmarshalText([]byte(rotationKey)); err != nil {
			return fmt.Errorf("read %q as a tailnet lock key: it must be the tlpub:... text the other device reports: %w", rotationKey, err)
		}
		wrapping = rotation.Verifier()
	}
	if err := lc.NetworkLockSign(ctx, signing, wrapping); err != nil {
		return fmt.Errorf("sign %s for tailnet lock: %w", nodeKey, err)
	}
	return nil
}
