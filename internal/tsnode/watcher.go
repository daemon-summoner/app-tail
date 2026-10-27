// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"net/netip"
	"time"

	"tailscale.com/ipn"
)

// busWatcher is the IPN notification stream. *local.IPNBusWatcher satisfies it;
// tests provide a scripted sequence.
type busWatcher interface {
	Next() (ipn.Notify, error)
	Close() error
}

// watchRetryDelay is how long to wait before re-subscribing after the bus drops.
const watchRetryDelay = 2 * time.Second

// watch keeps a subscription to the IPN bus alive for the node's lifetime,
// re-subscribing when it drops. It is the only writer of the cached status.
func (n *Node) watch(ctx context.Context) {
	defer close(n.watchDone)
	for ctx.Err() == nil {
		w, err := n.openBus(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			n.logger.Warn("tailnet event stream unavailable, retrying", "error", err)
			if !sleepCtx(ctx, watchRetryDelay) {
				return
			}
			continue
		}
		n.consume(ctx, w)
		if err := w.Close(); err != nil {
			// consume has already returned, so the subscription is over either way.
			// This is recorded rather than acted on: the loop's next move is to
			// resubscribe, which is the only recovery there is.
			n.logger.Debug("closing the tailnet event stream failed", "error", err)
		}
		if ctx.Err() != nil {
			return
		}
		// A closed stream means the backend restarted the session; resubscribe
		// after a pause so a persistent failure does not spin.
		if !sleepCtx(ctx, watchRetryDelay) {
			return
		}
	}
}

// consume applies notifications until the stream ends or the context is cancelled.
func (n *Node) consume(ctx context.Context, w busWatcher) {
	for {
		notify, err := w.Next()
		if err != nil {
			if ctx.Err() == nil {
				n.logger.Debug("tailnet event stream ended", "error", err)
			}
			return
		}
		n.applyNotify(ctx, notify)
		if ctx.Err() != nil {
			return
		}
	}
}

// applyNotify folds one bus notification into the cached status.
func (n *Node) applyNotify(ctx context.Context, notify ipn.Notify) {
	changed := false

	n.mu.Lock()
	if notify.InitialStatus != nil {
		next := statusFromBackend(notify.InitialStatus, n.params.Mode)
		// Preserve an auth URL the bus already delivered; the initial status may
		// not carry one yet even though login is pending.
		if next.AuthURL == "" {
			next.AuthURL = n.status.AuthURL
		}
		if !next.sameAs(n.status) {
			n.status = next
			changed = true
		}
		n.setIPsLocked(notify.InitialStatus.TailscaleIPs)
	}
	if notify.State != nil {
		state := backendStateName(*notify.State)
		if state != n.status.BackendState {
			n.status.BackendState = state
			changed = true
		}
		// A fresh login URL is only meaningful while login is pending.
		if state == StateRunning && n.status.AuthURL != "" {
			n.status.AuthURL = ""
			changed = true
		}
	}
	if notify.BrowseToURL != nil && *notify.BrowseToURL != n.status.AuthURL {
		n.status.AuthURL = *notify.BrowseToURL
		changed = true
	}
	if notify.ErrMessage != nil && *notify.ErrMessage != "" && n.status.Problem != *notify.ErrMessage {
		n.status.Problem = *notify.ErrMessage
		changed = true
	}
	if notify.Prefs != nil {
		// The bus is the only place a preference changed outside this process shows
		// up -- another client, a control-plane policy, a profile switch -- so this is
		// what turns a silent divergence into something the agent can act on.
		next := prefsFromIPN(notify.Prefs.AsStruct())
		if !next.Same(n.prefs) || !n.prefsKnown {
			n.prefs, n.prefsKnown = next, true
			changed = true
		}
	}
	n.loginURLs.remember(n.status.AuthURL)
	needsRefresh := changed && (n.status.BackendState == StateRunning || n.status.DNSName == "")
	state := n.status.BackendState
	n.mu.Unlock()

	if !changed {
		return
	}

	// The bus carries state transitions but not the node's own identity, so pull
	// full status once the node is up: this is where tailnet IPs become known,
	// and UDP listeners cannot bind without them.
	if needsRefresh && n.fetchStatus != nil {
		n.refreshIdentity(ctx)
	}
	n.diagnose(state)
	n.signal()
}

// refreshIdentity pulls hostname, DNS name, user and tailnet IPs from the backend.
func (n *Node) refreshIdentity(ctx context.Context) {
	fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := n.fetchStatus(fetchCtx)
	if err != nil {
		n.logger.Debug("could not refresh node identity", "error", err)
		return
	}
	next := statusFromBackend(st, n.params.Mode)

	n.mu.Lock()
	defer n.mu.Unlock()
	n.status.Hostname = next.Hostname
	n.status.DNSName = next.DNSName
	n.status.LoginName = next.LoginName
	n.status.Tags = next.Tags
	if len(next.TailscaleIPs) > 0 {
		n.status.TailscaleIPs = next.TailscaleIPs
	}
	if next.BackendState != "" {
		n.status.BackendState = next.BackendState
	}
	n.setIPsLocked(st.TailscaleIPs)
}

// setIPsLocked caches the node's own addresses. The caller must hold n.mu.
func (n *Node) setIPsLocked(addrs []netip.Addr) {
	for _, a := range addrs {
		if a.Is4() {
			n.ip4 = a
		} else if a.Is6() {
			n.ip6 = a
		}
	}
}

// signal wakes the lifecycle consumer without blocking the bus reader. Signals
// coalesce, so a slow consumer never stalls state tracking.
func (n *Node) signal() {
	select {
	case n.events <- struct{}{}:
	default:
	}
}

// sameAs compares the fields that come from backend status, ignoring locally
// derived ones, so a refresh that changes nothing does not emit an event.
func (s Status) sameAs(other Status) bool {
	if s.BackendState != other.BackendState || s.AuthURL != other.AuthURL ||
		s.Hostname != other.Hostname || s.DNSName != other.DNSName ||
		s.LoginName != other.LoginName || s.MagicDNSSuffix != other.MagicDNSSuffix ||
		s.ExitNodeActive != other.ExitNodeActive ||
		len(s.TailscaleIPs) != len(other.TailscaleIPs) ||
		len(s.Tags) != len(other.Tags) {
		return false
	}
	for i := range s.TailscaleIPs {
		if s.TailscaleIPs[i] != other.TailscaleIPs[i] {
			return false
		}
	}
	for i := range s.Tags {
		if s.Tags[i] != other.Tags[i] {
			return false
		}
	}
	return true
}

// backendStateName renders an ipn.State as the string the API reports.
func backendStateName(s ipn.State) string { return s.String() }

// sleepCtx waits for d, reporting false if the context was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
