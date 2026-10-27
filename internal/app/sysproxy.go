// SPDX-License-Identifier: MIT

package app

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/sysproxy"
	"github.com/sellitus/app-tail/internal/tsproxy"
)

// systemProxyState remembers the outcome of the last reconcile, so the dashboard reports
// what happened rather than what should have happened.
//
// The reconcile runs on the lifecycle goroutine and the API reads from request
// goroutines, which is what this guards.
type systemProxyState struct {
	mu      sync.RWMutex
	applied bool
	reason  string
}

func (s *systemProxyState) publish(applied bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied, s.reason = applied, reason
}

func (s *systemProxyState) snapshot() (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.applied, s.reason
}

// applySystemProxy points this machine at the proxy, or puts back what it pointed at
// before, according to the setting and to whether the proxy can actually serve it.
//
// It runs on every reconcile rather than only on a change, because the value it manages
// lives outside this process: another program, another profile or a restore from backup
// can move it at any time, and a switch that is on has to mean the setting is on now.
func (a *Agent) applySystemProxy(st tsproxy.Status) {
	manager := a.currentSystemProxy()
	if manager == nil {
		return
	}

	wanted, reason := a.systemProxyTarget(st)
	if wanted == "" {
		// Includes the ordinary case of the module being off, where there is nothing
		// to put back and Clear does nothing.
		if err := manager.Clear(); err != nil {
			a.logger.Warn("restoring this machine's proxy configuration failed", "error", err)
			a.systemProxy.publish(false, fmt.Sprintf("this machine's proxy configuration could not be restored: %v", err))
			return
		}
		a.systemProxy.publish(false, reason)
		return
	}

	if err := manager.Apply(wanted); err != nil {
		a.logger.Warn("pointing this machine at the proxy failed", "error", err)
		a.systemProxy.publish(false, err.Error())
		return
	}
	a.systemProxy.publish(true, "")
}

// systemProxyTarget is the auto-config URL this machine should point at, or empty with
// the reason it should point at nothing.
func (a *Agent) systemProxyTarget(st tsproxy.Status) (string, string) {
	if !a.settings().ProxySystem {
		return "", "the setting is switched off"
	}
	if !st.Enabled {
		return "", "the proxy module is switched off, so there is nothing to point this machine at"
	}
	if st.Listening == "" {
		reason := st.Error
		if reason == "" {
			reason = "the proxy is not listening, so there is nothing to point this machine at"
		}
		return "", reason
	}
	if st.RequiresToken {
		// The script this would install returns DIRECT for everything, because a PAC
		// result line has nowhere to put a credential. Writing the machine's setting to
		// achieve nothing is worse than leaving it alone and saying why.
		return "", "the proxy requires a password, so the auto-config script sends everything direct; " +
			"pointing this machine at it would change nothing"
	}
	pacURL := tsproxy.PACURL(a.dashboardHostPort())
	if pacURL == "" {
		return "", "the dashboard is not listening yet, so the auto-config script has no address"
	}
	return pacURL, ""
}

func (a *Agent) currentSystemProxy() SystemProxy {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.sysproxy
}

// sysProxyAPI is the management API's view of this machine's proxy configuration.
type sysProxyAPI struct{ a *Agent }

var _ httpapi.SystemProxy = sysProxyAPI{}

// SystemProxyAPI reports the machine-proxy surface, or nil when this agent has none.
func (a *Agent) SystemProxyAPI() httpapi.SystemProxy {
	if a.currentSystemProxy() == nil {
		// A typed nil inside a non-nil interface would defeat the caller's nil check.
		return nil
	}
	return sysProxyAPI{a: a}
}

func (s sysProxyAPI) View() httpapi.SystemProxyView {
	manager := s.a.currentSystemProxy()
	if manager == nil {
		return httpapi.SystemProxyView{Platform: runtime.GOOS}
	}

	// An unbound proxy leaves this empty, which is what makes the manual commands empty
	// rather than naming an address that answers nothing.
	var pacURL string
	if s.a.defaultProxyStatus().Listening != "" {
		pacURL = tsproxy.PACURL(s.a.dashboardHostPort())
	}

	state := manager.State(pacURL)
	applied, reason := s.a.systemProxy.snapshot()
	if reason == "" {
		reason = state.Reason
	}

	view := httpapi.SystemProxyView{
		Enabled:       s.a.settings().ProxySystem,
		Platform:      runtime.GOOS,
		Supported:     state.Supported,
		Applied:       applied,
		AutoConfigURL: state.AutoConfigURL,
		Managed:       state.Managed,
		Manual:        state.Manual,
		Capability: httpapi.Capability{
			Available: state.Supported,
			Degraded:  state.Supported && s.a.settings().ProxySystem && !applied,
			Reason:    reason,
			Limits:    state.Limits,
		},
	}
	if view.Manual == nil {
		view.Manual = []sysproxy.Command{}
	}
	return view
}
