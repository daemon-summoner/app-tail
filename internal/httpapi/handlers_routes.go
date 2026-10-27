// SPDX-License-Identifier: MIT

package httpapi

import "net/http"

// The limits of a userspace subnet router, stated wherever the module is shown rather
// than discovered by hitting them. None of these is a defect a later release fixes:
// app-tail installs no network interface, and the tailnet stack offers a userspace node
// no hook for anything but TCP.
const (
	tcpOnlyLimit = "Only TCP is carried across a network this device routes. UDP has no " +
		"equivalent hook in userspace, so DNS, QUIC and HTTP/3, video calls, VPNs and " +
		"file shares all fail across these routes."
	sourceAddressLimit = "Connections leave this machine from this machine's own address, " +
		"so a host on the routed network sees this device rather than the one that called it."
	pingLimit = "Ping across a routed network is answered by this machine, not by the host " +
		"being pinged, so a reply says nothing about whether that host is up."
)

func (s *Server) handleGetRoutes(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Routes, "subnet routes"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.Routes.View(r.Context()))
}

// handleRoutesCheck measures which devices carrying an accepted route answer from here.
//
// It is a POST because the answer comes from probing every device that advertises a
// route rather than from reading state, and that must happen when someone asks rather
// than on every dashboard poll.
func (s *Server) handleRoutesCheck(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Routes, "subnet routes"); err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.deps.Routes.Check(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

// RouteLimits are what a userspace subnet router does not do, served rather than written
// into each client so the dashboard, the tray and the CLI state them identically.
func RouteLimits() []string {
	return []string{tcpOnlyLimit, sourceAddressLimit, pingLimit}
}
