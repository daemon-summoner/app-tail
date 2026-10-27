// SPDX-License-Identifier: MIT

package sysdns

import (
	"fmt"
	"net/netip"
	"slices"
)

// change is one service's worth of work: what to write, what it had before app-tail ever
// touched it, and -- when there is nothing to do -- why.
//
// A skipped change is kept rather than dropped so the reason reaches the log. "Nothing
// happened" with no reason is the report that sends someone looking for a bug in the part
// that worked.
type change struct {
	Service Service
	// Set is what to write. Empty means restore the service to the network's own
	// resolvers, which is not the same as writing an empty list.
	Set []netip.Addr
	// Prior is what the service resolved through before app-tail changed it, carried for
	// the record and for the log line.
	Prior []netip.Addr
	// Skip names why this service is left alone, empty when it is not.
	Skip string
}

// plan decides what to write to point this machine at want.
//
// It is a pure function of what the services say and what the record remembers, so every
// rule below is reachable in a test without a machine to change. The rules are not an
// optimisation: writing a service's resolver costs a shell-out measured in hundreds of
// milliseconds, and a laptop has a dozen services.
func plan(states []state, want []netip.Addr, rec record) []change {
	out := make([]change, 0, len(states))
	for _, s := range states {
		prior := priorFor(s, rec, want)
		switch {
		case sameAddrs(s.Current, want):
			// Already pointing here. The record still has to carry it, which merge does
			// from this change, or switching the module off would leave the override in
			// place with nothing saying it was ours.
			out = append(out, change{Service: s.Service, Set: want, Prior: prior, Skip: "it already resolves through app-tail"})
		default:
			out = append(out, change{Service: s.Service, Set: want, Prior: prior})
		}
	}
	return out
}

// priorFor reports what a service resolved through before app-tail touched it: the
// recorded value when there is one, and what it says now when there is not.
//
// Preferring the record is the whole of what makes applying twice safe. Reading the
// current value a second time would read app-tail's own address and record it as the
// user's, and restoring would then put the override back.
//
// ours is what this application is about to write, and reaching the second branch with the
// service already set to it -- or to an address app-tail wrote before -- means the service's
// entry was lost while the override stood. Recording
// that as the user's own setting is the one mistake here with no way back: every later
// restore would write app-tail's address as a permanent static one, which outlives the
// process, the reboot and the uninstall. Nil instead, which restores to the network's own
// resolvers -- worse than the setting the user had, and the only one of the three outcomes
// the machine can resolve names through.
func priorFor(s state, rec record, ours []netip.Addr) []netip.Addr {
	if sr, ok := rec.Services[s.Service.ID]; ok {
		return parseAddrs(sr.Prior)
	}
	if rec.wroteHere(s.Current, ours) {
		return nil
	}
	return s.Current
}

// planRestore decides what to write to put every service back.
//
// A service whose setting is no longer one app-tail wrote is left alone: something else set
// it since -- a VPN client, a profile, the user -- and putting the older value back over it
// would be this package causing the very problem it exists to avoid.
func planRestore(states []state, rec record) []change {
	out := make([]change, 0, len(states))
	for _, s := range states {
		sr, ok := rec.Services[s.Service.ID]
		if !ok {
			continue
		}
		prior := parseAddrs(sr.Prior)
		wrote := parseAddrs(sr.Wrote)
		if !rec.wroteHere(s.Current, wrote) {
			out = append(out, change{
				Service: s.Service,
				Set:     prior,
				Prior:   prior,
				Skip: fmt.Sprintf("it resolves through %s now, which is not what app-tail set (%s)",
					describe(s.Current), describe(wrote)),
			})
			continue
		}
		out = append(out, change{Service: s.Service, Set: prior, Prior: prior})
	}
	return out
}

// merge folds a plan's changes into the record that will be written before them.
//
// Services already carrying a record keep the value recorded there; a service reached for
// the first time gets the value it has now. Nothing is ever removed here -- a service that
// disappeared between two applications still has to be restorable when it comes back.
func merge(rec record, changes []change) record {
	next := record{
		Services: make(map[string]serviceRecord, len(rec.Services)+len(changes)),
		// Carried across: the addresses app-tail added to this machine's loopback are
		// recorded by the bind, which happens before this, and dropping them here would
		// leave the restore with nothing saying to take them off again.
		Loopback: slices.Clone(rec.Loopback),
		Ours:     slices.Clone(rec.Ours),
	}
	for id, sr := range rec.Services {
		next.Services[id] = sr
		// A record from before Ours was kept still names what it wrote.
		next.Ours = addOurs(next.Ours, sr.Wrote)
	}
	for _, c := range changes {
		next.Ours = addOurs(next.Ours, formatAddrs(c.Set))
		existing, ok := next.Services[c.Service.ID]
		prior := formatAddrs(c.Prior)
		if ok {
			prior = existing.Prior
		}
		next.Services[c.Service.ID] = serviceRecord{
			Name:  c.Service.Name,
			Prior: prior,
			Wrote: formatAddrs(c.Set),
		}
	}
	return next
}

// addOurs adds the addresses ours does not carry yet, keeping the order they were first
// written in.
func addOurs(ours, addrs []string) []string {
	for _, a := range addrs {
		if !slices.Contains(ours, a) {
			ours = append(ours, a)
		}
	}
	return ours
}

// sameAddrs compares two resolver lists. Order matters: the first is the one everything
// goes to, so a list in another order is another setting.
func sameAddrs(a, b []netip.Addr) bool {
	return slices.Equal(a, b)
}

func formatAddrs(addrs []netip.Addr) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

// parseAddrs reads a recorded list back. An entry that will not parse is dropped: the
// record is on disk between boots and an unusable address in it must not stop the rest of
// a restore.
func parseAddrs(in []string) []netip.Addr {
	if len(in) == 0 {
		return nil
	}
	out := make([]netip.Addr, 0, len(in))
	for _, s := range in {
		if addr, err := netip.ParseAddr(s); err == nil {
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
