// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/exitnode"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// dnsAPI presents name resolution to the management API.
type dnsAPI struct{ a *Agent }

var _ httpapi.DNS = dnsAPI{}

// DNSAPI exposes the DNS module.
func (a *Agent) DNSAPI() httpapi.DNS { return dnsAPI{a: a} }

// View puts what the tailnet publishes beside what this machine actually resolves with.
//
// The gap between the two is the entire question: in the mode app-tail ships in, turning
// the tailnet's DNS on configures the resolver inside this process and changes nothing at
// all about how any other program on this machine resolves names. Showing only the first
// half is what makes "why doesn't my browser resolve foo.corp" unanswerable.
func (d dnsAPI) View(ctx context.Context) httpapi.DNSView {
	a := d.a
	s := a.settings()

	view := httpapi.DNSView{
		Enabled: s.DNSEnabled,
		Using:   a.primaryPrefs().DNSUseTailnet,
		System:  a.systemDNSView(ctx),
	}

	node := a.currentNode()
	if node == nil || !node.Status().Running() {
		view.Capability = dnsCapability(s, view, a.nodeProblem())
		return view
	}

	tailnet, err := node.TailnetDNS(ctx)
	if err != nil {
		a.logger.Debug("reading the tailnet's DNS configuration failed", "error", err)
		view.Error = err.Error()
	} else {
		view.MagicDNS = tailnet.MagicDNS
		view.Resolvers = append([]string(nil), tailnet.Resolvers...)
		view.SearchDomains = append([]string(nil), tailnet.Domains...)
		for _, r := range tailnet.Routes {
			view.Routes = append(view.Routes, httpapi.DNSRouteView{
				Suffix:    r.Suffix,
				Resolvers: append([]string(nil), r.Resolvers...),
			})
		}
		for _, r := range tailnet.Records {
			view.Records = append(view.Records, httpapi.DNSRecordView{
				Name: r.Name, Type: r.Type, Value: r.Value,
			})
		}
	}

	machine, err := node.MachineDNS(ctx)
	switch {
	case errors.Is(err, tsnode.ErrDNSNotManaged):
		// The expected answer in the mode app-tail ships in, and the one fact the panel
		// exists to state. It is a reason rather than an error precisely because reporting
		// it as a failure would send a user looking for a broken read.
		view.MachineReason = "Your tailnet's DNS changes nothing about this machine. Every " +
			"program other than app-tail keeps using the resolver it already had, so a name " +
			"your tailnet serves will not resolve in a browser unless you point it at " +
			"app-tail's proxy. Which resolver this machine uses is the System resolver above, " +
			"and it is a separate switch."
	case err != nil:
		a.logger.Debug("reading this machine's DNS configuration failed", "error", err)
		view.Error = err.Error()
	default:
		view.Machine = &httpapi.DNSMachineView{
			Nameservers:   append([]string(nil), machine.Nameservers...),
			SearchDomains: append([]string(nil), machine.SearchDomains...),
			MatchDomains:  append([]string(nil), machine.MatchDomains...),
		}
	}

	// Which device is answering matters only while one is selected, and the selection the
	// rotator holds is the live one -- the stored setting is what it falls back to.
	state, candidates, _ := a.exitNode.snapshot()
	if summary := exitnode.Summarize(s.ExitNodeEnabled, a.primaryPrefs(), state, candidates); summary.Current != "" {
		answering, err := node.ExitNodeAnswersDNS(ctx, summary.Current)
		if err != nil {
			a.logger.Debug("reading whether the exit node answers DNS failed", "error", err)
			view.Error = err.Error()
		} else if answering {
			view.ExitNodeResolving = true
			// A device the tailnet is no longer offering has no friendly name, and its
			// stable ID is still enough to look it up -- an unnamed device reads as a bug.
			view.ExitNodeLabel = summary.CurrentLabel
			if view.ExitNodeLabel == "" {
				view.ExitNodeLabel = summary.Current
			}
		}
	}

	view.Capability = dnsCapability(s, view, a.nodeProblem())
	return view
}

// dnsCapability states whether the tailnet's DNS is in force for this app and, when it is
// not, why -- so the dashboard, the tray and the CLI cannot reach different conclusions.
//
// Every "available" reading here is scoped to this process on purpose. There is no state
// in which THIS setting has changed the machine, and a capability that read otherwise would
// be the one place the app oversold what it does. The machine-wide resolver is a module of
// its own with a capability of its own (systemDNSCapability); the two are never merged,
// because a reader of this one is asking what app-tail resolves with, and a reader of that
// one is asking what their browser resolves with.
func dnsCapability(s config.Settings, view httpapi.DNSView, nodeProblem string) httpapi.Capability {
	limits := []string{
		"Only app-tail's own connections use your tailnet's DNS. Other programs keep the " +
			"resolver they already had.",
		"Names your tailnet serves -- device names and split-DNS domains -- resolve through " +
			"app-tail's proxy or its forwards, and nowhere else on this machine.",
	}
	switch {
	case !s.DNSEnabled:
		return httpapi.Capability{
			Reason: "The DNS module is off, so app-tail resolves names with this machine's own " +
				"resolver.",
			Limits: limits,
		}
	case nodeProblem != "":
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "The tailnet node is not running (" + nodeProblem +
				"), so nothing is resolving through your tailnet.",
			Limits: limits,
		}
	case view.Error != "":
		return httpapi.Capability{Available: true, Degraded: true, Reason: view.Error, Limits: limits}
	case !view.Using:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "Using your tailnet's DNS is switched off, so app-tail resolves names with " +
				"this machine's own resolver and device names will not resolve.",
			Limits: limits,
		}
	case len(view.Resolvers) == 0 && !view.MagicDNS:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "Your tailnet publishes no nameserver and does not resolve device names, so " +
				"there is nothing for app-tail to resolve with.",
			Limits: limits,
		}
	}
	return httpapi.Capability{Available: true, Limits: limits}
}
