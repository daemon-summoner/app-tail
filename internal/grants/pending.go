// SPDX-License-Identifier: MIT

package grants

import (
	"slices"
	"strings"
	"sync"
)

// Feature is which part of app-tail asked for a change an administrator has not approved. It
// reaches the dashboard beside each waiting approval, so it is part of the API.
type Feature string

const (
	// FeatureInterface is the tailnet on a real network interface.
	FeatureInterface Feature = "interface"
	// FeatureFabric is every connected network on one interface.
	FeatureFabric Feature = "fabric"
	// FeatureSystemDNS is pointing this machine's own name resolution at app-tail.
	FeatureSystemDNS Feature = "system-dns"
	// FeatureTLSInterception is the intrusion prevention feature opening encrypted connections.
	FeatureTLSInterception Feature = "tls-interception"
)

const openVPNFeaturePrefix = "openvpn:"

// OpenVPNFeature is one OpenVPN connection, by its connection id.
func OpenVPNFeature(id string) Feature { return Feature(openVPNFeaturePrefix + id) }

// OpenVPNID is the connection an OpenVPN feature names, and whether it is one.
func (f Feature) OpenVPNID() (string, bool) {
	return strings.CutPrefix(string(f), openVPNFeaturePrefix)
}

// Source is one kind of change one feature asks for. A feature can ask for more than one --
// the interface sends its routes and its resolver separately -- and a success on one says
// nothing about the other, so each is waiting, or not, on its own.
type Source struct {
	Feature Feature
	// Change names the request, such as the helper operation that was refused.
	Change string
}

// Observer hears how requests that may need an approval were answered.
type Observer interface {
	// Refused reports a change refused for the approvals it is missing.
	Refused(src Source, needs []Need)
	// Accepted reports a change that went through, so whatever it was waiting for is not
	// waiting any more.
	Accepted(src Source)
}

// The caps on what Pending holds. Everything it holds is shown to a person and every entry is
// a flag on one command line, so a list past these is no longer one anyone reads. The sources
// are bounded by the features this app has -- a handful plus one per OpenVPN connection -- and
// the needs by the routes and domains one change names.
const (
	maxPendingSources        = 64
	maxPendingNeedsPerSource = 32
)

// PendingNeed is one approval something is waiting for, and every feature waiting for it.
type PendingNeed struct {
	Need
	Features []Feature `json:"features"`
}

// Pending is every approval this process is waiting for, kept by the change that was refused.
// It is safe for concurrent use: refusals arrive from every session to the privileged side.
type Pending struct {
	mu sync.Mutex
	// order is the sources oldest first, which is the order their needs are listed in and the
	// order they are dropped in when the cap is reached.
	order    []Source
	bySource map[Source][]Need
}

// NewPending returns a Pending waiting for nothing.
func NewPending() *Pending {
	return &Pending{bySource: make(map[Source][]Need)}
}

var _ Observer = (*Pending)(nil)

// Refused records what a change is waiting for, replacing what the same change was waiting for
// before: the latest refusal is the one that describes the machine now. A change refused again
// keeps its place, so a list a person is reading does not reorder under them each time a
// retry is refused. A refusal naming nothing clears the change, since no approval would
// answer it.
func (p *Pending) Refused(src Source, needs []Need) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(needs) == 0 {
		p.dropLocked(src)
		return
	}
	needs = needs[:min(len(needs), maxPendingNeedsPerSource)]
	kept := make([]Need, len(needs))
	for i, n := range needs {
		n.CASHA256 = slices.Clone(n.CASHA256)
		kept[i] = n
	}
	if _, ok := p.bySource[src]; ok {
		p.bySource[src] = kept
		return
	}
	if len(p.order) == maxPendingSources {
		delete(p.bySource, p.order[0])
		p.order = p.order[1:]
	}
	p.order = append(p.order, src)
	p.bySource[src] = kept
}

// Accepted clears a change that went through.
func (p *Pending) Accepted(src Source) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dropLocked(src)
}

// Retain keeps only the changes of features keep still wants, which is how a feature that was
// switched off stops waiting for an approval it no longer needs.
func (p *Pending) Retain(keep func(Feature) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	order := p.order[:0]
	for _, src := range p.order {
		if keep(src.Feature) {
			order = append(order, src)
			continue
		}
		delete(p.bySource, src)
	}
	clear(p.order[len(order):])
	p.order = order
}

func (p *Pending) dropLocked(src Source) {
	if _, ok := p.bySource[src]; !ok {
		return
	}
	delete(p.bySource, src)
	p.order = slices.DeleteFunc(p.order, func(s Source) bool { return s == src })
}

// Features is every feature waiting for at least one approval, oldest refusal first.
func (p *Pending) Features() []Feature {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Feature
	for _, src := range p.order {
		if !slices.Contains(out, src.Feature) {
			out = append(out, src.Feature)
		}
	}
	return out
}

// Needs is every approval waiting, each listed once with the features waiting for it. Two
// needs are the same approval when they name the same kind, value and certificates -- one
// `tun grant` flag answers both. The result is the caller's to keep.
func (p *Pending) Needs() []PendingNeed {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []PendingNeed
	for _, src := range p.order {
		for _, need := range p.bySource[src] {
			i := slices.IndexFunc(out, func(have PendingNeed) bool { return sameApproval(have.Need, need) })
			if i < 0 {
				need.CASHA256 = slices.Clone(need.CASHA256)
				out = append(out, PendingNeed{Need: need, Features: []Feature{src.Feature}})
				continue
			}
			if !slices.Contains(out[i].Features, src.Feature) {
				out[i].Features = append(out[i].Features, src.Feature)
			}
		}
	}
	return out
}

func sameApproval(a, b Need) bool {
	return a.Kind == b.Kind && a.Value == b.Value && slices.Equal(a.CASHA256, b.CASHA256)
}

// CommandLine is the command an administrator runs on goos to approve needs, quoted for the
// shell it is pasted into, or "" when there is nothing to approve. A server name in an
// OpenVPN approval is not limited to characters a shell leaves alone, so every argument is
// quoted rather than trusted.
func CommandLine(goos string, needs []Need) string {
	if len(needs) == 0 {
		return ""
	}
	args := append([]string{"app-tail"}, GrantArgs(needs)...)
	quote := posixQuote
	if goos == "windows" {
		quote = windowsQuote
	} else {
		args = append([]string{"sudo"}, args...)
	}
	for i, arg := range args {
		args[i] = quote(arg)
	}
	return strings.Join(args, " ")
}

// shellSafe is true when every character of s means itself to a POSIX shell and to PowerShell.
func shellSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-_./:=,@+", r):
		default:
			return false
		}
	}
	return true
}

func posixQuote(s string) string {
	if shellSafe(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// windowsQuote quotes an argument for PowerShell, the shell the Windows command is given for.
// Its single quotes are literal, doubling any inside; its double quotes would still run a
// $(...) a server name carried.
func windowsQuote(s string) string {
	if shellSafe(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
