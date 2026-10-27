// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"slices"

	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"

	"github.com/sellitus/app-tail/internal/config"
)

// Prefs are the node preferences this app models, in stdlib types. It is deliberately a
// subset of ipn.Prefs: the ones it does not name -- the operator user, auto-update, SSH,
// drive shares -- belong to whoever set them and must survive every write this app makes.
//
// Two values are compared with Same rather than ==, because one member is a list. The
// comparison is what decides whether a notification from the backend changed anything, so
// comparing a slice by identity would report a change on every notification it sends.
type Prefs struct {
	// RouteAll accepts the subnet routes other devices advertise.
	RouteAll bool
	// ExitNodeID is the peer this node sends the rest of its traffic through, by stable
	// node ID, or empty for none.
	ExitNodeID string
	// AutoExitNode lets the backend choose the exit node and keep re-choosing it. It
	// takes precedence over ExitNodeID at the backend, so the two are never both set.
	AutoExitNode bool
	// ExitNodeAllowLANAccess keeps this machine's own local network reachable while an
	// exit node is carrying everything else.
	ExitNodeAllowLANAccess bool
	// AdvertiseExitNode offers this node to the tailnet as an exit node. It reads the
	// pair of default routes rather than a preference of its own.
	AdvertiseExitNode bool
	// AdvertisedSubnets are the networks this node offers to carry, in a canonical order
	// and without the default routes AdvertiseExitNode already accounts for. Keeping the
	// two disjoint is what lets each setting be compared against the node on its own.
	AdvertisedSubnets []netip.Prefix
	// CorpDNS configures this node's resolver with the tailnet's DNS. In userspace mode
	// that resolver is the one inside this process and nothing else on the machine, so a
	// consumer that reads this must say so rather than imply the machine changed.
	CorpDNS bool
	// ShieldsUp blocks every incoming connection regardless of what the tailnet's ACLs
	// allow, which includes the ones this app's own forwards depend on.
	ShieldsUp bool
	// PostureChecking sends device posture information -- serial numbers, OS version, MDM
	// identifiers -- to the tailnet. It leaves the machine, so nothing turns it on except
	// the user.
	PostureChecking bool
}

// Same reports whether two preference sets say the same thing. It exists because Prefs
// carries a list: the watcher decides whether a notification changed anything by
// comparing the value it carried against the one held, and == on a struct with a slice
// member does not compile.
func (p Prefs) Same(other Prefs) bool {
	return p.RouteAll == other.RouteAll &&
		p.ExitNodeID == other.ExitNodeID &&
		p.AutoExitNode == other.AutoExitNode &&
		p.ExitNodeAllowLANAccess == other.ExitNodeAllowLANAccess &&
		p.AdvertiseExitNode == other.AdvertiseExitNode &&
		p.CorpDNS == other.CorpDNS &&
		p.ShieldsUp == other.ShieldsUp &&
		p.PostureChecking == other.PostureChecking &&
		slices.Equal(p.AdvertisedSubnets, other.AdvertisedSubnets)
}

// PrefsPatch is a sparse edit: a nil member means "leave that preference alone". It is
// the only shape a write takes, because a whole-Prefs replacement would silently clear
// every preference this app does not model.
type PrefsPatch struct {
	RouteAll               *bool
	ExitNodeID             *string
	AutoExitNode           *bool
	ExitNodeAllowLANAccess *bool
	// AdvertiseRoutes is the whole advertised set, not one contribution to it. More than
	// one setting feeds it -- offering this node as an exit node, and the subnet list --
	// so each contributor writes the complete list computed from all of them. Writing a
	// contribution instead would have whichever setting was pushed last erase the other.
	AdvertiseRoutes *[]netip.Prefix
	CorpDNS         *bool
	ShieldsUp       *bool
	PostureChecking *bool
}

// empty reports a patch that would change nothing, which is not worth a round trip to
// the backend and must not be sent as an edit that names no field.
func (p PrefsPatch) empty() bool {
	return p.RouteAll == nil && p.ExitNodeID == nil && p.AutoExitNode == nil &&
		p.ExitNodeAllowLANAccess == nil && p.AdvertiseRoutes == nil &&
		p.CorpDNS == nil && p.ShieldsUp == nil && p.PostureChecking == nil
}

// prefField is one pref-backed connection field seen from all three sides at once: what
// the stored preferences ask the node for, what the node currently reports, and how that
// wanted value is written into a patch.
//
// The three are one entry rather than three tables because they must agree about which
// preference a key names; separate tables would let a key read one preference and write
// another, and nothing would fail until traffic went the wrong way.
type prefField struct {
	want  func(config.TailnetPrefs) any
	read  func(Prefs) any
	apply func(config.TailnetPrefs, *PrefsPatch)
}

// boolPref builds the entry for a preference carried as a boolean. Going through a
// typed constructor is what keeps the table free of type assertions: the wanted value is
// produced and consumed by the same closure.
func boolPref(want func(config.TailnetPrefs) bool, read func(Prefs) bool, put func(*PrefsPatch, bool)) prefField {
	return prefField{
		want:  func(p config.TailnetPrefs) any { return want(p) },
		read:  func(p Prefs) any { return read(p) },
		apply: func(p config.TailnetPrefs, patch *PrefsPatch) { put(patch, want(p)) },
	}
}

// stringPref is boolPref for a preference carried as a string, such as the node ID
// naming an exit node.
func stringPref(want func(config.TailnetPrefs) string, read func(Prefs) string, put func(*PrefsPatch, string)) prefField {
	return prefField{
		want:  func(p config.TailnetPrefs) any { return want(p) },
		read:  func(p Prefs) any { return read(p) },
		apply: func(p config.TailnetPrefs, patch *PrefsPatch) { put(patch, want(p)) },
	}
}

// routesPref builds the entry for a setting whose value is one part of the advertised
// route set: want and read stay this setting's own, while the write is the whole set.
func routesPref[T any](want func(config.TailnetPrefs) T, read func(Prefs) T) prefField {
	return prefField{
		want: func(p config.TailnetPrefs) any { return want(p) },
		read: func(p Prefs) any { return read(p) },
		apply: func(p config.TailnetPrefs, patch *PrefsPatch) {
			routes := advertisedRoutes(p)
			patch.AdvertiseRoutes = &routes
		},
	}
}

// wantedExitNodeID is the peer this connection names, which is empty whenever the backend
// is choosing: AutoExitNode takes precedence at the backend, and sending both would leave
// this app's own idea of the exit node disagreeing with the one actually in use.
func wantedExitNodeID(p config.TailnetPrefs) string {
	if p.ExitNodeAuto {
		return ""
	}
	return p.ExitNodeID
}

// advertisedRoutes is the complete set of routes this connection offers, computed from
// every preference that contributes one. It is a pure function of the preferences so that
// each contributing key writes the same whole list and none of them can erase another.
func advertisedRoutes(p config.TailnetPrefs) []netip.Prefix {
	var routes []netip.Prefix
	if p.RoutesAdvertiseExitNode {
		routes = append(routes, tsaddr.AllIPv4(), tsaddr.AllIPv6())
	}
	return append(routes, p.AdvertisedSubnets()...)
}

// prefFields projects one connection's stored preferences onto node preferences, one
// entry per pref-backed registry field, keyed by that field's JSON key.
//
// The module switches are not applied here. They are folded in by
// config.Settings.TailnetPrefsOf, which is what produces the value passed in, so a
// switched-off module reaches this table as the default it turns its fields back to.
//
// It lives here rather than in internal/config because the projection is a fact about
// ipn.Prefs, and internal/config imports nothing from Tailscale -- putting it there
// would invert that. A guard test asserts this table and config.PrefsFields name
// exactly each other, so a field added on either side cannot go unmapped.
var prefFields = map[string]prefField{
	"routes.accept": boolPref(
		func(p config.TailnetPrefs) bool { return p.RoutesAccept },
		func(p Prefs) bool { return p.RouteAll },
		func(patch *PrefsPatch, v bool) { patch.RouteAll = &v },
	),
	"routes.advertiseExitNode": routesPref(
		func(p config.TailnetPrefs) bool { return p.RoutesAdvertiseExitNode },
		func(p Prefs) bool { return p.AdvertiseExitNode },
	),
	"routes.advertise": routesPref(
		config.TailnetPrefs.AdvertisedSubnets,
		func(p Prefs) []netip.Prefix { return p.AdvertisedSubnets },
	),
	"exitNode.nodeId": stringPref(
		wantedExitNodeID,
		func(p Prefs) string { return p.ExitNodeID },
		func(patch *PrefsPatch, v string) { patch.ExitNodeID = &v },
	),
	"exitNode.auto": boolPref(
		func(p config.TailnetPrefs) bool { return p.ExitNodeAuto },
		func(p Prefs) bool { return p.AutoExitNode },
		func(patch *PrefsPatch, v bool) { patch.AutoExitNode = &v },
	),
	"dns.useTailnet": boolPref(
		func(p config.TailnetPrefs) bool { return p.DNSUseTailnet },
		func(p Prefs) bool { return p.CorpDNS },
		func(patch *PrefsPatch, v bool) { patch.CorpDNS = &v },
	),
	"security.shieldsUp": boolPref(
		func(p config.TailnetPrefs) bool { return p.ShieldsUp },
		func(p Prefs) bool { return p.ShieldsUp },
		func(patch *PrefsPatch, v bool) { patch.ShieldsUp = &v },
	),
	"security.postureChecking": boolPref(
		func(p config.TailnetPrefs) bool { return p.PostureChecking },
		func(p Prefs) bool { return p.PostureChecking },
		func(patch *PrefsPatch, v bool) { patch.PostureChecking = &v },
	),
	"exitNode.allowLanAccess": boolPref(
		// Off without an exit node, so the preference the node holds matches what is
		// actually happening rather than a setting waiting to mean something.
		func(p config.TailnetPrefs) bool { return p.ExitNodeSelected() && p.ExitNodeAllowLANAccess },
		func(p Prefs) bool { return p.ExitNodeAllowLANAccess },
		func(patch *PrefsPatch, v bool) { patch.ExitNodeAllowLANAccess = &v },
	),
}

// PrefKeys are the connection keys this package projects, in the registry's order.
func PrefKeys() []string {
	out := make([]string, 0, len(prefFields))
	for _, f := range config.PrefsFields() {
		if _, ok := prefFields[f.JSONKey]; ok {
			out = append(out, f.JSONKey)
		}
	}
	return out
}

// LiveValues reports what each pref-backed setting reads as on the node right now. It
// is the live half of the stored-versus-live comparison a consumer renders, and what
// adoption reads on a first run against a node someone else enrolled.
func LiveValues(p Prefs) map[string]any {
	out := make(map[string]any, len(prefFields))
	for key, f := range prefFields {
		out[key] = f.read(p)
	}
	return out
}

// Drift reports the pref-backed keys whose value on the node differs from what this
// connection asks for, in registry order. An empty result is the only state in which this
// app has nothing left to push.
func Drift(live Prefs, want config.TailnetPrefs) []string {
	var out []string
	for _, key := range PrefKeys() {
		f := prefFields[key]
		// DeepEqual rather than !=, because one setting's value is a list: comparing
		// those with != panics at runtime rather than failing to compile.
		if !reflect.DeepEqual(f.read(live), f.want(want)) {
			out = append(out, key)
		}
	}
	return out
}

// PrefsFor projects one connection's preferences onto the patch that mirrors them.
// Passing every pref-backed field is what makes the push after a node comes up complete:
// tsnet applies none of these from its server parameters, so this is the only path any of
// them take.
func PrefsFor(want config.TailnetPrefs) PrefsPatch {
	return PrefsForFields(want, PrefKeys())
}

// PrefsForFields projects only the named fields, for the write that follows a settings
// change: pushing the whole set there would reapply a preference the user is not
// touching, over one they may have just changed by hand on the node itself.
func PrefsForFields(want config.TailnetPrefs, keys []string) PrefsPatch {
	var patch PrefsPatch
	for _, key := range keys {
		if f, ok := prefFields[key]; ok {
			f.apply(want, &patch)
		}
	}
	return patch
}

// masked builds the single ipn.MaskedPrefs a patch becomes. Every member sets both the
// value and its own mask bit, so one edit carries the whole patch: two sequential edits
// are validated separately by the backend, and a pair that is only valid together --
// clearing an advertised exit node while selecting one, say -- fails on the first.
func (p PrefsPatch) masked() *ipn.MaskedPrefs {
	mp := &ipn.MaskedPrefs{}
	if p.RouteAll != nil {
		mp.RouteAll, mp.RouteAllSet = *p.RouteAll, true
	}
	if p.ExitNodeID != nil {
		mp.ExitNodeID, mp.ExitNodeIDSet = tailcfg.StableNodeID(*p.ExitNodeID), true
	}
	if p.AutoExitNode != nil {
		// The backend models this as an expression with room to grow ("mullvad",
		// "geo:us"); "any" is the only value it accepts today, and the empty string is
		// how automatic selection is turned back off.
		var expr ipn.ExitNodeExpression
		if *p.AutoExitNode {
			expr = ipn.AnyExitNode
		}
		mp.AutoExitNode, mp.AutoExitNodeSet = expr, true
	}
	if p.ExitNodeAllowLANAccess != nil {
		mp.ExitNodeAllowLANAccess, mp.ExitNodeAllowLANAccessSet = *p.ExitNodeAllowLANAccess, true
	}
	if p.AdvertiseRoutes != nil {
		mp.AdvertiseRoutes, mp.AdvertiseRoutesSet = *p.AdvertiseRoutes, true
	}
	if p.CorpDNS != nil {
		mp.CorpDNS, mp.CorpDNSSet = *p.CorpDNS, true
	}
	if p.ShieldsUp != nil {
		mp.ShieldsUp, mp.ShieldsUpSet = *p.ShieldsUp, true
	}
	if p.PostureChecking != nil {
		mp.PostureChecking, mp.PostureCheckingSet = *p.PostureChecking, true
	}
	return mp
}

// prefsFromIPN reads the modelled subset out of the backend's own value.
func prefsFromIPN(p *ipn.Prefs) Prefs {
	if p == nil {
		return Prefs{}
	}
	return Prefs{
		RouteAll:               p.RouteAll,
		ExitNodeID:             string(p.ExitNodeID),
		AutoExitNode:           p.AutoExitNode != "",
		ExitNodeAllowLANAccess: p.ExitNodeAllowLANAccess,
		AdvertiseExitNode:      p.AdvertisesExitNode(),
		AdvertisedSubnets:      advertisedSubnets(p.AdvertiseRoutes),
		CorpDNS:                p.CorpDNS,
		ShieldsUp:              p.ShieldsUp,
		PostureChecking:        p.PostureChecking,
	}
}

// advertisedSubnets are the networks in an advertised route set, which is that set
// without the default routes: those two are how a node offers itself as an exit node,
// and reading them as subnets would have the two settings report each other's value.
func advertisedSubnets(routes []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range routes {
		if p.Bits() > 0 {
			out = append(out, p)
		}
	}
	return config.SortPrefixes(out)
}

// Prefs reads the node's current preferences from the backend.
func (n *Node) Prefs(ctx context.Context) (Prefs, error) {
	lc := n.client()
	if lc == nil {
		return Prefs{}, ErrNotRunning
	}
	p, err := lc.GetPrefs(ctx)
	if err != nil {
		return Prefs{}, fmt.Errorf("read the node's preferences: %w", err)
	}
	return prefsFromIPN(p), nil
}

// CachedPrefs is the last value the event stream delivered, and whether one has arrived
// at all. It answers without a round trip, which is what lets the dashboard show live
// preferences beside the stored settings on every poll.
func (n *Node) CachedPrefs() (Prefs, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.prefs, n.prefsKnown
}

// CheckPrefs asks the backend whether a patch would be accepted, without applying it.
//
// It exists so a refusal reaches the user as the backend's own sentence at the moment
// they write the setting, rather than as a failed push minutes later with nothing on
// screen connecting the two.
func (n *Node) CheckPrefs(ctx context.Context, patch PrefsPatch) error {
	lc := n.client()
	if lc == nil {
		return ErrNotRunning
	}
	if patch.empty() {
		return nil
	}
	current, err := lc.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("read the node's preferences: %w", err)
	}
	// The backend validates the merged result, so the check has to be made against
	// what the prefs would become rather than against the patch alone.
	merged := current.Clone()
	merged.ApplyEdits(patch.masked())
	return lc.CheckPrefs(ctx, merged)
}

// EditPrefs applies a patch as one masked edit and returns what the preferences became.
func (n *Node) EditPrefs(ctx context.Context, patch PrefsPatch) (Prefs, error) {
	lc := n.client()
	if lc == nil {
		return Prefs{}, ErrNotRunning
	}
	if patch.empty() {
		return n.Prefs(ctx)
	}
	after, err := lc.EditPrefs(ctx, patch.masked())
	if err != nil {
		return Prefs{}, fmt.Errorf("change the node's preferences: %w", err)
	}
	next := prefsFromIPN(after)
	n.mu.Lock()
	n.prefs, n.prefsKnown = next, true
	n.mu.Unlock()
	return next, nil
}
