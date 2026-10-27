// SPDX-License-Identifier: MIT

package tsnode

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"

	"github.com/sellitus/app-tail/internal/config"
)

// A setting declared as living on the node, with no projection here, is stored and then
// silently never applied -- and one projected here without a registry entry can never be
// written. Neither failure produces an error anywhere, which is why the correspondence is
// asserted in both directions rather than trusted.
func TestEverySettingHeldOnTheNodeIsProjectedInBothDirections(t *testing.T) {
	declared := make(map[string]bool)
	for _, f := range config.PrefsFields() {
		declared[f.JSONKey] = true
		if _, ok := prefFields[f.JSONKey]; !ok {
			t.Errorf("setting %q is declared as a node preference but nothing here projects it, "+
				"so writing it would store a value the node never hears about", f.JSONKey)
		}
		if f.Kind == config.KindSecret {
			t.Errorf("setting %q is a secret held on the node; its value is reported beside the "+
				"node's own, which would put a stored secret on the wire", f.JSONKey)
		}
	}
	for key := range prefFields {
		if !declared[key] {
			t.Errorf("%q is projected onto a node preference but is not a setting declared as one, "+
				"so nothing can ever write it", key)
		}
	}
}

// PrefKeys drives the full push, the drift comparison and the view. A key missing from
// it is a preference this app claims to keep and never touches.
func TestEveryProjectedSettingIsNamedInRegistryOrder(t *testing.T) {
	var want []string
	for _, f := range config.PrefsFields() {
		want = append(want, f.JSONKey)
	}
	if got := PrefKeys(); !slices.Equal(got, want) {
		t.Errorf("PrefKeys() = %v, want %v", got, want)
	}
}

// A module switched off must reach the node as off. Leaving the preference standing
// would leave the tailnet acting on a setting the user turned off here and can no longer
// see -- the one shape of bug the module system exists to prevent.
func TestASettingWhoseModuleIsOffIsAskedForAsOff(t *testing.T) {
	tests := []struct {
		name   string
		app    config.Settings
		prefs  config.TailnetPrefs
		want   bool
		reason string
	}{
		{
			name:   "on, with its module on",
			app:    config.Settings{RoutesEnabled: true},
			prefs:  config.TailnetPrefs{RoutesAccept: true},
			want:   true,
			reason: "the user turned it on",
		},
		{
			name:   "off, with its module on",
			app:    config.Settings{RoutesEnabled: true},
			want:   false,
			reason: "the user turned it off",
		},
		{
			name:   "on, with its module off",
			prefs:  config.TailnetPrefs{RoutesAccept: true},
			want:   false,
			reason: "the module that governs it is off",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patch := PrefsFor(prefsOf(tt.app, tt.prefs))
			if patch.RouteAll == nil {
				t.Fatal("a full push named no value for accepting routes")
			}
			if *patch.RouteAll != tt.want {
				t.Errorf("asked the node for accept-routes=%v, want %v because %s",
					*patch.RouteAll, tt.want, tt.reason)
			}
		})
	}
}

// The push after a settings change carries only what changed. Sending the whole set
// there would reapply a preference the user is not touching, over one they may have just
// changed on the node itself.
func TestAChangePushesOnlyTheSettingsItNames(t *testing.T) {
	s := prefsOf(config.Settings{RoutesEnabled: true}, config.TailnetPrefs{RoutesAccept: true})

	if patch := PrefsForFields(s, nil); !patch.empty() {
		t.Errorf("a change naming no setting produced the edit %+v, want nothing to send", patch)
	}
	if patch := PrefsForFields(s, []string{"hostname"}); !patch.empty() {
		t.Errorf("a change naming only a setting the node does not hold produced %+v, "+
			"want nothing to send", patch)
	}
	patch := PrefsForFields(s, []string{"routes.accept"})
	if patch.RouteAll == nil || !*patch.RouteAll {
		t.Errorf("a change naming accept-routes produced %+v, want it set", patch)
	}
}

// Drift is what turns a preference changed outside this app into something it can act
// on. A comparison that missed it would leave the node quietly running on someone else's
// value while the dashboard reported this app's.
func TestDriftNamesOnlyTheSettingsTheNodeDisagreesWith(t *testing.T) {
	on := prefsOf(config.Settings{RoutesEnabled: true}, config.TailnetPrefs{RoutesAccept: true})

	if got := Drift(Prefs{RouteAll: true}, on); len(got) != 0 {
		t.Errorf("Drift on a node that agrees = %v, want none", got)
	}
	if got := Drift(Prefs{RouteAll: false}, on); !slices.Equal(got, []string{"routes.accept"}) {
		t.Errorf("Drift on a node holding the opposite = %v, want [routes.accept]", got)
	}
	// The live half of what the dashboard puts beside the stored value.
	if got := LiveValues(Prefs{RouteAll: true})["routes.accept"]; got != true {
		t.Errorf("the node's live accept-routes reads as %v, want true", got)
	}
}

// Two settings write the one advertised-route preference: the networks this device
// offers to carry, and offering the device itself as an exit node. Each has to write the
// whole set computed from both, because a contribution written alone would erase the
// other -- turning one on would silently withdraw whatever the other had advertised.
func TestBothRouteSettingsWriteTheWholeAdvertisedSet(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.0.0/24")
	both := prefsOf(config.Settings{RoutesEnabled: true}, config.TailnetPrefs{
		RoutesAdvertiseExitNode: true,
		RoutesAdvertise:         []netip.Prefix{subnet},
	})

	tests := []struct {
		name string
		keys []string
	}{
		{"a full push", PrefKeys()},
		{"a change to the subnet list alone", []string{"routes.advertise"}},
		{"a change to the exit-node offer alone", []string{"routes.advertiseExitNode"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patch := PrefsForFields(both, tt.keys)
			if patch.AdvertiseRoutes == nil {
				t.Fatal("the edit named no advertised routes at all")
			}
			got := *patch.AdvertiseRoutes
			if !slices.Contains(got, subnet) {
				t.Errorf("the edit advertises %v, which drops the subnet the settings ask for", got)
			}
			if !slices.Contains(got, tsaddr.AllIPv4()) || !slices.Contains(got, tsaddr.AllIPv6()) {
				t.Errorf("the edit advertises %v, which drops the exit-node offer the settings ask for", got)
			}
		})
	}
}

// The subnet list and the exit-node offer are read back separately, so each setting is
// compared against the node on its own. Reading the default routes as subnets would have
// each setting report the other's value, and the mirror would push forever.
func TestTheAdvertisedSubnetsAreReadBackWithoutTheExitNodeRoutes(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.0.0/24")
	live := prefsFromIPN(&ipn.Prefs{
		AdvertiseRoutes: []netip.Prefix{tsaddr.AllIPv4(), subnet, tsaddr.AllIPv6()},
	})

	if !live.AdvertiseExitNode {
		t.Error("a node advertising both default routes does not read as offering itself as an exit node")
	}
	if !slices.Equal(live.AdvertisedSubnets, []netip.Prefix{subnet}) {
		t.Errorf("the node's advertised subnets read as %v, want just %v", live.AdvertisedSubnets, subnet)
	}

	routing := config.Settings{RoutesEnabled: true}
	on := prefsOf(routing, config.TailnetPrefs{
		RoutesAdvertiseExitNode: true, RoutesAdvertise: []netip.Prefix{subnet},
	})
	if got := Drift(live, on); len(got) != 0 {
		t.Errorf("Drift against a node already holding these routes = %v, want none", got)
	}
	// The set is what matters; the order a person typed it in is not a change to push.
	reordered := prefsOf(routing, config.TailnetPrefs{
		RoutesAdvertiseExitNode: true,
		RoutesAdvertise:         []netip.Prefix{netip.MustParsePrefix("192.168.8.0/24"), subnet},
	})
	scrambled := prefsFromIPN(&ipn.Prefs{AdvertiseRoutes: []netip.Prefix{
		tsaddr.AllIPv4(), tsaddr.AllIPv6(), subnet, netip.MustParsePrefix("192.168.8.0/24"),
	}})
	if got := Drift(scrambled, reordered); len(got) != 0 {
		t.Errorf("Drift against the same networks in another order = %v, want none", got)
	}

	withoutSubnets := prefsOf(routing, config.TailnetPrefs{RoutesAdvertiseExitNode: true})
	if got := Drift(live, withoutSubnets); !slices.Equal(got, []string{"routes.advertise"}) {
		t.Errorf("Drift after the subnet list was cleared = %v, want [routes.advertise]", got)
	}
}

// The live value is what adoption stores on a first run against a node someone else
// enrolled, so it has to be the type the setting holds. A value of any other shape is
// not a wrong setting but a panic on that first run.
func TestTheAdvertisedSubnetsAreReportedAsTheSettingStoresThem(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.0.0/24")
	live := LiveValues(prefsFromIPN(&ipn.Prefs{AdvertiseRoutes: []netip.Prefix{subnet}}))

	var s config.Settings
	held := primaryTailnet()
	taken := config.AdoptPrefValues(&s, &held, live)

	if !slices.Contains(taken, "routes.advertise") {
		t.Fatalf("adoption took %v from a node advertising a subnet, want routes.advertise among them", taken)
	}
	if got := held.TS().RoutesAdvertise; !slices.Equal(got, []netip.Prefix{subnet}) {
		t.Errorf("the adopted setting holds %v, want %v", got, subnet)
	}
	if !s.RoutesEnabled {
		t.Error("the adopted routes are stored under a module that reads as off, where the user " +
			"can neither see nor change them")
	}
}

// The rules refusing a route this device must not advertise are written out in
// internal/config, which imports nothing from Tailscale. This is what binds them to the
// library's own values: a range that moves upstream fails here rather than leaving a rule
// that quietly guards an address space the tailnet no longer uses.
func TestConfigRefusesToAdvertiseTheRealTailnetRanges(t *testing.T) {
	if _, ok := config.SettingByName("routes.advertise"); !ok {
		t.Fatal("no setting declares the networks this device advertises")
	}
	for _, r := range TailnetRanges() {
		_, _, err := config.ParseSettingValue("routes.advertise", r.String())
		if err == nil {
			t.Errorf("advertising %s -- an address range this tailnet allocates its own devices "+
				"from -- was accepted", r)
			continue
		}
		if !strings.Contains(err.Error(), "tailnet's own addresses") {
			t.Errorf("refusing %s reads %q, want the tailnet-range rule rather than another one", r, err)
		}
	}
}

// An edit must carry the whole patch as one masked write. Two sequential edits are
// validated separately by the backend, so a pair that is only valid together fails on
// the first -- and a mask bit left unset is a value sent and silently ignored.
func TestAnEditSetsTheMaskForEveryValueItCarries(t *testing.T) {
	var empty PrefsPatch
	if mp := empty.masked(); mp.RouteAllSet {
		t.Error("an edit naming nothing set the accept-routes mask, which would write a zero value")
	}

	accept := true
	mp := PrefsPatch{RouteAll: &accept}.masked()
	if !mp.RouteAllSet {
		t.Error("an edit carrying accept-routes left its mask unset, so the backend would ignore it")
	}
	if !mp.RouteAll {
		t.Errorf("the edit carries accept-routes=%v, want true", mp.RouteAll)
	}
}

// Every field this app models has to reach the mask with the value the settings hold. A
// field whose arm is missing is a setting a user changes and saves and that never leaves
// this process, with a success reported for it.
func TestEveryModelledPreferenceReachesTheMaskWithItsOwnValue(t *testing.T) {
	on, off := true, false
	routes := []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")}

	tests := []struct {
		name  string
		patch PrefsPatch
		set   func(*ipn.MaskedPrefs) bool
		check func(*testing.T, *ipn.MaskedPrefs)
	}{
		{
			name:  "the exit node this device uses",
			patch: PrefsPatch{ExitNodeID: strPtr("nQ7pM3")},
			set:   func(mp *ipn.MaskedPrefs) bool { return mp.ExitNodeIDSet },
			check: func(t *testing.T, mp *ipn.MaskedPrefs) {
				if got := string(mp.ExitNodeID); got != "nQ7pM3" {
					t.Errorf("the edit carries exit node %q, want nQ7pM3", got)
				}
			},
		},
		{
			// The backend models this as an expression with room to grow, so a bare
			// boolean sent as one would be a value it does not understand.
			name:  "letting the backend choose the exit node",
			patch: PrefsPatch{AutoExitNode: &on},
			set:   func(mp *ipn.MaskedPrefs) bool { return mp.AutoExitNodeSet },
			check: func(t *testing.T, mp *ipn.MaskedPrefs) {
				if mp.AutoExitNode != ipn.AnyExitNode {
					t.Errorf("the edit carries %q, want the backend's own %q", mp.AutoExitNode, ipn.AnyExitNode)
				}
			},
		},
		{
			// Turning it back off is an empty expression rather than an absent one: an
			// absent field leaves the backend still choosing.
			name:  "taking that choice back",
			patch: PrefsPatch{AutoExitNode: &off},
			set:   func(mp *ipn.MaskedPrefs) bool { return mp.AutoExitNodeSet },
			check: func(t *testing.T, mp *ipn.MaskedPrefs) {
				if mp.AutoExitNode != "" {
					t.Errorf("the edit carries %q, want automatic selection turned off", mp.AutoExitNode)
				}
			},
		},
		{
			name:  "reaching the local network while an exit node is in use",
			patch: PrefsPatch{ExitNodeAllowLANAccess: &on},
			set:   func(mp *ipn.MaskedPrefs) bool { return mp.ExitNodeAllowLANAccessSet },
			check: func(t *testing.T, mp *ipn.MaskedPrefs) {
				if !mp.ExitNodeAllowLANAccess {
					t.Error("the edit carries LAN access as off, want it on")
				}
			},
		},
		{
			name:  "the networks this device offers",
			patch: PrefsPatch{AdvertiseRoutes: &routes},
			set:   func(mp *ipn.MaskedPrefs) bool { return mp.AdvertiseRoutesSet },
			check: func(t *testing.T, mp *ipn.MaskedPrefs) {
				if len(mp.AdvertiseRoutes) != 1 || mp.AdvertiseRoutes[0] != routes[0] {
					t.Errorf("the edit carries %v, want %v", mp.AdvertiseRoutes, routes)
				}
			},
		},
		{
			// The one pref whose reach is narrower than its name: it points the resolver
			// inside app-tail at the tailnet's DNS and changes nothing about how the rest
			// of the machine resolves names.
			name:  "resolving with the tailnet's DNS",
			patch: PrefsPatch{CorpDNS: &on},
			set:   func(mp *ipn.MaskedPrefs) bool { return mp.CorpDNSSet },
			check: func(t *testing.T, mp *ipn.MaskedPrefs) {
				if !mp.CorpDNS {
					t.Error("the edit carries the tailnet's DNS as off, want it on")
				}
			},
		},
		{
			// A shields setting that never left this process is the worst of the set: the
			// app reports incoming connections blocked while the device keeps taking them.
			name:  "refusing incoming connections",
			patch: PrefsPatch{ShieldsUp: &on},
			set:   func(mp *ipn.MaskedPrefs) bool { return mp.ShieldsUpSet },
			check: func(t *testing.T, mp *ipn.MaskedPrefs) {
				if !mp.ShieldsUp {
					t.Error("the edit carries shields as down, want them up")
				}
			},
		},
		{
			// Turning posture reporting back off has to reach the backend for the same
			// reason it is off by default: identifiers keep leaving the machine otherwise.
			name:  "reporting this device's posture",
			patch: PrefsPatch{PostureChecking: &off},
			set:   func(mp *ipn.MaskedPrefs) bool { return mp.PostureCheckingSet },
			check: func(t *testing.T, mp *ipn.MaskedPrefs) {
				if mp.PostureChecking {
					t.Error("the edit carries posture reporting as on, want it off")
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mp := tc.patch.masked()
			if !tc.set(mp) {
				t.Fatal("the edit left this field's mask unset, so the backend would ignore the value")
			}
			tc.check(t, mp)
		})
	}
}

// The exit node the settings name is empty whenever the backend is choosing, because
// sending both leaves this app's idea of the exit node disagreeing with the one in use --
// the backend takes the automatic choice and this app goes on reporting the pinned peer.
func TestThePinnedExitNodeIsOnlyAskedForWhenTheBackendIsNotChoosing(t *testing.T) {
	on := config.Settings{ExitNodeEnabled: true}
	tests := []struct {
		name  string
		app   config.Settings
		prefs config.TailnetPrefs
		want  string
	}{
		{"pinned", on, config.TailnetPrefs{ExitNodeID: "nQ7pM3"}, "nQ7pM3"},
		{"the backend is choosing", on, config.TailnetPrefs{ExitNodeAuto: true, ExitNodeID: "nQ7pM3"}, ""},
		{"the module is off", config.Settings{}, config.TailnetPrefs{ExitNodeID: "nQ7pM3"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := wantedExitNodeID(prefsOf(tc.app, tc.prefs)); got != tc.want {
				t.Errorf("wantedExitNodeID = %q, want %q", got, tc.want)
			}
		})
	}
}

// A backend that has no preferences yet is not a backend whose preferences are all off.
// Projecting the absent value as a zero Prefs would be pushed back as the node's own
// answer, turning every setting off on the first reconcile after a restart.
func TestNoPreferencesAtAllProjectToAnEmptyValueRatherThanAllOff(t *testing.T) {
	if got := prefsFromIPN(nil); !reflect.DeepEqual(got, Prefs{}) {
		t.Errorf("prefsFromIPN(nil) = %+v, want an empty value", got)
	}
}

// The preferences this app does not model belong to whoever set them: an operator user,
// auto-update, SSH, a drive share. A whole-Prefs write would clear all of them, which is
// the difference between changing one setting and taking the node over.
func TestAnEditLeavesPreferencesThisAppDoesNotModelAlone(t *testing.T) {
	existing := &ipn.Prefs{
		RouteAll:     false,
		RunSSH:       true,
		OperatorUser: "someone",
		ShieldsUp:    true,
		Hostname:     "already-named",
	}

	var sent ipn.Prefs
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPatch {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read the edit: %v", err)
			}
			var mp ipn.MaskedPrefs
			if err := json.Unmarshal(body, &mp); err != nil {
				t.Fatalf("decode the edit: %v", err)
			}
			// The backend merges the masked edit into what it holds; anything the mask
			// leaves out keeps its current value.
			merged := existing.Clone()
			merged.ApplyEdits(&mp)
			sent = *merged
			return jsonResponse(mustJSON(t, merged)), nil
		}
		return jsonResponse(mustJSON(t, existing)), nil
	})

	accept := true
	got, err := n.EditPrefs(t.Context(), PrefsPatch{RouteAll: &accept})
	if err != nil {
		t.Fatalf("EditPrefs: %v", err)
	}

	if !got.RouteAll {
		t.Errorf("accept-routes after the edit = %v, want it turned on", got.RouteAll)
	}
	if !sent.RunSSH || sent.OperatorUser != "someone" || !sent.ShieldsUp || sent.Hostname != "already-named" {
		t.Errorf("the edit changed preferences it was not asked about: %+v", sent)
	}
}

// A refusal has to arrive as the backend's own sentence. The check exists so the user
// reads it on the control they just changed, and a wrapper that swallowed it would leave
// them with a rejected save and no reason.
func TestACheckCarriesTheBackendsOwnRefusal(t *testing.T) {
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "check-prefs") {
			return errorResponse(http.StatusBadRequest,
				"cannot use an exit node while advertising one"), nil
		}
		return jsonResponse(mustJSON(t, &ipn.Prefs{})), nil
	})

	accept := true
	err := n.CheckPrefs(t.Context(), PrefsPatch{RouteAll: &accept})
	if err == nil {
		t.Fatal("a refused check reported success")
	}
	if !strings.Contains(err.Error(), "advertising one") {
		t.Errorf("the refusal reads %q, want the backend's own sentence", err)
	}
}

// An edit refused while being applied has to carry the backend's reason too. A caller
// that got a bare failure would have to guess between a wedged backend and a preference
// combination the tailnet does not allow.
func TestAnEditCarriesTheBackendsOwnRefusal(t *testing.T) {
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPatch {
			return errorResponse(http.StatusBadRequest, "routes cannot overlap the tailnet"), nil
		}
		return jsonResponse(mustJSON(t, &ipn.Prefs{})), nil
	})

	accept := true
	if _, err := n.EditPrefs(t.Context(), PrefsPatch{RouteAll: &accept}); err == nil {
		t.Fatal("a refused edit reported success")
	} else if !strings.Contains(err.Error(), "overlap the tailnet") {
		t.Errorf("the refusal reads %q, want the backend's own sentence", err)
	}
}

// A failed read must not answer with a zero value. Every preference modelled here is a
// boolean, so an invented Prefs{} is indistinguishable from a node that really has them
// all turned off -- and would be pushed back as if it were the node's own answer.
func TestAFailedReadIsReportedRatherThanAnsweredWithAZeroValue(t *testing.T) {
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return errorResponse(http.StatusInternalServerError, "backend is restarting"), nil
	})

	if _, err := n.Prefs(t.Context()); err == nil {
		t.Fatal("a failed read reported success")
	} else if !strings.Contains(err.Error(), "restarting") {
		t.Errorf("the failure reads %q, want the backend's own reason", err)
	}
}

// The check is made against what the preferences would become, so a backend that cannot
// say what they currently are cannot be checked against. Answering "accepted" there would
// wave through a combination the backend then rejects on the push, at a point where
// nothing on screen connects the failure to the setting that caused it.
func TestACheckAgainstPreferencesThatCouldNotBeReadIsRefusedRatherThanPassed(t *testing.T) {
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "check-prefs") {
			t.Error("the backend was asked to check a patch against preferences that could not be read")
			return jsonResponse(mustJSON(t, &ipn.Prefs{})), nil
		}
		return errorResponse(http.StatusInternalServerError, "backend is restarting"), nil
	})

	accept := true
	err := n.CheckPrefs(t.Context(), PrefsPatch{RouteAll: &accept})
	if err == nil {
		t.Fatal("a check made against preferences that could not be read reported success")
	}
	if !strings.Contains(err.Error(), "restarting") {
		t.Errorf("the failure reads %q, want the backend's own reason", err)
	}
}

// An edit naming no field is what a settings write that touched no node preference
// produces. Reading the current value back is the honest answer; sending the empty edit
// would be a write the backend may reject for naming nothing.
func TestAnEditThatWouldChangeNothingReadsTheCurrentValueBack(t *testing.T) {
	edits := 0
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPatch {
			edits++
		}
		return jsonResponse(mustJSON(t, &ipn.Prefs{RouteAll: true})), nil
	})

	got, err := n.EditPrefs(t.Context(), PrefsPatch{})
	if err != nil {
		t.Fatalf("EditPrefs on an empty edit: %v", err)
	}
	if !got.RouteAll {
		t.Errorf("an empty edit answered %+v, want what the node currently holds", got)
	}
	if edits != 0 {
		t.Errorf("an empty edit made %d writes, want none", edits)
	}
}

// A check that would change nothing must not be a round trip: it is run on every settings
// write, and asking the backend about an empty edit is both wasted and, on a backend that
// rejects an edit naming no field, a refusal of a save that was fine.
func TestACheckThatWouldChangeNothingNeverReachesTheBackend(t *testing.T) {
	calls := 0
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(mustJSON(t, &ipn.Prefs{})), nil
	})

	if err := n.CheckPrefs(t.Context(), PrefsPatch{}); err != nil {
		t.Fatalf("CheckPrefs on an empty edit: %v", err)
	}
	if calls != 0 {
		t.Errorf("an empty edit made %d backend calls, want none", calls)
	}
}

// Everything above needs a running node; before Start there is no backend to ask, and
// answering anything but "not running" would have a caller treat a value it invented as
// the node's own.
func TestThePreferenceCallsRefuseWhileTheNodeIsDown(t *testing.T) {
	n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)
	accept := true

	if _, err := n.Prefs(t.Context()); !errors.Is(err, ErrNotRunning) {
		t.Errorf("reading preferences while down = %v, want %v", err, ErrNotRunning)
	}
	if err := n.CheckPrefs(t.Context(), PrefsPatch{RouteAll: &accept}); !errors.Is(err, ErrNotRunning) {
		t.Errorf("checking an edit while down = %v, want %v", err, ErrNotRunning)
	}
	if _, err := n.EditPrefs(t.Context(), PrefsPatch{RouteAll: &accept}); !errors.Is(err, ErrNotRunning) {
		t.Errorf("editing while down = %v, want %v", err, ErrNotRunning)
	}
	if _, known := n.CachedPrefs(); known {
		t.Error("a node that has never run reported knowing its preferences")
	}
}

// The bus is the only place a preference changed outside this process shows up. A
// notification folded in wrongly is either a missed change -- the node quietly running on
// someone else's value -- or a false alarm on the first one, since every preference
// modelled here is a boolean whose zero value and "not read yet" are otherwise the same.
func TestTheEventStreamDeliversPreferencesIncludingTheFirstOne(t *testing.T) {
	n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)

	n.applyNotify(t.Context(), ipn.Notify{Prefs: prefsView(&ipn.Prefs{RouteAll: false})})
	got, known := n.CachedPrefs()
	if !known {
		t.Fatal("a delivered preference left the node reporting it had heard nothing")
	}
	if got.RouteAll {
		t.Errorf("accept-routes = %v, want the delivered value", got.RouteAll)
	}

	n.applyNotify(t.Context(), ipn.Notify{Prefs: prefsView(&ipn.Prefs{RouteAll: true})})
	if got, _ := n.CachedPrefs(); !got.RouteAll {
		t.Errorf("accept-routes after a later change = %v, want true", got.RouteAll)
	}

	// One preference is a list, so folding a notification in means comparing lists. A
	// comparison that read two different route sets as the same would leave the node
	// advertising what someone else set while this app reported its own value.
	subnet := netip.MustParsePrefix("10.0.0.0/24")
	n.applyNotify(t.Context(), ipn.Notify{Prefs: prefsView(&ipn.Prefs{
		RouteAll: true, AdvertiseRoutes: []netip.Prefix{subnet},
	})})
	if got, _ := n.CachedPrefs(); !slices.Equal(got.AdvertisedSubnets, []netip.Prefix{subnet}) {
		t.Errorf("advertised subnets after a change made elsewhere = %v, want %v",
			got.AdvertisedSubnets, subnet)
	}
}

// primaryTailnet is a connection of the kind every preference here belongs to.
func primaryTailnet() config.Tunnel {
	t := config.Tunnel{
		ID: config.PrimaryTunnelID, Slug: "tailnet", Name: "Tailnet",
		Type: config.TunnelTailscale, Enabled: true,
	}
	t.Tailscale = &config.TailscaleTunnel{}
	return t
}

// prefsOf is what one connection asks its node for: the preferences it stores with every
// module governing them folded in. Going through config rather than assembling a
// TailnetPrefs here is the point -- the gate is applied in exactly one place, and this is
// what binds the projection in this file to that answer.
func prefsOf(app config.Settings, p config.TailnetPrefs) config.TailnetPrefs {
	held := primaryTailnet()
	held.Tailscale.TailnetPrefs = p
	return app.TailnetPrefsOf(held)
}

// prefsView is a preference value in the read-only form the bus carries.
func prefsView(p *ipn.Prefs) *ipn.PrefsView {
	v := p.View()
	return &v
}

// mustJSON encodes a backend reply body.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode %T: %v", v, err)
	}
	return string(body)
}
