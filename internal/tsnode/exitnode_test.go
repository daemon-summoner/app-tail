// SPDX-License-Identifier: MIT

package tsnode

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

var probed = netip.MustParseAddr("100.64.0.9")

// A hosted exit node is one of thirty in a picker, so the place is the only thing that
// tells them apart and it has to survive the trip out of the backend's types.
func TestASuggestionKeepsTheDeviceAndWhereItIs(t *testing.T) {
	got := suggestionOf(apitype.ExitNodeSuggestionResponse{
		ID:       "nXYZ",
		Name:     "mullvad-berlin",
		Location: (&tailcfg.Location{Country: "Germany", CountryCode: "DE", City: "Berlin"}).View(),
	})

	want := Suggestion{
		ID:       "nXYZ",
		Name:     "mullvad-berlin",
		Location: PeerLocation{Country: "Germany", CountryCode: "DE", City: "Berlin"},
	}
	if got != want {
		t.Errorf("suggestionOf = %+v, want %+v", got, want)
	}
}

// A device someone runs themselves has no location at all, and reading one out of an
// invalid view would panic rather than leave the place empty.
func TestASuggestedDeviceWithNoPlaceIsStillASuggestion(t *testing.T) {
	got := suggestionOf(apitype.ExitNodeSuggestionResponse{ID: "nHOME", Name: "home-router"})

	if got.ID != "nHOME" || got.Name != "home-router" {
		t.Errorf("suggestionOf = %+v, want the device named", got)
	}
	if got.Location != (PeerLocation{}) {
		t.Errorf("location = %+v, want none for a device the tailnet places nowhere", got.Location)
	}
}

// The tailnet having nothing to suggest is an answer, not a failure: the caller turns an
// empty id into a sentence, which it cannot do if this invents one.
func TestNoSuggestionIsAnEmptyOneRatherThanAnInvention(t *testing.T) {
	if got := suggestionOf(apitype.ExitNodeSuggestionResponse{}); got != (Suggestion{}) {
		t.Errorf("suggestionOf = %+v, want an empty suggestion", got)
	}
}

// The whole point of asking the tailnet rather than picking a device ourselves is that
// the answer names one; a suggestion that lost the device on the way out of the backend
// would leave the button doing nothing anybody can see.
func TestTheTailnetsSuggestionArrivesAsTheDeviceItNamed(t *testing.T) {
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return jsonResponse(`{"ID":"nMULLVAD","Name":"mullvad-berlin"}`), nil
	})

	got, err := n.SuggestExitNode(t.Context())
	if err != nil {
		t.Fatalf("SuggestExitNode: %v", err)
	}
	if got.ID != "nMULLVAD" || got.Name != "mullvad-berlin" {
		t.Errorf("SuggestExitNode = %+v, want the device the tailnet named", got)
	}
}

// A tailnet whose only exit nodes are self-hosted refuses this outright, which is the
// common case rather than an exotic one. Reported as an empty suggestion it would read as
// "your tailnet has no exit node", which is a different and wrong statement.
func TestARefusedSuggestionCarriesTheTailnetsOwnReason(t *testing.T) {
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return errorResponse(http.StatusInternalServerError, "no exit node suggestion available"), nil
	})

	got, err := n.SuggestExitNode(t.Context())
	if err == nil {
		t.Fatalf("SuggestExitNode = %+v with no error, want the tailnet's refusal", got)
	}
	if !strings.Contains(err.Error(), "no exit node suggestion available") {
		t.Errorf("error = %v, want it to carry the tailnet's own reason", err)
	}
	if got != (Suggestion{}) {
		t.Errorf("SuggestExitNode = %+v beside an error, want no suggestion at all", got)
	}
}

func TestAMeasuredRoundTripIsReportedAsATime(t *testing.T) {
	got, err := roundTripOf(probed, &ipnstate.PingResult{LatencySeconds: 0.025})
	if err != nil {
		t.Fatalf("roundTripOf: %v", err)
	}
	if got != 25*time.Millisecond {
		t.Errorf("roundTripOf = %v, want 25ms", got)
	}
}

// Every one of these has to be an error rather than a zero: zero sorts ahead of every
// device that did answer, so a failed measurement would win the latency strategy outright.
func TestAMeasurementThatDidNotHappenIsAFailureRatherThanZero(t *testing.T) {
	cases := []struct {
		name string
		res  *ipnstate.PingResult
		want string
	}{
		{
			name: "the backend answered with nothing",
			res:  nil,
			want: "no result",
		},
		{
			name: "the ping itself failed",
			res:  &ipnstate.PingResult{Err: "no matching peer"},
			want: "no matching peer",
		},
		{
			name: "the device answered without a round trip",
			res:  &ipnstate.PingResult{},
			want: "no round trip was measured",
		},
		{
			name: "the round trip came back negative",
			res:  &ipnstate.PingResult{LatencySeconds: -1},
			want: "no round trip was measured",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := roundTripOf(probed, tc.res)
			if err == nil {
				t.Fatalf("roundTripOf = %v with no error, want the reason no measurement was made", got)
			}
			if got != 0 {
				t.Errorf("roundTripOf = %v beside an error, want no measurement at all", got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error is %q, want it to say %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), probed.String()) {
				t.Errorf("error is %q, want it to name the device measured", err)
			}
		})
	}
}
