// SPDX-License-Identifier: MIT

package hostnet

import (
	"testing"

	"tailscale.com/health"
	"tailscale.com/util/eventbus"
)

// The tracker is handed to the router and to the resolver, and both report through it
// rather than returning what they find. A tracker with nothing to publish through takes
// the process down at the first report -- and the first report is never made where the
// tracker is built: on Windows the router raises one from a goroutine of its own when
// configuring the interface runs long, so the crash lands after the interface is up, with
// nothing on the stack naming the line that built it.
//
// A report is made here for that reason. Asserting the tracker is non-nil would pass on
// the zero value that caused this.
func TestTheHealthTrackerCanCarryAReport(t *testing.T) {
	bus := eventbus.New()
	t.Cleanup(bus.Close)

	tracker := healthTracker(bus)
	if tracker == nil {
		t.Fatal("no health tracker was built for the router and the resolver to report through")
	}

	// TimeToVisible left at zero so the report is published as it is made rather than
	// parked on a timer, which is the path the router's own report takes.
	warnable := &health.Warnable{
		Code:     "app-tail-test-report",
		Severity: health.SeverityMedium,
		Text:     health.StaticMessage("a report the router would make while configuring the interface"),
	}
	tracker.SetUnhealthy(warnable, nil)
	tracker.SetHealthy(warnable)
}
