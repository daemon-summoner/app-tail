// SPDX-License-Identifier: MIT

package sysdns

import (
	"context"
	"slices"
	"testing"
)

// The record is the only thing that stops app-tail recording its own address as the user's
// setting, and a record can be lost while the override stands -- deleted by hand, or written
// to a path one run could not work out. Reaching an apply in that state and believing the
// machine is what makes the mistake permanent: every later restore would then write a
// loopback address nothing answers on as a static setting, which survives the reboot and the
// uninstall, with every repair reporting success.
func TestAppTailNeverRecordsItsOwnAddressAsWhatTheUserHad(t *testing.T) {
	ours := addrs("127.0.0.153")
	wifi := state{Service: Service{ID: "wifi-id", Name: "Wi-Fi"}, Current: ours}

	changes := plan([]state{wifi}, ours, record{})
	if len(changes) != 1 {
		t.Fatalf("planned %d changes, want one", len(changes))
	}
	if got := changes[0].Prior; got != nil {
		t.Errorf("app-tail recorded %v as what the user had, which is its own address", got)
	}
}

// The half that matters on the machine: with no record and the override already standing, a
// restore must hand the service back to its network rather than write app-tail's address as a
// permanent one.
func TestAMachineWithNoRecordLeftIsRestoredToItsOwnNetworksResolvers(t *testing.T) {
	m, machine := newTestManager(t)
	ctx := context.Background()
	ours := addrs("127.0.0.153")
	machine.current["wifi-id"] = slices.Clone(ours)
	machine.current["eth-id"] = slices.Clone(ours)

	if err := m.Apply(ctx, ours); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := m.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	for _, id := range []string{"wifi-id", "eth-id"} {
		if got, ok := machine.current[id]; ok {
			t.Errorf("%s still resolves through %v, want its network's own resolvers", id, got)
		}
	}
}

// app-tail moves between loopback addresses, so a service that app-tail's record has not met
// yet can already be on one it wrote earlier -- the helper restarted with a new service up,
// for one. That address is app-tail's too, and recording it as the user's would make every
// later restore write it back as a static setting nothing answers on.
func TestAnAddressAppTailWroteEarlierIsNeverRecordedAsWhatTheUserHad(t *testing.T) {
	rec := record{Services: map[string]serviceRecord{}, Ours: []string{"127.0.0.153", "127.0.0.154"}}
	eth := state{Service: Service{ID: "eth-id", Name: "Ethernet"}, Current: addrs("127.0.0.153")}
	vpn := state{Service: Service{ID: "vpn-id", Name: "VPN"}, Current: addrs("10.9.9.9")}

	changes := plan([]state{eth, vpn}, addrs("127.0.0.154"), rec)

	if got := changes[0].Prior; got != nil {
		t.Errorf("app-tail recorded %v as what Ethernet had, which is its own earlier address", got)
	}
	if got := changes[1].Prior; !slices.Equal(got, addrs("10.9.9.9")) {
		t.Errorf("the VPN's own %v was recorded as %v", addrs("10.9.9.9"), got)
	}
}
