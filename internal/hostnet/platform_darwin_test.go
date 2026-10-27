// SPDX-License-Identifier: MIT

package hostnet

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/net/tstun"
)

// The name app-tail asks for has to be one this platform's interface creator will take.
// A name it rejects is refused before any interface exists, so the node has already torn
// down its contained self by the time anyone finds out.
//
// Checked against that creator rather than against a copy of its rule: the rule lives in
// the dependency, and a copy here would go on passing after the dependency changed it.
func TestTheDefaultInterfaceNameIsOneThisPlatformWillCreate(t *testing.T) {
	dev, _, err := tstun.New(func(string, ...any) {}, DefaultInterfaceName())
	if err == nil {
		// This machine holds the rights and really made one. It exists only as this
		// reference, carries no address and no route, and goes away with the close.
		if closeErr := dev.Close(); closeErr != nil {
			t.Errorf("close the interface this test created: %v", closeErr)
		}
		return
	}
	// Every other failure is this test process lacking the rights, which says nothing
	// about the name and is the ordinary case.
	if strings.Contains(err.Error(), "Interface name") {
		t.Errorf("the interface app-tail asks for is refused before it is created: %v", err)
	}
}

// The packaged Tailscale clients run their tailnet inside a network system extension and leave
// no socket anywhere this side can see, so a machine holding a second tailnet would be reported
// as holding one with nothing to name. The lookup is what is checked rather than the table of
// names: pgrep's own idea of a process name truncates on some systems, and a table checked
// against a copy of that rule would go on passing on a machine where the lookup finds nothing.
func TestTheClientDrivingATailnetIsNamedByItsRunningProcess(t *testing.T) {
	for _, name := range conflictingProcesses {
		t.Run(name, func(t *testing.T) {
			if found := runningTailnetClient(t.Context()); found != "" {
				// A client this test did not start makes its own result unattributable.
				t.Skipf("this machine is already running %s, so a started one proves nothing", found)
			}

			// A copy of a system program that does nothing but wait, under the name being
			// looked for. It holds no rights and touches nothing.
			path := filepath.Join(t.TempDir(), name)
			body, err := os.ReadFile("/bin/sleep")
			if err != nil {
				t.Fatalf("read the program to run under the name being looked for: %v", err)
			}
			if err := os.WriteFile(path, body, 0o755); err != nil {
				t.Fatalf("write it under that name: %v", err)
			}
			cmd := exec.Command(path, "60")
			if err := cmd.Start(); err != nil {
				t.Fatalf("start a process named %q: %v", name, err)
			}
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				_, _ = cmd.Process.Wait()
			})

			if found := runningTailnetClient(t.Context()); found != name {
				t.Errorf("the client driving the tailnet was named %q, want %q -- a conflict that "+
					"cannot say which client holds it is one a user cannot act on", found, name)
			}
		})
	}
}

// A resident network extension is not a conflict on its own, and this is the case that makes
// the difference visible: macOS keeps the packaged client's extension running after the app is
// quit, so a machine with nothing connected to a tailnet still has that process on it. Refusing
// the mode there sends a user looking for a client they have already quit.
func TestAClientThatHoldsNoTailnetIsNotAConflict(t *testing.T) {
	if said := DetectConflict(t.Context(), ""); said != "" {
		// Reported rather than passed over: it is also the machine this suite is running on.
		t.Skipf("this machine is holding a tailnet, so nothing here can be attributed: %s", said)
	}
	if found := runningTailnetClient(t.Context()); found == "" {
		t.Skip("no tailnet client is running on this machine, so there is nothing resident to pass over")
	}
	if said := DetectConflict(t.Context(), ""); said != "" {
		t.Errorf("a client that holds no tailnet was refused: %s", said)
	}
}

// The sentence is the whole of what a user gets. It has to name the interface and the address
// that were found -- so the finding can be checked against the machine -- and where the switch
// is, because quitting the app is what people try first and it does not disconnect the extension.
func TestTheConflictSaysWhatWasFoundAndWhereToTurnItOff(t *testing.T) {
	said := conflictWith("io.tailscale.ipn.macsys.network-extension", "utun4", "100.72.90.28")

	for _, want := range []string{
		"io.tailscale.ipn.macsys.network-extension",
		"utun4",
		"100.72.90.28",
		"Network Extensions",
	} {
		if !strings.Contains(said, want) {
			t.Errorf("the conflict reported does not name %q: %s", want, said)
		}
	}

	// A tailnet nobody claims is still a conflict, and still has to read as one sentence.
	unclaimed := conflictWith("", "utun7", "100.64.1.1")
	if !strings.Contains(unclaimed, "utun7") || !strings.Contains(unclaimed, "100.64.1.1") {
		t.Errorf("a tailnet with no client to name lost what was found: %s", unclaimed)
	}
	if strings.Contains(unclaimed, "()") {
		t.Errorf("a tailnet with no client to name left an empty name in the sentence: %s", unclaimed)
	}
}
