// SPDX-License-Identifier: MIT

//go:build darwin || linux

package hostnet

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The suite's own binary dials its own helper here, so the helper and the caller run the same
// program -- what an installed helper and its agent are.
func TestTheHelperAcceptsItsOwnBinary(t *testing.T) {
	host := &commandedHost{}
	client := dialTo(t, testContext(t), servedByHost(t, host))
	if err := client.RouterUp(testContext(t)); err != nil {
		t.Fatalf("the helper refused its own program: %v", err)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.brought != 1 {
		t.Fatalf("the request reached the privileged side %d times, want once", host.brought)
	}
}

// dialerSource is a program that is not app-tail: it connects to the socket it is given,
// sends one request, and prints the reply.
const dialerSource = `package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

func main() {
	conn, err := net.Dial("unix", os.Args[1])
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(2)
	}
	fmt.Fprintln(conn, ` + "`" + `{"op":"router-up"}` + "`" + `)
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println("read:", err)
		os.Exit(3)
	}
	fmt.Print(line)
}
`

// buildDialer compiles dialerSource into a program of its own.
func buildDialer(t *testing.T) string {
	t.Helper()
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("this test builds a second program and needs the go command: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module dialer\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(dialerSource), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "dialer")
	cmd := exec.Command(gobin, "build", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the second program: %v\n%s", err, out)
	}
	return bin
}

func TestTheHelperRefusesAProcessRunningAnotherBinaryUnderTheOwnersAccount(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the suite runs as root, and root may command the helper whatever it runs")
	}
	dialer := buildDialer(t)
	host := &commandedHost{}
	path := servedByHost(t, host)

	out, err := exec.Command(dialer, path).Output()
	if err != nil {
		t.Fatalf("run the second program: %v\n%s", err, out)
	}
	var resp response
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("read the helper's reply %q: %v", out, err)
	}
	if !strings.Contains(resp.Error, "different program") {
		t.Fatalf("the helper answered %+v, want a refusal for a different program", resp)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.brought != 0 {
		t.Fatal("a request from another program reached the privileged side")
	}
}
