// SPDX-License-Identifier: MIT

package sysdns

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// macOS keeps two copies of a service's resolver setting in different places, and this
// package depends on that: Setup:/Network/Service/<id>/DNS is the persisted override,
// written by networksetup and by the Network pane, and State:/Network/Service/<id>/DNS is
// what the DHCP client learned. Nothing writes the second one but the system, so it still
// holds the network's own resolvers while app-tail's override is in place -- which is what
// makes the network's own names resolvable at the same time as the user's chosen resolver.
//
// /etc/resolv.conf is the merged result of the two and is therefore the wrong place to read
// a base from: with the override installed it reports app-tail's own address.

const (
	scutilPath       = "/usr/sbin/scutil"
	networksetupPath = "/usr/sbin/networksetup"
	// dsCacheUtilPath and mDNSResponder are how a resolver change is made to take effect.
	// Without the flush the machine answers from its cache, which reads as a switch that
	// did nothing.
	dsCacheUtilPath = "/usr/bin/dscacheutil"
	killallPath     = "/usr/bin/killall"
	// ifconfigPath and loopbackInterface are how an address other than 127.0.0.1 is made
	// bindable here: macOS assigns that one address and refuses the rest of 127/8.
	ifconfigPath      = "/sbin/ifconfig"
	loopbackInterface = "lo0"
)

// DefaultRecordPath is where the record lives on macOS: a root-owned directory, because a
// file a user can edit is a list of addresses root will point this machine at later.
func DefaultRecordPath() string { return "/var/db/app-tail/" + RecordFileName }

func newMachineResolver(logf func(format string, args ...any)) machineResolver {
	return darwinResolver{logf: logf, run: execRun}
}

// runner executes one of the machine's own tools. The resolver holds one rather than calling
// exec directly so that what this package does to a machine -- which service it writes, with
// which arguments, and what it does with the answer -- can be exercised without a machine to
// change.
type runner func(ctx context.Context, path string, args []string, stdinLines ...string) (string, error)

type darwinResolver struct {
	logf func(format string, args ...any)
	run  runner
}

func (d darwinResolver) supported() (bool, string) { return true, "" }

// services lists the network services with an address right now.
//
// Only the active ones: a laptop carries a dozen services -- every ethernet adapter it has
// ever seen, every VPN -- and writing to all of them is a dozen shell-outs to change
// nothing. The inactive ones also cannot resolve anything, so an override on them is a
// setting that does nothing until the next time that port is used, which is precisely when
// nobody is expecting app-tail to be in the path.
func (d darwinResolver) services(ctx context.Context) ([]Service, error) {
	ids, err := d.activeServiceIDs(ctx)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, "Setup:/Network/Service/"+id)
	}
	dicts, err := d.scutilShow(ctx, keys)
	if err != nil {
		return nil, err
	}
	out := make([]Service, 0, len(ids))
	for i, id := range ids {
		name := ""
		if dicts[i] != nil {
			name = dicts[i].value("UserDefinedName")
		}
		if name == "" {
			// A service with no name of its own cannot be handed to networksetup, which
			// takes the name and nothing else.
			d.logf("skipping the network service %s: it has no name for networksetup to take", id)
			continue
		}
		if isTailnetService(name) {
			continue
		}
		out = append(out, Service{ID: id, Name: name})
	}
	return out, nil
}

// isTailnetService reports a service belonging to a tailnet client, app-tail's own
// included. Pointing one of those at app-tail's resolver would put the tailnet's own name
// resolution behind the forwarder that is meant to sit beside it.
func isTailnetService(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "tailscale") || strings.Contains(lower, "app-tail")
}

// activeServiceIDs lists the services carrying an address, over either protocol.
func (d darwinResolver) activeServiceIDs(ctx context.Context) ([]string, error) {
	out, err := d.run(ctx, scutilPath, nil,
		"list State:/Network/Service/[^/]+/IPv4",
		"list State:/Network/Service/[^/]+/IPv6",
	)
	if err != nil {
		return nil, fmt.Errorf("list this machine's active network services: %w", err)
	}
	var ids []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(out, "\n") {
		_, key, ok := strings.Cut(line, "= ")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		rest, ok := strings.CutPrefix(key, "State:/Network/Service/")
		if !ok {
			continue
		}
		id, _, ok := strings.Cut(rest, "/")
		if !ok || id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, nil
}

// get reads the override layer: what networksetup would report, and nothing the system
// filled in.
func (d darwinResolver) get(ctx context.Context, s Service) ([]netip.Addr, error) {
	dicts, err := d.scutilShow(ctx, []string{"Setup:/Network/Service/" + s.ID + "/DNS"})
	if err != nil {
		return nil, err
	}
	if dicts[0] == nil {
		// No override key at all, which is the state of a machine following its network.
		return nil, nil
	}
	return parseAddrs(dicts[0].array("ServerAddresses")), nil
}

// set writes the override, or removes it when addrs is empty.
//
// networksetup rather than scutil: writing the Setup: key directly leaves the preferences
// file and the running configuration disagreeing until something else reloads it, and
// "Empty" is the documented way to say "follow the network again".
func (d darwinResolver) set(ctx context.Context, s Service, addrs []netip.Addr) error {
	name, err := d.currentName(ctx, s)
	if err != nil {
		return err
	}
	args := []string{"-setdnsservers", name}
	if len(addrs) == 0 {
		args = append(args, "Empty")
	} else {
		for _, a := range addrs {
			args = append(args, a.String())
		}
	}
	if _, err := d.run(ctx, networksetupPath, args); err != nil {
		return err
	}
	return nil
}

// currentName is the name networksetup knows a service by now. The record keeps the name it
// had when the record was written, and a rename since then would point networksetup at a
// service that no longer exists under it; the id is what survives the rename.
func (d darwinResolver) currentName(ctx context.Context, s Service) (string, error) {
	dicts, err := d.scutilShow(ctx, []string{"Setup:/Network/Service/" + s.ID})
	if err != nil {
		return "", err
	}
	if dicts[0] != nil {
		if name := dicts[0].value("UserDefinedName"); name != "" {
			return name, nil
		}
	}
	return s.Name, nil
}

// base reads what the network itself published for a service.
func (d darwinResolver) base(ctx context.Context, s Service) (Base, error) {
	dicts, err := d.scutilShow(ctx, []string{
		"State:/Network/Service/" + s.ID + "/DNS",
		"State:/Network/Service/" + s.ID + "/DHCP",
	})
	if err != nil {
		return Base{}, err
	}
	var out Base
	if dns := dicts[0]; dns != nil {
		out.Nameservers = parseAddrs(dns.array("ServerAddresses"))
		out.SearchDomains = dns.array("SearchDomains")
		if domain := dns.value("DomainName"); domain != "" {
			out.SearchDomains = append(out.SearchDomains, domain)
		}
	}
	if len(out.Nameservers) == 0 && dicts[1] != nil {
		// A service whose resolver came straight from DHCP without configd copying it
		// into the DNS key. The option carries the same addresses in their wire form.
		out.Nameservers = parseDHCPAddresses(dicts[1].value("Option_6"))
		if domain := dhcpText(dicts[1].value("Option_15")); domain != "" {
			out.SearchDomains = append(out.SearchDomains, domain)
		}
	}
	return out, nil
}

// flush makes a resolver change take effect now rather than when the cache expires.
func (d darwinResolver) flush(ctx context.Context) error {
	if _, err := d.run(ctx, dsCacheUtilPath, []string{"-flushcache"}); err != nil {
		return err
	}
	// The responder holds its own copy of the configuration and its own cache, and only
	// the signal makes it read the new one.
	if _, err := d.run(ctx, killallPath, []string{"-HUP", "mDNSResponder"}); err != nil {
		return err
	}
	return nil
}

// holdLoopback aliases one address onto lo0 so app-tail can listen on it.
//
// The mask is a single address rather than the interface's own /8: an alias carrying the
// whole range would restate the loopback route, and this exists to add one address, not to
// take a position on where 127/8 goes.
func (d darwinResolver) holdLoopback(ctx context.Context, addr netip.Addr) error {
	if !addr.Is4() {
		return fmt.Errorf("app-tail listens for DNS on an IPv4 loopback address, and %s is not one", addr)
	}
	if _, err := d.run(ctx, ifconfigPath, []string{
		loopbackInterface, "alias", addr.String(), "netmask", "255.255.255.255", "up",
	}); err != nil {
		return fmt.Errorf("add %s to this machine's loopback interface: %w", addr, err)
	}
	d.logf("added %s to %s so app-tail can listen for DNS there", addr, loopbackInterface)
	return nil
}

// releaseLoopback takes the alias back off lo0.
//
// An address the interface does not carry is the state this wants, so a refusal is checked
// against the interface rather than reported: a reboot drops every alias, and a restore that
// failed on "it is already gone" would keep the record on disk and repeat forever.
func (d darwinResolver) releaseLoopback(ctx context.Context, addr netip.Addr) error {
	_, removeErr := d.run(ctx, ifconfigPath, []string{loopbackInterface, "-alias", addr.String()})
	if removeErr == nil {
		return nil
	}
	out, err := d.run(ctx, ifconfigPath, []string{loopbackInterface})
	if err != nil {
		return fmt.Errorf("remove %s from this machine's loopback interface: %w", addr, errors.Join(removeErr, err))
	}
	if loopbackCarries(out, addr) {
		return fmt.Errorf("remove %s from this machine's loopback interface: %w", addr, removeErr)
	}
	return nil
}

// loopbackCarries reports whether ifconfig's output for one interface lists addr.
func loopbackCarries(out string, addr netip.Addr) bool {
	family := "inet"
	if addr.Is6() {
		family = "inet6"
	}
	for _, raw := range strings.Split(out, "\n") {
		fields := strings.Fields(raw)
		if len(fields) < 2 || fields[0] != family {
			continue
		}
		// An IPv6 address is printed with its zone attached, which is not part of the
		// address the caller asked about.
		text, _, _ := strings.Cut(fields[1], "%")
		if got, err := netip.ParseAddr(text); err == nil && got == addr {
			return true
		}
	}
	return false
}

// scutilDict is one dictionary scutil printed.
type scutilDict struct {
	scalars map[string]string
	arrays  map[string][]string
}

func (d *scutilDict) value(key string) string { return d.scalars[key] }

func (d *scutilDict) array(key string) []string {
	if v, ok := d.arrays[key]; ok {
		return v
	}
	// A single-valued key where an array was expected is the same answer with one entry,
	// and scutil prints it either way depending on what wrote it.
	if v, ok := d.scalars[key]; ok && v != "" {
		return []string{v}
	}
	return nil
}

// scutilShow reads several keys in one invocation and returns one entry per key, in order,
// with nil for a key that does not exist.
//
// One invocation rather than one per key: each is a process launch, and this runs on a
// path a user is waiting on.
func (d darwinResolver) scutilShow(ctx context.Context, keys []string) ([]*scutilDict, error) {
	commands := make([]string, 0, len(keys))
	for _, key := range keys {
		commands = append(commands, "show "+key)
	}
	out, err := d.run(ctx, scutilPath, nil, commands...)
	if err != nil {
		return nil, fmt.Errorf("read this machine's network configuration: %w", err)
	}
	dicts := parseScutil(out)
	if len(dicts) != len(keys) {
		return nil, fmt.Errorf("asked scutil for %d keys and it answered about %d", len(keys), len(dicts))
	}
	return dicts, nil
}

// parseScutil turns scutil's output into one entry per command, nil where the key was
// missing. Nested dictionaries are skipped rather than flattened: nothing here reads one,
// and flattening would collide keys from different levels.
func parseScutil(out string) []*scutilDict {
	var dicts []*scutilDict
	var current *scutilDict
	var arrayKey string
	depth := 0

	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "":
			continue
		case line == "No such key":
			if depth == 0 {
				dicts = append(dicts, nil)
			}
			continue
		case line == "<dictionary> {" && depth == 0:
			current = &scutilDict{scalars: map[string]string{}, arrays: map[string][]string{}}
			depth = 1
			continue
		case line == "}":
			depth--
			if depth == 1 {
				arrayKey = ""
			}
			if depth == 0 {
				dicts = append(dicts, current)
				current = nil
			}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, " : ")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case depth == 2 && arrayKey != "":
			current.arrays[arrayKey] = append(current.arrays[arrayKey], value)
		case depth != 1:
			continue
		case value == "<array> {":
			arrayKey = key
			current.arrays[key] = nil
			depth = 2
		case strings.HasSuffix(value, "{"):
			// A nested dictionary. Counted so the closing brace lands where it should.
			depth = 2
		default:
			current.scalars[key] = value
		}
	}
	return dicts
}

// parseDHCPAddresses reads the DNS server option, which scutil prints as one hex blob of
// four-byte addresses.
func parseDHCPAddresses(value string) []netip.Addr {
	raw, ok := dhcpBytes(value)
	if !ok || len(raw)%4 != 0 {
		return nil
	}
	out := make([]netip.Addr, 0, len(raw)/4)
	for i := 0; i+4 <= len(raw); i += 4 {
		out = append(out, netip.AddrFrom4([4]byte(raw[i:i+4])))
	}
	return out
}

// dhcpText reads a text-valued DHCP option.
func dhcpText(value string) string {
	raw, ok := dhcpBytes(value)
	if !ok {
		return ""
	}
	return strings.TrimRight(string(raw), "\x00")
}

// dhcpBytes decodes the "<data> 0x..." form scutil prints an option in.
func dhcpBytes(value string) ([]byte, bool) {
	body, ok := strings.CutPrefix(value, "<data> 0x")
	if !ok {
		return nil, false
	}
	raw, err := hex.DecodeString(strings.TrimSpace(body))
	if err != nil {
		return nil, false
	}
	return raw, true
}

// execRun executes one of the system tools, sending stdin lines to those that read commands
// that way. A failure carries the tool's own output, which is where the reason is.
func execRun(ctx context.Context, path string, args []string, stdinLines ...string) (string, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	if len(stdinLines) > 0 {
		cmd.Stdin = strings.NewReader(strings.Join(stdinLines, "\n") + "\nquit\n")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if text == "" {
			return "", fmt.Errorf("%s: %w", path, err)
		}
		return "", fmt.Errorf("%s: %w: %s", path, err, text)
	}
	return string(out), nil
}
