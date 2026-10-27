// SPDX-License-Identifier: MIT

package sysdns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

// Linux is served through systemd-resolved and through nothing else.
//
// resolvectl sets a per-link resolver at run time, which is revertible in one command and
// survives nothing -- exactly the properties this wants. The other shapes a Linux machine
// takes -- a resolv.conf written by NetworkManager, by dhclient, by a hand-rolled script,
// or a symlink into a container runtime -- have no such seam, and the only way to override
// them is to rewrite the file. Guessing at which one wrote it from outside is how a working
// resolv.conf gets replaced with a broken one, so this refuses instead, in the same terms
// the interface mode already refuses an unknown Linux.

// resolvectlPaths is every place a Linux machine keeps resolvectl, in the order they are
// tried. The list is fixed on purpose: this program runs commands that repoint the whole
// machine's name resolution, and a name looked up through PATH is a name whoever set the
// environment chose. A distribution that keeps it somewhere else is told so by supported(),
// which is a sentence the user can act on rather than a lookup that quietly finds something
// else.
var resolvectlPaths = []string{
	"/usr/bin/resolvectl",
	// Where a distribution that predates the usr-merge keeps it.
	"/bin/resolvectl",
	// NixOS and Guix build the system's programs into a profile rather than into /usr.
	"/run/current-system/sw/bin/resolvectl",
}

// resolvedUnit exists on a machine running systemd-resolved and on no other.
const resolvedUnit = "/run/systemd/resolve/resolv.conf"

// DefaultRecordPath is where the record lives on Linux: a root-owned directory, because a
// file a user can edit is a list of addresses root will point this machine at later.
func DefaultRecordPath() string { return "/var/lib/app-tail/" + RecordFileName }

func newMachineResolver(logf func(format string, args ...any)) machineResolver {
	return linuxResolver{logf: logf}
}

type linuxResolver struct {
	logf func(format string, args ...any)
}

func (l linuxResolver) supported() (bool, string) {
	if resolvectl() == "" {
		return false, "app-tail can only change this machine's resolver through systemd-resolved, and resolvectl is not at any of " +
			strings.Join(resolvectlPaths, ", ") + " on this machine. " +
			"Point your resolver at app-tail by hand, or run a resolver that app-tail can drive."
	}
	if _, err := os.Stat(resolvedUnit); err != nil {
		return false, "app-tail can only change this machine's resolver through systemd-resolved, which is not running here. " +
			"Rewriting whatever wrote /etc/resolv.conf from outside is how a working resolver configuration gets broken, so app-tail will not do it."
	}
	return true, ""
}

func resolvectl() string {
	for _, path := range resolvectlPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

// services lists the links carrying an address. resolved keeps a resolver per link, which
// is the same shape as a network service everywhere else.
func (l linuxResolver) services(ctx context.Context) ([]Service, error) {
	out, err := runLinux(ctx, "--no-pager", "status")
	if err != nil {
		return nil, fmt.Errorf("list this machine's links: %w", err)
	}
	var services []Service
	for _, line := range strings.Split(out, "\n") {
		// "Link 2 (enp0s1)" heads each link's section.
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Link ")
		if !ok {
			continue
		}
		index, name, ok := strings.Cut(rest, " (")
		if !ok {
			continue
		}
		name = strings.TrimSuffix(name, ")")
		if name == "" || isTailnetLink(name) {
			continue
		}
		services = append(services, Service{ID: strings.TrimSpace(index), Name: name})
	}
	return services, nil
}

// isTailnetLink reports an interface a tailnet client owns. Pointing one at app-tail's
// resolver would put the tailnet's own name resolution behind the forwarder meant to sit
// beside it.
func isTailnetLink(name string) bool {
	return strings.HasPrefix(name, "tailscale") || strings.HasPrefix(name, "app-tail") || strings.HasPrefix(name, "utun")
}

// get reads the resolvers set on one link, which resolvectl reports as the current DNS
// servers for that link.
func (l linuxResolver) get(ctx context.Context, s Service) ([]netip.Addr, error) {
	out, err := runLinux(ctx, "dns", s.Name)
	if err != nil {
		return nil, err
	}
	// "Link 2 (enp0s1): 1.1.1.1 1.0.0.1", or nothing after the colon when none is set.
	_, list, ok := strings.Cut(out, ":")
	if !ok {
		return nil, nil
	}
	var addrs []netip.Addr
	for _, field := range strings.Fields(list) {
		if addr, err := netip.ParseAddr(field); err == nil {
			addrs = append(addrs, addr)
		}
	}
	return addrs, nil
}

// set points a link at the addresses. An empty list hands the link back to whatever
// configured it, which is what resolvectl does with no addresses at all.
func (l linuxResolver) set(ctx context.Context, s Service, addrs []netip.Addr) error {
	args := []string{"dns", s.Name}
	for _, a := range addrs {
		args = append(args, a.String())
	}
	if _, err := runLinux(ctx, args...); err != nil {
		return err
	}
	return nil
}

// base reads what a link was given by its own network, which resolved keeps separately
// from the runtime override this package writes.
func (l linuxResolver) base(ctx context.Context, s Service) (Base, error) {
	out, err := runLinux(ctx, "--no-pager", "status", s.Name)
	if err != nil {
		return Base{}, err
	}
	var base Base
	section := ""
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if key, value, ok := strings.Cut(line, ": "); ok {
			section = strings.TrimSpace(key)
			line = strings.TrimSpace(value)
		}
		switch section {
		case "DNS Servers", "Current DNS Server":
			for _, field := range strings.Fields(line) {
				if addr, err := netip.ParseAddr(field); err == nil && !containsAddr(base.Nameservers, addr) {
					base.Nameservers = append(base.Nameservers, addr)
				}
			}
		case "DNS Domain":
			for _, field := range strings.Fields(line) {
				if field != "" && field != "~." {
					base.SearchDomains = append(base.SearchDomains, strings.TrimPrefix(field, "~"))
				}
			}
		}
	}
	return base, nil
}

func containsAddr(list []netip.Addr, addr netip.Addr) bool {
	for _, a := range list {
		if a == addr {
			return true
		}
	}
	return false
}

// flush drops resolved's cache so the change is visible to the next lookup rather than to
// the one after the old entries expire.
func (l linuxResolver) flush(ctx context.Context) error {
	_, err := runLinux(ctx, "flush-caches")
	return err
}

// holdLoopback and releaseLoopback refuse: Linux assigns the whole of 127/8 to the loopback
// interface, so every address app-tail listens on is already bindable and an address it
// could not bind was refused for some other reason -- something else holding it, or a
// namespace that does not carry loopback. Adding an address here to paper over that would
// change this machine for a reason that was never diagnosed.
func (l linuxResolver) holdLoopback(_ context.Context, addr netip.Addr) error {
	return fmt.Errorf("this machine already carries every loopback address, so app-tail could not listen on %s for another reason", addr)
}

func (l linuxResolver) releaseLoopback(context.Context, netip.Addr) error {
	return errors.New("app-tail never adds a loopback address on Linux, so there is none to give back")
}

func runLinux(ctx context.Context, args ...string) (string, error) {
	path := resolvectl()
	if path == "" {
		return "", fmt.Errorf("resolvectl is not installed on this machine")
	}
	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if text == "" {
			return "", fmt.Errorf("resolvectl %s: %w", strings.Join(args, " "), err)
		}
		return "", fmt.Errorf("resolvectl %s: %w: %s", strings.Join(args, " "), err, text)
	}
	return string(out), nil
}
