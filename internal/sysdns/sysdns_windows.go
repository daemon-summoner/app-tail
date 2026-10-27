// SPDX-License-Identifier: MIT

package sysdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows keeps a static resolver and a DHCP-learned one in separate registry values under
// the same key, and this package depends on that: NameServer is the override, and
// DhcpNameServer is what the network handed out. Setting the first does not touch the
// second, so the network's own resolvers stay readable while app-tail's override is in
// place -- which is what makes the network's own names resolvable at the same time as the
// user's chosen resolver.
//
// The override itself is written with netsh rather than by writing NameServer directly: the
// value alone does not take effect until the stack is told to reread it, and netsh is what
// tells it.

const (
	// adapterClass is the network adapter class whose subkeys carry the friendly names.
	adapterClass = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}`
	// tcpipInterfaces is where each adapter's IPv4 settings live.
	tcpipInterfaces = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
)

// DefaultRecordPath is where the record lives on Windows: in app-tail's own folder under
// ProgramData, narrowed to the administrators when it is created, because a file a user can
// edit is a list of addresses an elevated process will point this machine at later.
//
// Windows is asked where that folder is rather than the environment, for the reason
// systemProgram does not read %SystemRoot%: the elevated process inherits the environment of
// the session that started it, so a %ProgramData% a standard account set in HKCU\Environment
// would decide where an elevated app-tail reads its instructions from. KF_FLAG_DEFAULT_PATH
// asks for the folder's registered location rather than a redirected one.
//
// A machine that cannot answer at all is the empty string, which every caller turns into a
// path under the state directory instead. There is no hard-coded C:\ProgramData: a machine
// that has ProgramData somewhere else is exactly the machine a guess would be wrong about.
func DefaultRecordPath() string {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT_PATH)
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "app-tail", RecordFileName)
}

func newMachineResolver(logf func(format string, args ...any)) machineResolver {
	return windowsResolver{logf: logf, run: execRun, values: interfaceValue, names: adapterName, flags: interfaceFlag}
}

// runner is how the system tools are reached, so a test can watch what would be run
// without repointing the machine it runs on.
type runner func(ctx context.Context, path string, args []string) (string, error)

// valueReader is how an adapter's stored TCP/IP settings are read. The live one reads
// HKLM, which is this machine's own network configuration.
type valueReader func(guid, name string) (string, error)

// nameReader is how an adapter's current friendly name is read from the identifier a record
// was written under.
type nameReader func(guid string) (string, error)

// flagReader is how one of an adapter's numeric TCP/IP settings is read. Whether the value
// was there at all is reported separately, because zero is a setting somebody chose and its
// absence is a different answer.
type flagReader func(guid, name string) (uint64, bool, error)

type windowsResolver struct {
	logf   func(format string, args ...any)
	run    runner
	values valueReader
	names  nameReader
	flags  flagReader
}

func (w windowsResolver) supported() (bool, string) { return true, "" }

// services lists the adapters that are up and carrying an address, by the friendly name
// netsh takes and the GUID the registry is keyed by.
func (w windowsResolver) services(ctx context.Context) ([]Service, error) {
	live, err := liveAdapterNames()
	if err != nil {
		return nil, err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, adapterClass, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("read this machine's network adapters: %w", err)
	}
	defer key.Close()
	guids, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("list this machine's network adapters: %w", err)
	}

	var out []Service
	for _, guid := range guids {
		name, err := adapterName(guid)
		if err != nil {
			// Not every subkey under the adapter class carries a Connection\Name, and one
			// that does not is not an adapter this can act on. Any other failure is an
			// adapter this machine has and app-tail did not see, which is an adapter left
			// resolving through whatever it resolved through with nothing said about it.
			if !errors.Is(err, registry.ErrNotExist) {
				w.logf("leaving the network adapter %s alone: its name could not be read: %v", guid, err)
			}
			continue
		}
		if name == "" {
			continue
		}
		if !live[strings.ToLower(name)] || isTailnetAdapter(name) {
			continue
		}
		out = append(out, Service{ID: guid, Name: name})
	}
	return out, nil
}

// isTailnetAdapter reports an adapter a tailnet client owns. Pointing one at app-tail's
// resolver would put the tailnet's own name resolution behind the forwarder meant to sit
// beside it.
func isTailnetAdapter(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "tailscale") || strings.Contains(lower, "app-tail")
}

// liveAdapterNames reports the adapters that are up and have an address, keyed by lowercase
// friendly name. An adapter that is down cannot resolve anything, so an override on it is a
// setting that does nothing until the next time that adapter is used -- which is exactly
// when nobody expects app-tail to be in the path.
func liveAdapterNames() (map[string]bool, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("read this machine's network adapters: %w", err)
	}
	out := make(map[string]bool, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		out[strings.ToLower(iface.Name)] = true
	}
	return out, nil
}

// adapterName reads one adapter's friendly name, which is what netsh takes and what the
// user sees in the network settings.
func adapterName(guid string) (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, adapterClass+`\`+guid+`\Connection`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer key.Close()
	name, _, err := key.GetStringValue("Name")
	return name, err
}

// get reads the static resolver setting, which is the layer app-tail writes.
func (w windowsResolver) get(ctx context.Context, s Service) ([]netip.Addr, error) {
	value, err := w.values(s.ID, "NameServer")
	if err != nil {
		return nil, err
	}
	return splitRegistryAddrs(value), nil
}

// set points an adapter at the addresses, or hands it back to DHCP when the list is empty.
//
// IPv6 resolvers live under a separate stack and are set with their own command; mixing the
// two into one call silently sets neither, so they are left out here. Leaving them out is
// only acceptable while something else is still set: an adapter that would have been
// repointed at IPv6 alone is refused, because the alternative is reporting a machine
// repointed that was never touched.
func (w windowsResolver) set(ctx context.Context, s Service, addrs []netip.Addr) error {
	// netsh identifies an adapter by the name a user can change in the network settings, so
	// the name is re-read from the identifier the record was written under: a record written
	// before a rename otherwise names an adapter netsh no longer finds, and the way back for
	// that adapter is gone. The recorded name is kept when the machine cannot better it,
	// which leaves netsh to say what it cannot find.
	if name, err := w.names(s.ID); err != nil {
		w.logf("could not read the current name of the network adapter recorded as %s, using that name: %v", s.Name, err)
	} else if name != "" && name != s.Name {
		w.logf("the network adapter recorded as %s is now called %s", s.Name, name)
		s.Name = name
	}

	if len(addrs) == 0 {
		_, err := w.runNetsh(ctx, "interface", "ipv4", "set", "dnsservers", "name="+s.Name, "source=dhcp")
		return err
	}

	var v4, dropped []netip.Addr
	for _, addr := range addrs {
		if addr.Is6() {
			dropped = append(dropped, addr)
			continue
		}
		v4 = append(v4, addr)
	}
	if len(v4) == 0 {
		return fmt.Errorf("cannot point %s at %s: app-tail sets IPv4 resolvers on Windows and every address given is IPv6", s.Name, describe(addrs))
	}
	if len(dropped) > 0 {
		w.logf("pointing %s at its IPv4 resolvers only; %s left unset (app-tail sets IPv6 resolvers on no platform)", s.Name, describe(dropped))
	}

	// Every argument is tagged. netsh also accepts them by position, and its positions are
	// name, source, address, register, validate -- so a bare "primary" meant as "this is the
	// first resolver" lands on register and changes how this machine registers itself in DNS
	// instead. The first address goes on with set, which replaces the list; the rest are added
	// at the position they should be asked in.
	register := w.registrationMode(s)
	for i, addr := range v4 {
		args := []string{"interface", "ipv4", "set", "dnsservers",
			"name=" + s.Name, "source=static", "address=" + addr.String(), "register=" + register, "validate=no"}
		if i > 0 {
			args = []string{"interface", "ipv4", "add", "dnsservers",
				"name=" + s.Name, "address=" + addr.String(), fmt.Sprintf("index=%d", i+1), "validate=no"}
		}
		if _, err := w.runNetsh(ctx, args...); err != nil {
			if i == 0 {
				return err
			}
			// Named because the adapter is neither where it was nor where it was asked to
			// be: it resolves through what did land, and the caller's record of what to put
			// back is still right, but this is not the machine anybody asked for.
			return fmt.Errorf("pointed %s at %s and could not add the rest: %w",
				s.Name, describe(v4[:i]), err)
		}
	}
	return nil
}

// registrationMode is what netsh has to be told so that pointing an adapter at a resolver
// leaves this machine registering itself in DNS exactly as it did before.
//
// The parameter has no "leave this alone" value and netsh applies its own default when it is
// left out, so the setting is read back and handed straight in. Windows keeps it as two
// numbers under the adapter's own settings: RegistrationEnabled turns registration off
// altogether, and RegisterAdapterName adds the adapter's connection-specific name alongside
// the primary one. An adapter carrying neither is on their defaults, which is registration
// under the primary suffix and nothing else.
//
// A setting that cannot be read falls back to that same default rather than to netsh's, and
// says so: the fallback is what almost every machine is on, and a wrong guess here changes
// which names a managed network can find this machine under.
func (w windowsResolver) registrationMode(s Service) string {
	const primary = "primary"
	enabled, present, err := w.flags(s.ID, "RegistrationEnabled")
	if err != nil {
		w.logf("could not read whether %s registers itself in DNS (%v); leaving it registering under the primary suffix", s.Name, err)
		return primary
	}
	if present && enabled == 0 {
		return "none"
	}
	connection, present, err := w.flags(s.ID, "RegisterAdapterName")
	if err != nil {
		w.logf("could not read whether %s registers its own connection name in DNS (%v); leaving it registering under the primary suffix", s.Name, err)
		return primary
	}
	if present && connection != 0 {
		return "both"
	}
	return primary
}

// base reads what DHCP handed the adapter, which Windows keeps whether or not a static
// resolver is set on top of it.
func (w windowsResolver) base(ctx context.Context, s Service) (Base, error) {
	// A value that is not there arrives as an empty string, so nothing here treats a missing
	// setting as a failure and every error that does arrive is a registry this cannot read.
	servers, err := w.values(s.ID, "DhcpNameServer")
	if err != nil {
		return Base{}, err
	}
	base := Base{Nameservers: splitRegistryAddrs(servers)}
	// The statically configured suffix first: it is the one somebody chose for this adapter,
	// and where both exist Windows itself asks in that order. A search list that asks the
	// network's suffix first resolves a short name against the network before the machine's
	// own configuration, which is the opposite of what configuring one is for.
	for _, value := range []string{"Domain", "DhcpDomain"} {
		domain, err := w.values(s.ID, value)
		if err != nil {
			// Said out loud rather than dropped: the suffix is what makes a short name on
			// this network resolvable, and a search list missing one is a machine that
			// resolves less after app-tail restores it than it did before.
			w.logf("could not read %s for %s, leaving it out of that adapter's search list: %v", value, s.Name, err)
			continue
		}
		if domain != "" && !slices.Contains(base.SearchDomains, domain) {
			base.SearchDomains = append(base.SearchDomains, domain)
		}
	}
	return base, nil
}

// interfaceValue reads one value from an adapter's TCP/IP settings. A value that is not
// there is an empty string rather than a failure: an adapter with no DHCP resolver has no
// DhcpNameServer, which is an answer.
func interfaceValue(guid, name string) (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipInterfaces+`\`+guid, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read the network settings for %s: %w", guid, err)
	}
	defer key.Close()
	value, _, err := key.GetStringValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s for %s: %w", name, guid, err)
	}
	return value, nil
}

// interfaceFlag reads one numeric value from an adapter's TCP/IP settings, reporting whether
// it was there at all. An adapter that has never been given the setting has no value, which
// is a different answer from a setting of zero.
func interfaceFlag(guid, name string) (uint64, bool, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipInterfaces+`\`+guid, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("read the network settings for %s: %w", guid, err)
	}
	defer key.Close()
	value, _, err := key.GetIntegerValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read %s for %s: %w", name, guid, err)
	}
	return value, true, nil
}

// splitRegistryAddrs reads the separated list Windows keeps resolvers in. The separator is
// a comma in one value and a space in another, so both are accepted.
func splitRegistryAddrs(value string) []netip.Addr {
	fields := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' })
	var out []netip.Addr
	for _, field := range fields {
		if addr, err := netip.ParseAddr(strings.TrimSpace(field)); err == nil {
			out = append(out, addr)
		}
	}
	return out
}

// systemProgram is the full path of a program that ships with Windows.
//
// A bare command name is resolved through PATH and through the working directory, so which
// program runs is decided by whoever set up the environment this process was started in --
// and the programs named here repoint the whole machine's name resolution. Windows is asked
// for its own system directory rather than %SystemRoot% being read, because an environment
// variable belongs to that same environment.
func systemProgram(name string) (string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", fmt.Errorf("find this machine's system directory: %w", err)
	}
	return filepath.Join(dir, name), nil
}

// flush drops the resolver cache so the change is visible to the next lookup.
func (w windowsResolver) flush(ctx context.Context) error {
	ipconfig, err := systemProgram("ipconfig.exe")
	if err != nil {
		return err
	}
	if _, err := w.runTool(ctx, ipconfig, []string{"/flushdns"}); err != nil {
		return fmt.Errorf("flush this machine's resolver cache: %w", err)
	}
	return nil
}

// commandTimeout bounds one run of a system tool.
//
// Each of them talks to services that can be wedged -- an adapter part way through
// reconfiguring, a validation waiting on a domain controller that is not answering -- and
// they run while this machine's resolver is part way changed, on the one goroutine every
// other resolver change waits behind. A run that never returns would hold this machine there.
const commandTimeout = 30 * time.Second

// runTool runs one system tool under that bound. The caller's context still ends it sooner:
// this is a ceiling on a single command, not a replacement for shutting down.
func (w windowsResolver) runTool(ctx context.Context, path string, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	return w.run(ctx, path, args)
}

// holdLoopback and releaseLoopback refuse: Windows answers for the whole of 127/8 on its
// loopback pseudo-interface, so an address app-tail could not bind was refused for some
// other reason -- something else already holding it. Adding an address here would change
// this machine for a reason that was never diagnosed.
func (w windowsResolver) holdLoopback(_ context.Context, addr netip.Addr) error {
	return fmt.Errorf("this machine already carries every loopback address, so app-tail could not listen on %s for another reason", addr)
}

func (w windowsResolver) releaseLoopback(context.Context, netip.Addr) error {
	return errors.New("app-tail never adds a loopback address on Windows, so there is none to give back")
}

func (w windowsResolver) runNetsh(ctx context.Context, args ...string) (string, error) {
	netsh, err := systemProgram("netsh.exe")
	if err != nil {
		return "", err
	}
	out, err := w.runTool(ctx, netsh, args)
	if err != nil {
		return "", fmt.Errorf("netsh %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// execRun executes one of the system tools, folding its output into the error so a netsh
// refusal reaches the user as the sentence netsh wrote rather than an exit status.
func execRun(ctx context.Context, path string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	// Both tools are console programs, and app-tail is built without a console of its own, so
	// each one would otherwise flash a window on the user's screen -- once per network adapter,
	// every time the resolver is applied or put back.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if text == "" {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", err, text)
	}
	return string(out), nil
}
