// SPDX-License-Identifier: MIT

// Package hostnet is the privilege boundary for running app-tail on a real network
// interface.
//
// Everything that needs rights the agent does not have -- creating the interface,
// installing routes, writing resolver configuration -- is behind one small interface with
// four operations. That is deliberate: the surface a privileged component exposes is the
// surface an attacker gets, so it is four calls that each take a value the caller could
// not have used to name an arbitrary file or command.
//
// There are two implementations. Local does the work in this process, which is what runs
// when the process already has the rights -- Windows after elevating, or a unix agent
// started as root. Client talks over a unix socket to a helper that has them, which is
// how macOS keeps the agent itself unprivileged: the tray, the browser and the config
// directory all belong to the user, and only a small helper is root.
package hostnet

import (
	"context"
	"errors"
	"fmt"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/dns"
	"tailscale.com/wgengine/router"

	"github.com/sellitus/app-tail/internal/buildinfo"
	"github.com/sellitus/app-tail/internal/grants"
)

// Version identifies this build to the other side of the boundary. The helper holds
// root, so a version it does not recognise is refused rather than negotiated with: the
// wire protocol carries no compatibility rules, and a helper left behind by an older
// release would read the same fields differently.
var Version = buildinfo.Get().Version

// ErrUnsupported reports that this platform has no interface mode at all. It is a
// sentinel because the caller's response is to explain rather than to retry.
var ErrUnsupported = errors.New("this platform cannot run app-tail on a network interface")

// ErrNoHelper reports that the privileged helper is not installed or not reachable. It
// is distinct from a permission failure: the answer is to install it, and the message
// that says so is worth more than a generic refusal.
var ErrNoHelper = errors.New("the privileged helper is not running")

// ErrHelperNotOpenToThisAccount reports that a helper is on the machine and this account
// cannot open its socket. It is a separate sentinel from ErrNoHelper because the answers
// are opposite: one is to install a helper, and this one is to install the helper again
// for the account that is asking. A helper from an older build, or one installed from
// another account, leaves a socket this one cannot reach.
var ErrHelperNotOpenToThisAccount = errors.New("the privileged helper is installed but this account cannot reach it")

// ErrHelperFromAnotherBuild reports that the helper on this machine is not the one this
// app speaks to. It is a sentinel because the answer is neither to install a helper nor to
// look at the socket: the one already there has to be replaced, and only the layer that
// knows the platform can name the command that does it.
var ErrHelperFromAnotherBuild = errors.New("the privileged helper is from another build of app-tail")

// ErrHelperBusy reports that another connection holds the helper's single session. It is a
// sentinel because nothing about the machine is wrong: it is capable, it is set up, and
// something else has the interface -- so the answer is to deal with that, not to install or
// repair anything.
var ErrHelperBusy = errors.New("another app-tail on this machine is already using the privileged helper")

// ErrNeedsElevation reports that this platform has no helper and the process itself does
// not hold the rights. It is a separate sentinel from ErrNoHelper because the two have
// opposite answers: install something once, or restart this process elevated.
var ErrNeedsElevation = errors.New("app-tail needs administrator rights to run on a network interface")

// ErrDeclined reports that the request for administrator rights was dismissed. It is a
// sentinel because the answer is to carry on without the interface mode and say what was
// given up, not to retry: asking again for something that was just refused is how an app
// becomes one people click through without reading.
var ErrDeclined = errors.New("the request for administrator rights was declined")

// errNoHelperOnThisPlatform is what the helper's own entry points return where the design
// has no helper. It is defined here rather than per-platform because the server refers to
// it on every platform: the check is what turns a helper command on Windows into a
// sentence instead of a socket error from a path that was never going to exist.
var errNoHelperOnThisPlatform = errors.New("this platform has no privileged helper: the app elevates itself instead")

// Capabilities is what the privileged side reports it can do, read before anything is
// torn down. Every field is a reason a start would fail, gathered while the existing
// node is still up so the failure is a refusal rather than an outage.
type Capabilities struct {
	// Version is the helper's build version. A helper from another release is refused
	// rather than trusted: it is the same wire protocol only by coincidence.
	Version string `json:"version"`
	// Build identifies the helper's binary by its contents, which is what the version
	// cannot do: two builds of one commit report the same version and are not the same
	// program. The helper is a copy of this same binary, so the two either match exactly
	// or the helper is one a rebuild left behind.
	Build string `json:"build"`
	// Interface is the name the platform would give a new interface, which is what the
	// doctor reports and what a user greps for.
	Interface string `json:"interface"`
	// Conflict names another program already managing a tailnet on this machine, empty
	// when there is none. Two of them delete each other's resolver files and fight over
	// the same address range, so this is a refusal rather than a warning.
	Conflict string `json:"conflict,omitempty"`
	// Missing names a component the mode needs that is not installed, empty when
	// everything is present. It is separate from Conflict because the two have opposite
	// answers: stop something, or install something.
	Missing string `json:"missing,omitempty"`
	// ResolverBusy names what already holds every address app-tail would listen for DNS
	// on, empty when one of them is free. It is the machine-wide resolver's own version of
	// Conflict, and separate from it because the two features fail independently: a
	// machine running another tailnet client can still switch its DNS, and one running
	// another DNS server can still take the interface.
	ResolverBusy string `json:"resolverBusy,omitempty"`
	// Leftovers are resources a previous run did not clean up: an interface still up,
	// resolver files still on disk. They are reported rather than silently reused
	// because they are also what an unclean exit looks like from outside.
	Leftovers []string `json:"leftovers,omitempty"`
	// StaleOverride is set when a previous run left this machine's name resolution pointed
	// at app-tail and nothing has put it back. It is not one of the Leftovers because
	// those are paths a user can delete and this is a setting on every network service,
	// which only the privileged side can restore.
	StaleOverride string `json:"staleOverride,omitempty"`
}

// Usable reports whether a start may proceed, and why not when it may not.
//
// The missing component is reported before the conflict: a machine with both has to
// install something whichever client it ends up running, and naming the conflict first
// would send someone to quit an app they will need again either way.
func (c Capabilities) Usable() (bool, string) {
	if c.Missing != "" {
		return false, c.Missing
	}
	if c.Conflict != "" {
		return false, c.Conflict
	}
	return true, ""
}

// Host is the privileged side of the boundary.
//
// The lifecycle is fixed: Capabilities, then OpenTUN, then any number of SetRoutes and
// SetDNS, then Close. Close reverses the machine-level changes -- routes removed,
// resolver configuration restored -- and is what makes an ordinary shutdown leave no
// trace. An unclean exit is covered separately, by the dead-man's switch in the helper.
//
// The device OpenTUN returns belongs to the caller, because what the caller passes it to
// closes it. Close here never touches it.
type Host interface {
	// Capabilities reports what this machine can do, without changing anything.
	Capabilities(ctx context.Context) (Capabilities, error)
	// OpenTUN creates the interface and hands it back with the name the OS gave it.
	// name may be empty for the platform default.
	OpenTUN(ctx context.Context, name string) (tun.Device, string, error)
	// RouterUp brings the interface up, which on some platforms is a separate step from
	// creating it and on others is already done.
	RouterUp(ctx context.Context) error
	// SetRoutes installs the addresses and routes the interface carries. A nil config
	// removes everything, which is what the engine sends on the way down.
	SetRoutes(ctx context.Context, cfg *router.Config) error
	// SetHostRoutes is SetRoutes for a caller that is not the tailnet engine: the same
	// installation, expressed as address ranges and a packet size rather than as the
	// engine's own configuration. The zero value removes everything.
	SetHostRoutes(ctx context.Context, r Routes) error
	// ScopeHostDefault keeps this machine's own way out reachable for a program that binds a
	// socket to the interface holding it, which carrying this machine's traffic otherwise
	// breaks. It is asked for again on every change to what is carried, because the interface
	// and the next hop are the machine's and the machine may have moved. A platform that
	// cannot do it returns ErrScopedRoutesUnsupported, which is a documented answer rather
	// than a failure.
	ScopeHostDefault(ctx context.Context) error
	// UnscopeHostDefault takes those copies back, leaving the machine's routing as it was.
	UnscopeHostDefault(ctx context.Context) error
	// SetDNS installs the resolver configuration. A zero config removes it.
	SetDNS(ctx context.Context, cfg dns.OSConfig) error
	// BaseDNS reports the resolver settings this machine would use with no app-tail on
	// it, which is what the tailnet resolver forwards everything else to. A platform
	// that will not say returns dns.ErrGetBaseConfigNotSupported, which is a documented
	// answer rather than a failure.
	BaseDNS(ctx context.Context) (dns.OSConfig, error)
	// SplitDNS reports whether this machine can point one domain at the tailnet's
	// resolver and leave every other domain alone. It is asked of the live configurator
	// rather than assumed from the platform, because on Linux the answer depends on which
	// resolver is actually installed and a wrong yes silently drops the split.
	SplitDNS(ctx context.Context) (bool, error)
	// Close reverses every change this made to the machine.
	Close() error
}

// Options configures which side of the boundary a caller ends up on.
type Options struct {
	// SocketPath is where the helper listens, empty for the platform default.
	SocketPath string
	// Logf receives the privileged side's own logging. Required for Local, since a
	// route or resolver change that failed halfway has to be visible somewhere.
	Logf func(format string, args ...any)
	// Grants, when set, hears every change the helper refused for a missing approval and every
	// one it accepted, credited to the feature that sends it. The agent keeps the list a person
	// is asked to approve from it. A process that holds the rights itself is never refused, so
	// only the helper's client reports.
	Grants grants.Observer
}

// Open returns the privileged side, in this process when it already has the rights and
// over the helper socket when it does not.
//
// The choice is made from the process's own privilege rather than from configuration:
// a machine where the agent happens to run as root needs no helper, and asking one to be
// installed there would be a step that changes nothing.
func Open(ctx context.Context, opts Options) (Host, error) {
	if opts.Logf == nil {
		return nil, errors.New("hostnet: no log function was provided")
	}
	if !Supported() {
		return nil, ErrUnsupported
	}
	if Privileged() {
		return NewLocal(opts.Logf), nil
	}
	if !HasHelper() {
		return nil, ErrNeedsElevation
	}
	// Unwrapped rather than returned straight through: Dial's own return type is the
	// concrete client, and a nil one placed in this interface is not nil to a caller that
	// checks it. Whoever gets a refusal here must be able to close what they were given
	// without first knowing which side of the boundary produced it.
	client, err := Dial(ctx, opts)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// checkVersion refuses a helper from another build. The wire protocol carries no
// compatibility rules of its own, so a helper left behind by an older release would
// answer with fields this build reads differently -- and it holds root while doing it.
func checkVersion(want, got string) error {
	if want == "" || got == "" {
		return fmt.Errorf("the helper did not say which version it is (this build is %q, it said %q)", want, got)
	}
	if want != got {
		return fmt.Errorf("%w: it is version %s and this app is %s", ErrHelperFromAnotherBuild, got, want)
	}
	return nil
}
