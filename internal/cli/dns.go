// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/hostnet"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/sysdns"
)

// DNS reads what the tailnet publishes and what this machine resolves with.
func (c *Client) DNS(ctx context.Context) (httpapi.DNSView, error) {
	var out httpapi.DNSView
	err := c.do(ctx, http.MethodGet, "/api/dns", nil, &out)
	return out, err
}

// DNSProfiles lists the shipped resolver profiles and the user's own.
func (c *Client) DNSProfiles(ctx context.Context) ([]config.DNSProfile, error) {
	var out struct {
		Profiles []config.DNSProfile `json:"profiles"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/dns/profiles", nil, &out); err != nil {
		return nil, err
	}
	return out.Profiles, nil
}

// CreateDNSProfile adds a resolver profile.
func (c *Client) CreateDNSProfile(ctx context.Context, p config.DNSProfile) (config.DNSProfile, error) {
	var out config.DNSProfile
	err := c.do(ctx, http.MethodPost, "/api/dns/profiles", p, &out)
	return out, err
}

// UpdateDNSProfile replaces a resolver profile, keeping its id so the settings pointing at
// it stay valid.
func (c *Client) UpdateDNSProfile(ctx context.Context, id string, p config.DNSProfile) (config.DNSProfile, error) {
	var out config.DNSProfile
	err := c.do(ctx, http.MethodPut, "/api/dns/profiles/"+url.PathEscape(id), p, &out)
	return out, err
}

// DeleteDNSProfile removes a resolver profile. Built-ins and the one in force are refused
// by the agent.
func (c *Client) DeleteDNSProfile(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/dns/profiles/"+url.PathEscape(id), nil, nil)
}

// SetUpSystemDNS arranges the administrator rights the machine-wide resolver needs and
// reports the state that produced.
func (c *Client) SetUpSystemDNS(ctx context.Context) (httpapi.DNSView, error) {
	var out httpapi.DNSView
	err := c.do(ctx, http.MethodPost, "/api/dns/setup", nil, &out)
	return out, err
}

// runDNS dispatches the DNS subcommands, showing the state when given none.
func runDNS(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return runDNSShow(ctx, args, env)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "use":
		return runDNSUse(ctx, rest, env)
	case "profile":
		return runDNSProfile(ctx, rest, env)
	case "block":
		return runDNSBlock(ctx, rest, env)
	case "setup":
		return runDNSSetup(ctx, rest, env)
	case "restore":
		return runDNSRestore(ctx, rest, env)
	default:
		return usagef("unknown dns subcommand %q; use `dns`, `dns use NAME`, `dns profile`, `dns block`, `dns setup` or `dns restore`", sub)
	}
}

// runDNSShow prints what this machine resolves names with beside what the tailnet
// publishes.
//
// Both halves are printed even when one is empty. The whole reason this command exists is
// that a name does not resolve somewhere the user expected it to, and showing only one half
// is what makes that look like a bug.
func runDNSShow(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "dns"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.DNS(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, view)
	}

	writeSystemDNS(env, view.System)
	if !view.Enabled {
		// Printed rather than returned, because the machine-wide half above is the reason
		// somebody ran this and it has nothing to do with the tailnet's DNS.
		fmt.Fprintln(env.Stdout, "\nThe tailnet DNS module is off, so app-tail resolves tailnet names with this machine's own resolver.")
		fmt.Fprintln(env.Stdout, "Turn it on with: app-tail settings set dns true")
		return nil
	}

	rows := [][2]string{
		{"Using your tailnet's DNS", yesNo(view.Using)},
		{"Device names resolve", yesNo(view.MagicDNS)},
	}
	if len(view.Resolvers) > 0 {
		rows = append(rows, [2]string{"Tailnet nameservers", strings.Join(view.Resolvers, ", ")})
	}
	if len(view.SearchDomains) > 0 {
		rows = append(rows, [2]string{"Search domains", strings.Join(view.SearchDomains, ", ")})
	}
	for _, r := range view.Routes {
		answered := "your tailnet's own resolver"
		if len(r.Resolvers) > 0 {
			answered = strings.Join(r.Resolvers, ", ")
		}
		rows = append(rows, [2]string{"Split DNS " + r.Suffix, answered})
	}
	for _, r := range view.Records {
		rows = append(rows, [2]string{"Tailnet record " + r.Name, r.Value})
	}
	if view.ExitNodeResolving {
		rows = append(rows, [2]string{"Resolved by exit node", view.ExitNodeLabel})
	}

	if view.Machine != nil {
		if len(view.Machine.Nameservers) > 0 {
			rows = append(rows, [2]string{"This machine's nameservers", strings.Join(view.Machine.Nameservers, ", ")})
		}
		if len(view.Machine.MatchDomains) > 0 {
			rows = append(rows, [2]string{"Sent to your tailnet", strings.Join(view.Machine.MatchDomains, ", ")})
		}
	}

	fmt.Fprintln(env.Stdout, "\nTailnet DNS")
	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintf(writer, "%s:\t%s\n", row[0], row[1])
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	if view.MachineReason != "" {
		fmt.Fprintf(env.Stdout, "\n%s\n", view.MachineReason)
	}
	if view.Capability.Reason != "" {
		fmt.Fprintf(env.Stdout, "\n%s\n", view.Capability.Reason)
	}
	for _, limit := range view.Capability.Limits {
		fmt.Fprintf(env.Stdout, "  - %s\n", limit)
	}
	return nil
}

// writeSystemDNS prints the machine-wide half. An agent built before this half existed
// sends nothing for it, which is reported as absent rather than as a resolver that changes
// nothing -- those are different situations and only one of them is fixable here.
func writeSystemDNS(env Env, view *httpapi.DNSSystemView) {
	fmt.Fprintln(env.Stdout, "This machine's resolver")
	if view == nil {
		fmt.Fprintln(env.Stdout, "  This agent does not report the machine-wide resolver.")
		return
	}

	rows := [][2]string{
		{"Machine-wide resolver", onOff(view.Enabled)},
		{"Profile", profileWord(view)},
	}
	if len(view.Servers) > 0 {
		rows = append(rows, [2]string{"Resolvers", strings.Join(view.Servers, ", ")})
	}
	if len(view.Protocols) > 0 {
		rows = append(rows, [2]string{"Reached over", strings.Join(view.Protocols, ", ")})
	}
	rows = append(rows, [2]string{"In force on this machine", yesNo(view.Applied)})
	if view.Listen != "" {
		rows = append(rows, [2]string{"Answering on", view.Listen})
	}
	if view.Base != nil && len(view.Base.Nameservers) > 0 {
		rows = append(rows, [2]string{"This network's resolvers", strings.Join(view.Base.Nameservers, ", ")})
	}
	if len(view.LocalSuffixes) > 0 {
		rows = append(rows, [2]string{"Names kept on this network", strings.Join(view.LocalSuffixes, ", ")})
	}
	if view.Queries.Total > 0 {
		rows = append(rows, [2]string{"Queries", fmt.Sprintf("%d in total, %d to the profile, %d to this network",
			view.Queries.Total, view.Queries.ToProfile, view.Queries.ToLocal)})
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintf(writer, "  %s:\t%s\n", row[0], row[1])
	}
	if err := writer.Flush(); err != nil {
		// The writer is this command's own stdout; a failure here is the same one every
		// other line would hit, and there is nowhere left to report it.
		fmt.Fprintf(env.Stderr, "app-tail: could not print the machine-wide resolver: %v\n", err)
	}

	if view.Error != "" {
		fmt.Fprintf(env.Stdout, "\n  %s\n", view.Error)
	}
	if view.Unreachable != "" {
		fmt.Fprintf(env.Stdout, "\n  %s\n", view.Unreachable)
	}
	if view.Intercepted != "" {
		fmt.Fprintf(env.Stdout, "\n  %s\n", view.Intercepted)
	}
	if view.Bootstrap != "" {
		// Printed whichever way it went: the resolver that turned a hostname into an address
		// chose which server this machine is really talking to, and that is not something to
		// state only when it went wrong.
		fmt.Fprintf(env.Stdout, "\n  %s\n", view.Bootstrap)
	}

	if view.NeedsSetup {
		fmt.Fprintln(env.Stdout, "\n  This machine is not set up for it yet. Run: app-tail dns setup")
	} else if view.Blocker != "" {
		fmt.Fprintf(env.Stdout, "\n  %s\n", view.Blocker)
	}
}

func profileWord(view *httpapi.DNSSystemView) string {
	if view.ProfileLabel != "" {
		return fmt.Sprintf("%s (%s)", view.ProfileLabel, view.Profile)
	}
	return view.Profile
}

// runDNSUse switches this machine to a resolver profile, by name or id.
//
// The profile travels with the module switch in one write because it is refused while the
// switch that governs it is off. Choosing System default switches the module off rather
// than leaving it on doing nothing: the undo has to leave the settings looking like a
// machine that never used the feature, which is what turning the module off produces on its
// own.
func runDNSUse(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns use", env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("dns use takes exactly one profile name or id")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	profiles, err := client.DNSProfiles(ctx)
	if err != nil {
		return err
	}
	profile, err := resolveDNSProfile(profiles, pos[0])
	if err != nil {
		return err
	}

	on := profile.ID != dnsprofiles.SystemID
	patch := map[string]json.RawMessage{
		"systemDns.enabled": json.RawMessage(fmt.Sprintf("%t", on)),
	}
	// The profile travels with the switch when it is going on, because it is refused while
	// the switch that governs it is off. It is left out when going off for the same reason
	// from the other side: turning the module off resets the settings it owns back to their
	// defaults, and naming the profile in that write is naming a setting the same write has
	// just made unavailable.
	if on {
		patch["systemDns.profile"] = mustJSONString(profile.ID)
	}
	result, err := client.UpdateSettings(ctx, patch)
	if err != nil {
		return err
	}

	// The write stored the choice. Whether this machine's own resolver actually moved is a
	// separate fact that only the agent knows, and the settings write waits for the
	// reconcile, so the state read back here is the state that write produced. Reporting the
	// request back as though it were the outcome is how somebody spends an afternoon
	// debugging a site through a resolver they were never on.
	view, err := client.DNS(ctx)
	if err != nil {
		return fmt.Errorf("stored %s as this machine's resolver profile, but could not read back "+
			"what this machine is resolving with: %w", profile.Name, err)
	}
	sys := view.System

	if !on {
		if sys != nil && sys.Applied {
			return fmt.Errorf("this machine's resolver is still pointed at app-tail: %s",
				systemDNSObstacle(sys))
		}
		fmt.Fprintln(env.Stdout, "This machine resolves names the way it always did.")
		return nil
	}
	if sys == nil {
		fmt.Fprintf(env.Stdout, "%s is now this machine's resolver profile. "+
			"This agent does not report whether it is in force.\n", profile.Name)
		noteRestart(env.Stdout, result)
		return nil
	}
	if !sys.Applied {
		fmt.Fprintf(env.Stdout, "%s is now this machine's resolver profile, but this machine is not "+
			"resolving through it yet.\n", profile.Name)
		if sys.NeedsSetup {
			return fmt.Errorf("%s; run `app-tail dns setup` to arrange it", systemDNSObstacle(sys))
		}
		return errors.New(systemDNSObstacle(sys))
	}
	// The agent's list, not the stored one: a profile whose resolvers come from the tailnet
	// stores none, and printing the stored list would report an empty pair of brackets for
	// the machine that is resolving through them right now.
	servers := profile.Servers
	if len(sys.Servers) > 0 {
		servers = sys.Servers
	}
	fmt.Fprintf(env.Stdout, "This machine now resolves names through %s (%s).\n",
		profile.Name, strings.Join(servers, ", "))
	if sys.Intercepted != "" {
		// Printed after the success line and not instead of it: the override really is in
		// force, and what is wrong is where the answers come from.
		fmt.Fprintf(env.Stdout, "\n%s\n", sys.Intercepted)
	}
	if sys.Bootstrap != "" {
		fmt.Fprintf(env.Stdout, "\n%s\n", sys.Bootstrap)
	}
	noteRestart(env.Stdout, result)
	return nil
}

// systemDNSObstacle names why this machine is not resolving through the profile it was
// pointed at, preferring the most specific fact the agent reported. The last arm is not a
// formality: a state with no reason at all is itself worth saying out loud, because the
// alternative is a command that fails silently.
func systemDNSObstacle(view *httpapi.DNSSystemView) string {
	for _, reason := range []string{view.Blocker, view.Error, view.Unreachable} {
		if reason != "" {
			return reason
		}
	}
	return "the agent reported no reason; `app-tail dns` prints the whole state"
}

// runDNSProfile dispatches the catalog subcommands.
func runDNSProfile(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return runDNSProfileList(ctx, args, env)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return runDNSProfileList(ctx, rest, env)
	case "add":
		return runDNSProfileAdd(ctx, rest, env)
	case "edit":
		return runDNSProfileEdit(ctx, rest, env)
	case "rm":
		return runDNSProfileRemove(ctx, rest, env)
	default:
		return usagef("unknown dns profile command %q; use list, add, edit or rm", sub)
	}
}

func runDNSProfileList(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns profile list", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the profiles as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "dns profile list"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	profiles, err := client.DNSProfiles(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		if profiles == nil {
			profiles = []config.DNSProfile{}
		}
		return writeJSON(env, profiles)
	}

	view, err := client.DNS(ctx)
	if err != nil {
		return err
	}
	inUse := ""
	if view.System != nil && view.System.Enabled {
		inUse = view.System.Profile
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "ID\tNAME\tRESOLVERS\tSOURCE\tIN USE")
	for _, p := range profiles {
		source := "user"
		if p.BuiltIn {
			source = "built-in"
		}
		servers := strings.Join(p.Servers, ", ")
		switch {
		case dnsprofiles.NeedsTailnet(p.ID):
			// Its resolvers are whatever the tailnet publishes when it is applied, so the
			// column says where they come from rather than reading as "no resolvers".
			servers = "your tailnet's own"
		case servers == "":
			servers = "this machine's own"
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", p.ID, p.Name, servers, source, yesNo(p.ID == inUse))
	}
	return writer.Flush()
}

func runDNSProfileAdd(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns profile add", env)
	loc := addLocationFlags(fs)
	name := fs.String("name", "", "label for the profile (required)")
	servers := fs.String("servers", "", "comma-separated resolvers, tried in order: 1.1.1.1, tls://dns.example, https://dns.example/path (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "dns profile add"); err != nil {
		return err
	}
	if strings.TrimSpace(*name) == "" {
		return usagef("dns profile add needs --name")
	}
	list := splitList(*servers)
	if len(list) == 0 {
		return usagef("dns profile add needs --servers")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	created, err := client.CreateDNSProfile(ctx, config.DNSProfile{Name: *name, Servers: list})
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Added resolver profile %s (%s): %s\n",
		created.Name, created.ID, strings.Join(created.Servers, ", "))
	fmt.Fprintf(env.Stdout, "Switch to it with: app-tail dns use %s\n", created.ID)
	return nil
}

func runDNSProfileEdit(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns profile edit", env)
	loc := addLocationFlags(fs)
	name := fs.String("name", "", "new label, defaulting to the current one")
	servers := fs.String("servers", "", "comma-separated resolvers, defaulting to the current ones")
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("dns profile edit takes exactly one profile name or id")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	profiles, err := client.DNSProfiles(ctx)
	if err != nil {
		return err
	}
	profile, err := resolveDNSProfile(profiles, pos[0])
	if err != nil {
		return err
	}
	// Sent whole rather than as a patch, because the agent's update replaces the profile:
	// an unspecified field has to arrive as what it already was or the edit would clear it.
	if strings.TrimSpace(*name) != "" {
		profile.Name = *name
	}
	if strings.TrimSpace(*servers) != "" {
		profile.Servers = splitList(*servers)
	}

	updated, err := client.UpdateDNSProfile(ctx, profile.ID, profile)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Updated resolver profile %s (%s): %s\n",
		updated.Name, updated.ID, strings.Join(updated.Servers, ", "))
	return nil
}

func runDNSProfileRemove(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns profile rm", env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("dns profile rm takes exactly one profile name or id")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	profiles, err := client.DNSProfiles(ctx)
	if err != nil {
		return err
	}
	profile, err := resolveDNSProfile(profiles, pos[0])
	if err != nil {
		return err
	}
	if profile.BuiltIn {
		return fmt.Errorf("%q is a built-in resolver profile and cannot be removed", pos[0])
	}
	if err := client.DeleteDNSProfile(ctx, profile.ID); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Removed resolver profile %s\n", profile.Name)
	return nil
}

// resolveDNSProfile accepts an id or a name. A name that matches more than one profile is
// refused rather than guessed at: the command that follows points this whole machine's name
// resolution somewhere, and picking the wrong one is not a mistake the user would see.
func resolveDNSProfile(profiles []config.DNSProfile, wanted string) (config.DNSProfile, error) {
	for _, p := range profiles {
		if p.ID == wanted {
			return p, nil
		}
	}

	var matches []config.DNSProfile
	for _, p := range profiles {
		if strings.EqualFold(p.Name, wanted) {
			matches = append(matches, p)
		}
	}
	switch len(matches) {
	case 0:
		return config.DNSProfile{}, fmt.Errorf("no resolver profile called %q; run `app-tail dns profile list`", wanted)
	case 1:
		return matches[0], nil
	default:
		ids := make([]string, 0, len(matches))
		for _, p := range matches {
			ids = append(ids, p.ID)
		}
		return config.DNSProfile{}, fmt.Errorf("%q matches more than one resolver profile (%s); name it by id",
			wanted, strings.Join(ids, ", "))
	}
}

// runDNSSetup arranges the rights the machine-wide resolver needs, through the agent so the
// dialog is raised once and the switch takes effect without a restart.
func runDNSSetup(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns setup", env)
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "dns setup"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Setting this machine up to let app-tail change how it resolves names.")
	fmt.Fprintln(env.Stdout, "Your system will ask for your password, because changing it needs administrator rights.")
	view, err := client.SetUpSystemDNS(ctx)
	if err != nil {
		return err
	}
	if view.System != nil && !view.System.Ready {
		return fmt.Errorf("this machine is still not set up for the machine-wide resolver: %s", view.System.Blocker)
	}
	fmt.Fprintln(env.Stdout, "\nThis machine is ready. Choose a resolver profile with:")
	fmt.Fprintln(env.Stdout, "  app-tail dns use cloudflare")
	return nil
}

// restoreSystemDNS is the machine-level repair, behind a variable so a test can say what the
// machine answered -- put back, nothing recorded, partly back -- without touching one.
var restoreSystemDNS = hostnet.RepairSystemDNS

// runDNSRestore puts this machine's resolver back from the record a previous run left, and
// hands back to its network any service still pointed only at app-tail's own addresses.
//
// It works on the machine rather than through the agent, and needs administrator rights,
// because the cases it exists for have no agent running: a machine with no helper to have
// repaired it at boot, and the Windows boot-time task that runs it as SYSTEM before anyone
// logs in.
func runDNSRestore(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns restore", env)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "dns restore"); err != nil {
		return err
	}

	restored, err := restoreSystemDNS(ctx, tunLogf(env))
	if errors.Is(err, hostnet.ErrResolverServed) {
		fmt.Fprintln(env.Stdout, "app-tail is running and serving this machine's resolver, so there is nothing to repair.")
		fmt.Fprintln(env.Stdout, "Quitting it puts the resolver back.")
		return nil
	}
	var partial *sysdns.PartialRestoreError
	if errors.As(err, &partial) {
		// Not an error exit: everything reachable was put back, and saying so is the whole
		// point -- the user reading this has a machine that cannot resolve names, and being
		// told the repair worked when one adapter is still redirected is what stops them
		// looking any further.
		fmt.Fprintln(env.Stdout, "Most of this machine's resolver is back to what it was before app-tail changed it.")
		fmt.Fprintln(env.Stdout, "\nThese network services could not be read, so app-tail left them alone:")
		for _, name := range partial.Services {
			fmt.Fprintf(env.Stdout, "  %s\n", name)
		}
		fmt.Fprintln(env.Stdout, "\nThat is what a disabled adapter, an unplugged dock or a switched-off radio looks like.")
		fmt.Fprintln(env.Stdout, "app-tail kept what they had. Bring them back and run this again to finish.")
		if rest := otherThanPartial(err); rest != nil {
			return fmt.Errorf("put the rest of this machine's resolver back: %w", rest)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("put this machine's resolver back: %w "+
			"(this command changes every network service, so it has to run with administrator rights)", err)
	}
	if !restored {
		fmt.Fprintln(env.Stdout, "Nothing to put back: no run of app-tail left this machine's resolver redirected.")
		return nil
	}
	fmt.Fprintln(env.Stdout, "This machine's resolver is back to what it was before app-tail changed it.")
	return nil
}

// otherThanPartial is err without the partial restore inside it, nil when that was all it
// carried.
func otherThanPartial(err error) error {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var rest []error
		for _, inner := range joined.Unwrap() {
			if other := otherThanPartial(inner); other != nil {
				rest = append(rest, other)
			}
		}
		return errors.Join(rest...)
	}
	var partial *sysdns.PartialRestoreError
	if errors.As(err, &partial) {
		return nil
	}
	return err
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

// mustJSONString encodes one profile id for a settings patch. The value comes from the
// agent's own catalog, so a value JSON cannot encode would mean the agent sent something
// that is not a string at all.
func mustJSONString(v string) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("encode %q: %v", v, err))
	}
	return raw
}
