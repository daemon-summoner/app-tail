// SPDX-License-Identifier: MIT

package httpapi

// The proxy instances surface: every listener this app offers a program, what each one is
// allowed to reach, and what each is doing right now.
//
// The stored half and the live half are merged here for the reason TunnelView merges them:
// a client that fetched permissions and status separately would show an instance's rules
// beside a status from a different poll, and two clients reading the two endpoints would
// reach different conclusions about the same listener.

import (
	"context"
	"encoding/json"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsproxy"
)

// Proxies is the instance list as the API needs it.
type Proxies interface {
	List() []ProxyInstanceView
	Get(id string) (ProxyInstanceView, error)
	// Schema is the instance form's field metadata, resolved against this installation.
	Schema() []config.FieldSchema
	// Create adds an instance and binds it if it is meant to be listening.
	Create(ctx context.Context, spec ProxyInstanceSpec) (ProxyInstanceView, error)
	// Update writes the fields a patch carries and returns the instance as it now stands.
	Update(ctx context.Context, id string, patch map[string]json.RawMessage) (ProxyInstanceView, error)
	// SetRules replaces the whole ordered rule list.
	//
	// It replaces rather than merges because order is the meaning here: the first matching
	// rule decides, so a partial write would have to say where each rule goes, and a client
	// that got that wrong would move a deny below the allow it was written to except.
	SetRules(ctx context.Context, id string, rules []access.Rule) (ProxyInstanceView, error)
	// Delete removes an instance and stops it.
	Delete(ctx context.Context, id string) error
	// Test answers what this instance would do with one destination without dialling it.
	Test(ctx context.Context, id string, req ProxyTestRequest) (ProxyTestResult, error)
}

// ProxyInstanceSpec is what a client sends to add an instance: what to call it.
//
// It carries no settings and no rules, for the reason TunnelSpec carries none: everything
// else is a field of the instance form or a rule, written against the instance that now
// exists, so there is one validator and one write path however a value was first set. A new
// instance therefore reaches nothing until somebody grants it something, which is the only
// safe state for a listener to be created in.
type ProxyInstanceSpec struct {
	// Name is the display name. Empty is refused rather than defaulted: an instance is
	// named after the program pointed at it, and that is not something to guess.
	Name string `json:"name"`
	// Slug is the handle this instance answers for in its auto-configuration URL and its
	// local socket. Empty derives one from the name.
	Slug string `json:"slug"`
	// ListenAddr is where it binds. Empty takes the next free port above the default, so
	// adding an instance never lands on one already spoken for.
	ListenAddr string `json:"listenAddr"`
}

// ProxyInstanceView is one instance: what was stored about it, what it reaches, and what it
// is doing.
//
// Settings carries the stored fields under the keys the schema names, which is what lets
// the instance form be rendered from the schema with no per-instance client code.
type ProxyInstanceView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
	// Enabled is whether this instance is meant to be listening, which is a different
	// question from whether it is.
	Enabled bool `json:"enabled"`
	// Removable is whether this instance may be deleted. Served rather than worked out by
	// each client, because the one instance that may not be is identified by an id no
	// client should have to know.
	Removable bool           `json:"removable"`
	Settings  map[string]any `json:"settings"`
	// Rules are this instance's permissions, in the order they are matched.
	Rules []access.Rule `json:"rules"`
	// Reach is what those rules amount to, in sentences. It is computed by the agent so the
	// dashboard, the tray and the CLI cannot describe one instance's permissions
	// differently -- and so a person who does not read rule tables still learns what they
	// have granted.
	Reach []string `json:"reach"`

	// Listening is where it is bound, empty when nothing is. Together with Enabled it
	// separates "off" from "on but could not bind".
	Listening string `json:"listening,omitempty"`
	// LocalSocket is the path of the socket beside the port, where the platform has one.
	// It is the boundary that works: the kernel vouches for the account at the other end.
	LocalSocket string `json:"localSocket,omitempty"`
	// ConfiguredAddr is what the settings ask for, and MovedFromConfig reports that a port
	// conflict put the listener somewhere else -- which is what explains a snippet naming
	// one port while the dashboard shows another.
	ConfiguredAddr   string `json:"configuredAddr"`
	MovedFromConfig  bool   `json:"movedFromConfig"`
	RequiresPassword bool   `json:"requiresPassword"`
	Error            string `json:"error,omitempty"`
	// SocksURL and HTTPURL are what a program is pointed at. Rendered here rather than
	// assembled by a client, for the reason the snippets are: an address a user copies is
	// not somewhere to have two implementations.
	SocksURL string `json:"socksUrl,omitempty"`
	HTTPURL  string `json:"httpUrl,omitempty"`
	// PACURL is where a browser fetches the auto-configuration script, and Snippets are the
	// ready-to-run ways to point a program at this instance. Both are filled in from the
	// request rather than by the agent's own view of itself, because the address a browser
	// can fetch is the one it dialed -- see withCommands.
	PACURL   string            `json:"pacUrl,omitempty"`
	Snippets []tsproxy.Snippet `json:"snippets"`
	Counters tsproxy.Counters  `json:"counters"`
	// Capability answers "is this working, and if not why" for this one instance.
	Capability Capability `json:"capability"`
	// Default marks the instance the command line and the /proxy.pac route address when
	// nothing names one. It decides which ways of pointing a program at a proxy are offered
	// and is not served: a client has no use for it, and Removable already says which
	// instance is load-bearing.
	Default bool `json:"-"`
}

// ProxyTestRequest is one destination to ask about.
type ProxyTestRequest struct {
	// Address is host:port, exactly as a program would ask the proxy for it.
	Address string `json:"address"`
	// Protocol is the transport, tcp or udp. Empty means tcp, which is what a proxy
	// carries unless the caller says otherwise.
	Protocol string `json:"protocol"`
}

// ProxyTestResult is the answer, with the rule that decided.
//
// Naming the rule is the point: rule order is the whole difficulty of a permission model,
// and "refused" without "by which line" leaves somebody editing rules and guessing which
// one they are actually changing.
type ProxyTestResult struct {
	Address string `json:"address"`
	Allowed bool   `json:"allowed"`
	// Resolved is the address the destination resolved to, and Tunnel the connection that
	// would carry it. Both are empty when nothing could work out where the destination is,
	// which is a third answer rather than a refusal.
	Resolved string `json:"resolved,omitempty"`
	Tunnel   string `json:"tunnel,omitempty"`
	// TunnelName is that connection as a person reads it, or a phrase for this machine's
	// own network, so a result never shows a bare id.
	TunnelName string `json:"tunnelName,omitempty"`
	// Egress names the connection this machine's internet traffic leaves through, as a
	// person reads it, and is present only on a destination no connection carries. The
	// packets go through it while the rules still treat the destination as this machine's
	// own network, and a result that showed only one of those two would be read as the
	// other.
	Egress string `json:"egress,omitempty"`
	// Rule is the id of the rule that decided and RuleIndex its one-based position, zero
	// when no rule matched.
	Rule      string `json:"rule,omitempty"`
	RuleIndex int    `json:"ruleIndex,omitempty"`
	// Reason is the sentence to show, whichever way it went.
	Reason string `json:"reason"`
}
