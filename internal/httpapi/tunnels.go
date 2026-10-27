// SPDX-License-Identifier: MIT

package httpapi

// The connections surface: every private network this app is attached to, what each is
// called, and what each is doing right now.
//
// The stored half and the live half are merged here rather than by a client, for the same
// reason ForwardView merges them: a dashboard that fetched configuration and status
// separately would render a connection that exists with a status that belongs to a
// different poll, and a tray reading the same two endpoints would reach a different
// conclusion from the dashboard's.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// Tunnels is the connection list as the API needs it.
type Tunnels interface {
	List() []TunnelView
	Get(id string) (TunnelView, error)
	// Schema is the connection form's field metadata, resolved against this installation.
	Schema() []config.FieldSchema
	// Types are the kinds of network a connection can be added as, which is what an add
	// menu offers. A kind this build cannot bring up is absent rather than offered and
	// then refused after the person has filled the form in.
	Types() []TunnelTypeInfo
	// Create adds a connection and brings it up if it is meant to be up.
	Create(ctx context.Context, spec TunnelSpec) (TunnelView, error)
	// Update takes a context for the same reason the mutating Forwards methods do: it
	// returns the connection as it stands after the write rather than as it was asked to
	// be.
	Update(ctx context.Context, id string, patch map[string]json.RawMessage) (TunnelView, error)
	// Delete removes a connection and stops it.
	Delete(ctx context.Context, id string) error
	// Import replaces one connection's settings with the configuration file its server
	// issued, and returns the connection as it now stands.
	//
	// It is a write rather than a parse-and-return-the-fields, so the format is understood
	// in exactly one place and the client never has to know which field a line maps to. A
	// file naming something this app cannot honour is refused whole, with the line and the
	// directive: importing part of a configuration would produce a connection that looks
	// like the one the file describes and quietly does less.
	Import(ctx context.Context, id, file string) (TunnelView, error)
	// Retry builds one connection again now, whether or not anything about it changed. It is
	// what a connection that is running and carrying nothing needs: an ordinary write is
	// reconciled by rebuilding what differs, and a connection that stopped working differs
	// from nothing.
	Retry(ctx context.Context, id string) (TunnelView, error)
	// Peers are the devices on one connection. It is per-connection rather than one list
	// for the machine because a device belongs to the network that issued its id: offering
	// one connection's devices while another is selected would build a forward pointing at
	// a name the chosen network cannot resolve.
	//
	// A kind of network that has no device list -- a point-to-point link -- answers with an
	// empty one. That is the truth about it, not a failure.
	Peers(ctx context.Context, id string) ([]tsnode.Peer, error)
}

// TunnelHealth is one connection's own account of itself, beside the state word.
//
// It is what separates a connection that is up and working from one that is up and carrying
// nothing: both report themselves connected, and only these figures differ.
type TunnelHealth struct {
	// Up and Down are cumulative bytes since this connection was built, from this machine's
	// point of view.
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
	// Since is when this connection was built. A connection that keeps coming back with a
	// short uptime is failing and being retried, which every other field reports as working.
	Since time.Time `json:"since,omitzero"`
	// LastHandshake is when the two sides last agreed on keys, absent for a kind that has no
	// handshake or one that has never completed it.
	LastHandshake time.Time `json:"lastHandshake,omitzero"`
	// Dropped is how many packets the connection's own outbound queue discarded to keep its
	// delay and depth bounded. Absent while nothing was dropped, and always for a kind that
	// has no such queue.
	Dropped int64 `json:"dropped,omitempty"`
}

// TunnelTypeInfo is one kind of network a connection can be added as.
//
// The label travels with the value for the reason every other label the agent serves does:
// a client that held its own word for a protocol would eventually disagree with the one on
// the connection's own page.
type TunnelTypeInfo struct {
	Value config.TunnelType `json:"value"`
	Label string            `json:"label"`
}

// TunnelSpec is what a client sends to add a connection: what kind of network it is and
// what to call it.
//
// It carries no settings. Everything else about a connection is a field of the connection
// form, so it is written by a patch against the connection that now exists -- which is
// what keeps one validator, one schema and one write path for a field however it was
// first set.
type TunnelSpec struct {
	Type config.TunnelType `json:"type"`
	// Name is the display name. Empty takes the type's own name, so a connection added
	// with nothing but a type is still called something a person can read.
	Name string `json:"name"`
	// Slug is the DNS label this connection answers for. Empty derives one from the name:
	// somebody naming a connection "Office VPN" should not also have to invent
	// "office-vpn".
	Slug string `json:"slug"`
}

// TunnelImport is the configuration file a server issued, as a client sends it.
//
// It is the whole file rather than the fields read out of it, because the file is what the
// user has: nobody transcribes a WireGuard configuration, they paste the one they were sent
// or the one behind a QR code.
type TunnelImport struct {
	File string `json:"file"`
}

// TunnelView is one connection: what was stored about it, and what it is doing.
//
// Settings carries the stored fields under the same keys the schema names, which is what
// lets the connection form be rendered from the schema with no per-type client code. The
// members beside it are the live half, which no field of the stored document holds.
type TunnelView struct {
	ID   string            `json:"id"`
	Type config.TunnelType `json:"type"`
	// TypeLabel is the type as a person reads it, resolved here so a client never has to
	// hold a map from wire value to word.
	TypeLabel string `json:"typeLabel"`
	// Name and Slug are duplicated out of Settings because every surface shows them --
	// a list row, a rail entry, a tray item -- and none of those renders the form.
	Name string `json:"name"`
	Slug string `json:"slug"`
	// Enabled is whether this connection is meant to be up, which is a different question
	// from whether it is.
	Enabled bool `json:"enabled"`
	// Removable is whether this connection may be deleted. Served rather than worked out by
	// each client, because the one connection that may not be is identified by an id no
	// client should have to know -- and a client that knew it would keep offering the action
	// after the rule behind it changed.
	Removable bool `json:"removable"`
	// Retryable is whether this connection can be built again now. Served for the same
	// reason Removable is: what the agent would refuse is decided in one place, so a client
	// never offers an action it will be told no for.
	Retryable bool           `json:"retryable"`
	Settings  map[string]any `json:"settings"`

	// State is the one status vocabulary every kind of connection reports in, and
	// StateLabel is the word beside it. The label is served rather than derived by each
	// client so the dashboard, the tray and the CLI cannot describe one connection
	// differently.
	State      string `json:"state"`
	StateLabel string `json:"stateLabel"`
	// Live reports that traffic can cross right now, which is what a caller deciding
	// whether to offer an action needs and is not the same as State being "connected":
	// a degraded connection still carries.
	Live bool `json:"live"`
	// Detail explains a state that needs explaining, shown verbatim.
	Detail string `json:"detail,omitempty"`
	// Health is what this connection has carried and how long it has been up, absent for a
	// kind that counts nothing of its own -- a tailnet counts per device, and its figures
	// are on the activity screen instead. Absent is what stops a screen printing a
	// confident zero for a connection nothing is counting.
	Health *TunnelHealth `json:"health,omitempty"`
	// AuthURL is where a person completes an interactive login, set only alongside a
	// state that is waiting for one.
	AuthURL string   `json:"authUrl,omitempty"`
	Addrs   []string `json:"addrs,omitempty"`
	Names   []string `json:"names,omitempty"`
	// Limits are what this connection does not carry, stated up front. They are not
	// errors and never clear.
	Limits []string `json:"limits,omitempty"`
}
