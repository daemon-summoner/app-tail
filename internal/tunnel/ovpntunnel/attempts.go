// SPDX-License-Identifier: MIT

package ovpntunnel

// Reaching a server the stored settings do not quite describe.
//
// An OpenVPN connection is configured by copying values out of a file, and three of those
// values fail silently when they are copied into the wrong place. A tls-auth key and a
// tls-crypt key are the same file with the same header, so a key in the wrong box is not
// something any check here can see -- the server simply drops every packet and says nothing.
// The digest that signs a tls-auth control channel is the same: wrong, and the server never
// answers. And a port that carries something other than an OpenVPN server answers with
// whatever it does carry, which openvpn reports as a peer of its own kind.
//
// So when a connection cannot reach its server, this is what it tries instead: the same
// stored material read the other way, the digests a server asks for, and the addresses an
// administrator picks when nothing forced another choice. Every one of them is derived from
// what is already stored -- nothing here is fetched, guessed at from a provider, or invented.
//
// None of it is written back. The settings stay exactly as they were entered, and the
// connection reports which change reached the server so that it can be made -- or not -- by
// the person who entered them.

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/sellitus/app-tail/internal/config"
)

// Reached remembers which derived attempt got each connection to its server.
//
// Without it every restart searches the same ladder from the top, and restarts are ordinary:
// choosing a different connection to carry this machine's internet traffic restarts both of
// them, because whether a connection takes the default route is decided when its program starts.
// A user switching between two servers would wait out the whole search twice, every time.
//
// What is kept is the change's own description, not the settings it produced. The ladder is
// rebuilt from whatever is stored at the time, so a description that no longer names an attempt
// in it is simply dropped -- editing the settings can never leave a connection dialling
// something derived from what they used to say.
//
// It lives as long as the process and is written nowhere. Nothing here changes what is stored.
type Reached struct {
	mu sync.Mutex
	by map[string]string
}

// NewReached builds the shared memory of what worked. One belongs to the agent, not to a
// connection: the point of it is to outlive the connection object that learned it.
func NewReached() *Reached { return &Reached{by: map[string]string{}} }

// of is the change that last reached this connection's server, empty when none is remembered.
// A nil Reached remembers nothing, which is what a connection built without one gets.
func (r *Reached) of(id string) string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.by[id]
}

// remember records the change that reached this connection's server. The stored settings
// working is remembered as much as any other answer: it is what stops a connection that was
// fixed properly from being started on a derived attempt for the rest of the session.
func (r *Reached) remember(id, what string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.by[id] = what
}

// preferring puts the attempt that reached this server last time first, and the rest of the
// attempts at its address immediately behind it, leaving everything else in its own order.
//
// The whole address moves rather than the one attempt, because an address is what a failure can
// condemn wholesale: the attempts at one of them have to stay together for that to mean
// anything.
//
// The settings as stored keep being tried first when nothing is remembered, and a remembered
// description that names none of the attempts -- the settings changed since -- leaves the order
// alone rather than guessing at what it meant.
func preferring(attempts []attempt, what string) []attempt {
	if what == "" {
		return attempts
	}
	at := -1
	for i, a := range attempts {
		if a.what == what {
			at = i
			break
		}
	}
	if at <= 0 {
		return attempts
	}
	here := attempts[at].endpoint
	out := make([]attempt, 0, len(attempts))
	out = append(out, attempts[at])
	for i, a := range attempts {
		if i != at && a.endpoint == here {
			out = append(out, a)
		}
	}
	for _, a := range attempts {
		if a.endpoint != here {
			out = append(out, a)
		}
	}
	return out
}

// controlDigests are the digests a server may require on a tls-auth control channel, in the
// order they are tried. They apply to a tls-auth key only: a tls-crypt channel carries its own
// and takes no digest at all.
var controlDigests = []string{"SHA512", "SHA256"}

// standardEndpoints are the port and transport an OpenVPN server answers on when nothing else
// is known: openvpn's own default, and the port a server that has to cross a firewall is put
// on. They are tried only after the configured address has failed.
var standardEndpoints = []struct{ port, proto string }{
	{"1194", config.OpenVPNProtoUDP},
	{"443", config.OpenVPNProtoTCP},
}

// change is one difference from the stored settings: what it does to a run, and what it is
// called when the connection reports which change reached the server. A change with no name
// is the settings as they stand, which is always what is tried first.
type change struct {
	what  string
	apply func(*Run)
}

// attempt is one way to start this connection.
type attempt struct {
	run Run
	// what names every difference from the stored settings, empty for the settings
	// themselves.
	what string
	// endpoint groups the attempts that dial the same address. An address that turns out to
	// carry something other than an OpenVPN server condemns all of them at once: no key and
	// no digest makes a name server answer OpenVPN.
	endpoint int
}

// stored reports whether this attempt is the settings exactly as they are held.
func (a attempt) stored() bool { return a.what == "" }

// attemptsFor is every way this connection will be started, in order, beginning with its
// settings exactly as they are stored.
//
// carried says this connection reaches its server through the connection before it in a
// chain, which settles the address: it is the loopback listener this app owns, and the
// standard ports are somewhere on this machine rather than on the server. The key material
// is still searched, because filing a key under the wrong directive is a copying mistake
// that a chain neither causes nor cures.
func attemptsFor(base Run, carried bool) []attempt {
	where := endpointChanges(base)
	if carried {
		where = where[:1]
	}
	var out []attempt
	for i, where := range where {
		for _, how := range keyChanges(base) {
			run := base
			if where.apply != nil {
				where.apply(&run)
			}
			if how.apply != nil {
				how.apply(&run)
			}
			out = append(out, attempt{run: run, what: describe(where.what, how.what), endpoint: i})
		}
	}
	return out
}

// describe joins the names of the changes one attempt carries into the phrase the connection
// reports it by.
func describe(parts ...string) string {
	var held []string
	for _, part := range parts {
		if part != "" {
			held = append(held, part)
		}
	}
	return strings.Join(held, " and ")
}

// endpointChanges are the addresses this connection will dial, its own first.
//
// The host is never changed: it is the one thing about the server that a configuration cannot
// be wrong about by a copying mistake, and dialling a different host would be this app
// choosing somebody else's server.
func endpointChanges(base Run) []change {
	out := []change{{}}
	host, port, err := net.SplitHostPort(base.Remote)
	if err != nil {
		return out
	}
	for _, ep := range standardEndpoints {
		if ep.port == port && ep.proto == base.Proto {
			continue
		}
		remote := net.JoinHostPort(host, ep.port)
		out = append(out, change{
			what: fmt.Sprintf("its server reached at %s over %s", remote, ep.proto),
			apply: func(r *Run) {
				r.Remote, r.Proto = remote, ep.proto
			},
		})
	}
	return out
}

// keyChanges are the ways this connection's key material may have been filed under the wrong
// directive, and the digests that go with the one of them that is signed.
func keyChanges(base Run) []change {
	out := []change{{}}
	switch {
	case base.TLSCrypt != "":
		out = append(out, withDigests(base, change{
			what: "its key read as a tls-auth key",
			// Direction 1 is the client's half: a server hands that out and keeps 0 itself.
			apply: func(r *Run) {
				r.TLSAuth, r.TLSCrypt, r.KeyDirection = r.TLSCrypt, "", config.OpenVPNKeyDirectionClient
			},
		})...)
	case base.TLSAuth != "":
		// The stored slot first, with the digests that channel may be signed with, then the
		// same key read the other way.
		out = append(out, withDigests(base, change{})[1:]...)
		out = append(out, change{
			what: "its key read as a tls-crypt key",
			apply: func(r *Run) {
				r.TLSCrypt, r.TLSAuth, r.KeyDirection = r.TLSAuth, "", ""
			},
		})
	}
	return out
}

// withDigests expands one key change into itself followed by the same change signed with each
// digest a server may ask for.
//
// It expands nothing when a digest is already stored: the file said which one this server
// uses, and trying others would be this app disagreeing with it.
func withDigests(base Run, slot change) []change {
	out := []change{slot}
	if base.Auth != "" {
		return out
	}
	for _, digest := range controlDigests {
		apply, name := slot.apply, digest
		out = append(out, change{
			what: describe(slot.what, "its control channel signed with "+name),
			apply: func(r *Run) {
				if apply != nil {
					apply(r)
				}
				r.Auth = name
			},
		})
	}
	return out
}
