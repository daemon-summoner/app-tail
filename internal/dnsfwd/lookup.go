// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// LookupAddrs resolves a hostname to addresses through the pool it is given.
//
// It exists because a resolver named by hostname -- tls://dns.nextdns.io, a DoH URL -- has
// to be turned into an address before it can be dialled, and the one resolver that must
// never be asked is the forwarder itself: while the override is installed, this process is
// what the machine's own resolver calls answer. So the profile's names are pinned once,
// through the network's own resolvers, and the answer is a literal address from then on.
//
// Both address families are asked for and both answers are kept, IPv4 first: a resolver
// that publishes an AAAA on a machine with no working IPv6 is a resolver that answers
// nothing, and the ordering is what makes the fallback in Pool reach the address that works.
func LookupAddrs(ctx context.Context, pool *Pool, host string) ([]netip.Addr, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if name == "" {
		return nil, fmt.Errorf("a resolver hostname is required")
	}
	if addr, err := netip.ParseAddr(name); err == nil {
		// Already an address. Answering it here keeps the caller from having to ask which
		// of its upstreams needed resolving.
		return []netip.Addr{addr}, nil
	}

	var (
		out   []netip.Addr
		fails []error
	)
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		q := Question{ID: randomID(), Name: name, Type: qtype, Class: dnsmessage.ClassINET}
		query, err := encodeQuery(q)
		if err != nil {
			return nil, err
		}
		answer, err := pool.Exchange(ctx, query, false)
		if err != nil {
			fails = append(fails, err)
			continue
		}
		addrs, err := answerAddresses(answer, name)
		if err != nil {
			fails = append(fails, fmt.Errorf("%s %s: %w", name, qtype, err))
			continue
		}
		out = append(out, addrs...)
	}
	if len(out) == 0 {
		if len(fails) > 0 {
			return nil, fmt.Errorf("looking up %s: %w", name, joinErrors(fails))
		}
		return nil, fmt.Errorf("looking up %s: this name has no address", name)
	}
	return out, nil
}

// encodeQuery encodes a query with recursion desired, which is what a stub resolver asks
// and what every forwarder above us expects to see.
func encodeQuery(q Question) ([]byte, error) {
	name, err := dnsmessage.NewName(q.fqdn())
	if err != nil {
		return nil, fmt.Errorf("%q is not a usable resolver hostname", q.Name)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: q.ID, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: q.Type, Class: q.Class}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// answerAddresses reads the addresses out of an answer, following CNAMEs by name rather than
// by trusting the order records arrive in.
func answerAddresses(msg []byte, name string) ([]netip.Addr, error) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil, errMalformed
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, errMalformed
	}
	if code, ok := rcode(msg); ok && code != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("the resolver answered %s", code)
	}

	// Names the answer is for: the one asked about, plus whatever each CNAME points at.
	wanted := map[string]bool{name: true}
	var out []netip.Addr
	for {
		h, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, errMalformed
		}
		owner := strings.TrimSuffix(strings.ToLower(h.Name.String()), ".")
		switch h.Type {
		case dnsmessage.TypeCNAME:
			body, err := p.CNAMEResource()
			if err != nil {
				return nil, errMalformed
			}
			if wanted[owner] {
				wanted[strings.TrimSuffix(strings.ToLower(body.CNAME.String()), ".")] = true
			}
		case dnsmessage.TypeA:
			body, err := p.AResource()
			if err != nil {
				return nil, errMalformed
			}
			if wanted[owner] {
				out = append(out, netip.AddrFrom4(body.A))
			}
		case dnsmessage.TypeAAAA:
			body, err := p.AAAAResource()
			if err != nil {
				return nil, errMalformed
			}
			if wanted[owner] {
				out = append(out, netip.AddrFrom16(body.AAAA))
			}
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, errMalformed
			}
		}
	}
	return out, nil
}

// joinErrors renders several failures as one line. errors.Join's newlines end up in a
// dashboard field, where a multi-line reason renders as one run-on sentence anyway.
func joinErrors(errs []error) error { return inlineErrors(errs) }

// inlineErrors is several failures reported on one line, separated the way the dashboard
// reads them, and still unwrapping to each: what a resolver could not be reached for is
// decided further up, by asking errors.Is of the whole.
type inlineErrors []error

func (e inlineErrors) Error() string {
	parts := make([]string, 0, len(e))
	for _, err := range e {
		parts = append(parts, err.Error())
	}
	return strings.Join(parts, "; ")
}

func (e inlineErrors) Unwrap() []error { return e }
