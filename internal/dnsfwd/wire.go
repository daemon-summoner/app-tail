// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// errMalformed is what every wire helper reports for bytes that are not a DNS message.
// The caller turns it into FORMERR rather than dropping the packet, because silence from
// a resolver reads to the machine as a resolver that is gone.
var errMalformed = errors.New("not a DNS message")

const (
	// localTTL bounds how long a client may remember an answer this package made up,
	// whether that is an address or a negative answer's SOA. A minute is short enough that
	// changing the setting behind an answer drains the caches holding it on its own, which
	// has to be enough: nothing here can reach into a client's cache to expire an entry.
	localTTL = 60
	// negativeZoneNS and negativeZoneMailbox fill the two SOA fields that would name a real
	// operator. They are under .invalid, which RFC 2606 reserves precisely so a made-up
	// name cannot collide with somebody's real one.
	negativeZoneNS      = "app-tail.invalid."
	negativeZoneMailbox = "hostmaster.app-tail.invalid."
)

// Question is what one query asks, in the terms routing decides on.
type Question struct {
	// ID is the client's transaction id, which the answer has to carry back.
	ID uint16
	// Name is lowercased with the trailing dot removed, so the root is the empty
	// string. Routing compares suffixes, and a stray dot makes every comparison wrong.
	Name  string
	Type  dnsmessage.Type
	Class dnsmessage.Class
}

// String renders the question the way a DNS tool would, for logs.
func (q Question) String() string {
	name := q.Name
	if name == "" {
		name = "."
	}
	return fmt.Sprintf("%s %s", name, q.Type)
}

// fqdn returns the name in the form the message builder wants.
func (q Question) fqdn() string {
	if q.Name == "" {
		return "."
	}
	return q.Name + "."
}

// parseQuestion reads the header and the first question. A query with no question is
// malformed for our purposes: there is nothing to route it by.
func parseQuestion(msg []byte) (Question, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return Question{}, fmt.Errorf("%w: %w", errMalformed, err)
	}
	q, err := p.Question()
	if err != nil {
		return Question{}, fmt.Errorf("%w: %w", errMalformed, err)
	}
	return Question{
		ID:    h.ID,
		Name:  strings.ToLower(strings.TrimSuffix(q.Name.String(), ".")),
		Type:  q.Type,
		Class: q.Class,
	}, nil
}

// queryID reads the transaction id without parsing anything else, which is all the answer
// path needs to hand a reply back to the right client.
func queryID(msg []byte) (uint16, bool) {
	if len(msg) < 12 {
		return 0, false
	}
	return binary.BigEndian.Uint16(msg[:2]), true
}

// setID overwrites the transaction id in place. Plain UDP gets a fresh random id on the
// way out so an off-path attacker cannot guess it, and the client's own id back.
func setID(msg []byte, id uint16) {
	if len(msg) < 2 {
		return
	}
	binary.BigEndian.PutUint16(msg[:2], id)
}

// rcode reads the response code. The EDNS extended bits live in the OPT record and carry
// nothing this package decides on, so the four header bits are the whole answer here.
func rcode(msg []byte) (dnsmessage.RCode, bool) {
	if len(msg) < 12 {
		return 0, false
	}
	return dnsmessage.RCode(msg[3] & 0x0F), true
}

// truncated reports the TC bit, which is a server saying "ask me again over TCP".
func truncated(msg []byte) bool {
	return len(msg) >= 12 && msg[2]&0x02 != 0
}

// isResponse reports the QR bit. An upstream that answers with a query is either
// confused or not talking to us.
func isResponse(msg []byte) bool {
	return len(msg) >= 12 && msg[2]&0x80 != 0
}

// answers a question reports whether a response is the answer to the question we asked.
// Plain UDP needs it: a matching id alone is 16 bits of protection against a forged
// reply, and the question section is the rest of it.
func answersQuestion(msg []byte, q Question) bool {
	got, err := parseQuestion(msg)
	if err != nil {
		return false
	}
	return got.Name == q.Name && got.Type == q.Type && got.Class == q.Class
}

// response builds a reply carrying nothing but a response code. It is the answer to
// every question this package decides without asking anyone.
func response(q Question, code dnsmessage.RCode) []byte {
	return buildResponse(q, code, false, nil, nil)
}

// truncatedResponse tells the client the answer did not fit and to ask again over TCP.
// The records are dropped: a truncated message is a signal, not a partial answer.
func truncatedResponse(q Question) []byte {
	return buildResponse(q, dnsmessage.RCodeSuccess, true, nil, nil)
}

// localhostAnswer answers the localhost zone here, as RFC 6761 requires: the name means
// this machine, and asking anyone else what it means is the mistake.
func localhostAnswer(q Question) []byte {
	var records []dnsmessage.Resource
	switch q.Type {
	case dnsmessage.TypeA:
		records = append(records, addressRecord(q, netip.AddrFrom4([4]byte{127, 0, 0, 1})))
	case dnsmessage.TypeAAAA:
		records = append(records, addressRecord(q, netip.IPv6Loopback()))
	}
	if len(records) == 0 {
		// Any other type is NOERROR with no records: the name exists and has nothing of
		// that kind, which is the true answer and is not NXDOMAIN.
		return localNegative(q, dnsmessage.RCodeSuccess)
	}
	return buildResponse(q, dnsmessage.RCodeSuccess, false, records, nil)
}

// blockedAnswer is what a name on a blocklist is answered with. All three stop the
// connection; they differ in what the program that asked does next, which is why the shape
// is the user's choice rather than this package's.
func blockedAnswer(q Question, answer BlockAnswer) []byte {
	switch answer {
	case AnswerRefused:
		// REFUSED says this resolver will not answer, not that the name has nothing, so
		// RFC 2308 does not make it a negative answer and there is no lifetime to bound.
		return response(q, dnsmessage.RCodeRefused)
	case AnswerSinkhole:
		var records []dnsmessage.Resource
		switch q.Type {
		case dnsmessage.TypeA:
			records = append(records, addressRecord(q, netip.AddrFrom4([4]byte{0, 0, 0, 0})))
		case dnsmessage.TypeAAAA:
			records = append(records, addressRecord(q, netip.IPv6Unspecified()))
		}
		if len(records) == 0 {
			// Any other type is NOERROR with no records. Answering NXDOMAIN there would say
			// the name does not exist while the A record this same list produces says it does.
			return localNegative(q, dnsmessage.RCodeSuccess)
		}
		return buildResponse(q, dnsmessage.RCodeSuccess, false, records, nil)
	default:
		return localNegative(q, dnsmessage.RCodeNameError)
	}
}

// localNegative builds a "no" this package decided itself, bounded so the client forgets
// it. Every negative answer synthesized here goes through this, whether it is NXDOMAIN or
// a NOERROR carrying no records.
//
// RFC 2308 takes the lifetime of a cached "no" from the SOA in the authority section, and
// a reply without one leaves every resolver to invent a lifetime of its own. An answer
// app-tail made up then outlives the state that produced it, with nothing on this side
// able to expire the entry early: a name stays dead after the connection serving it comes
// up, or after the blocklist that killed it was switched off.
func localNegative(q Question, code dnsmessage.RCode) []byte {
	return buildResponse(q, code, false, nil, negativeSOA(q))
}

// negativeSOA is the authority record that bounds how long a local negative answer is
// remembered. The zone is synthesized, because an answer app-tail decided has no real zone
// behind it: the queried name owns the record, and the two fields that would address a
// real operator name a reserved domain (RFC 2606) so they can never collide with one.
//
// A name too long to encode yields no record rather than no answer. The reply is then the
// unbounded one this function exists to avoid, which is worse than it could be and still
// better than failing to answer a machine that is waiting.
func negativeSOA(q Question) []dnsmessage.Resource {
	name, err := dnsmessage.NewName(q.fqdn())
	if err != nil {
		return nil
	}
	ns, err := dnsmessage.NewName(negativeZoneNS)
	if err != nil {
		return nil
	}
	mbox, err := dnsmessage.NewName(negativeZoneMailbox)
	if err != nil {
		return nil
	}
	return []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{
			Name:  name,
			Type:  dnsmessage.TypeSOA,
			Class: dnsmessage.ClassINET,
			TTL:   localTTL,
		},
		// The negative lifetime is the lesser of MinTTL and this record's own TTL, so both
		// carry it; the rest describe a transfer schedule for a zone nobody transfers.
		Body: &dnsmessage.SOAResource{
			NS: ns, MBox: mbox, Serial: 1,
			Refresh: localTTL, Retry: localTTL, Expire: localTTL, MinTTL: localTTL,
		},
	}}
}

func addressRecord(q Question, addr netip.Addr) dnsmessage.Resource {
	name, err := dnsmessage.NewName(q.fqdn())
	if err != nil {
		return dnsmessage.Resource{}
	}
	header := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: localTTL}
	if addr.Is4() {
		return dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: addr.As4()}}
	}
	return dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: addr.As16()}}
}

// buildResponse assembles a reply to q, carrying answer records and authority records. A
// name too long to encode, or a record that could not be built, degrades to a header-only
// reply carrying the same code -- the client gets an answer either way, which is the
// property that matters to a machine waiting on one.
func buildResponse(q Question, code dnsmessage.RCode, tc bool, records, authority []dnsmessage.Resource) []byte {
	header := dnsmessage.Header{
		ID:                 q.ID,
		Response:           true,
		RecursionDesired:   true,
		RecursionAvailable: true,
		Truncated:          tc,
		RCode:              code,
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), header)
	b.EnableCompression()
	if msg, err := buildBody(&b, q, records, authority); err == nil {
		return msg
	}
	return headerOnly(header)
}

func buildBody(b *dnsmessage.Builder, q Question, records, authority []dnsmessage.Resource) ([]byte, error) {
	name, err := dnsmessage.NewName(q.fqdn())
	if err != nil {
		return nil, err
	}
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: q.Type, Class: q.Class}); err != nil {
		return nil, err
	}
	if len(records) > 0 {
		if err := b.StartAnswers(); err != nil {
			return nil, err
		}
		if err := addRecords(b, records); err != nil {
			return nil, err
		}
	}
	if len(authority) > 0 {
		// Sections are written in order, and the builder allows skipping one: an answer
		// with an authority and no answers starts here.
		if err := b.StartAuthorities(); err != nil {
			return nil, err
		}
		if err := addRecords(b, authority); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// addRecords writes records into whichever section the builder is currently in.
func addRecords(b *dnsmessage.Builder, records []dnsmessage.Resource) error {
	for _, r := range records {
		var err error
		switch body := r.Body.(type) {
		case *dnsmessage.AResource:
			err = b.AResource(r.Header, *body)
		case *dnsmessage.AAAAResource:
			err = b.AAAAResource(r.Header, *body)
		case *dnsmessage.SOAResource:
			err = b.SOAResource(r.Header, *body)
		default:
			err = fmt.Errorf("cannot build a %T", r.Body)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// headerOnly is the last-resort reply: twelve bytes that say which query this answers and
// how it went.
func headerOnly(h dnsmessage.Header) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[:2], h.ID)
	msg[2] = 0x80 | 0x01 // QR, RD
	if h.Truncated {
		msg[2] |= 0x02
	}
	msg[3] = 0x80 | byte(h.RCode&0x0F) // RA
	return msg
}

// udpPayloadSize reports how large an answer the client said it can take over UDP. A
// query with no OPT record predates EDNS and gets the 512 bytes RFC 1035 allows.
func udpPayloadSize(msg []byte) int {
	opt, ok := findOPT(msg)
	if !ok || opt.class < 512 {
		return 512
	}
	if opt.class > 4096 {
		// Beyond this a UDP answer is fragmented, which middleboxes drop; the TCP retry
		// is faster than a black hole.
		return 4096
	}
	return int(opt.class)
}

// optRecord locates one OPT record inside a message.
type optRecord struct {
	// class is the OPT record's class field, which EDNS redefines as the requestor's
	// UDP payload size.
	class uint16
	// rdlenOff is the offset of the two-byte RDLENGTH field.
	rdlenOff int
	// rdata is the option list, as a sub-slice of the message.
	rdata []byte
}

// ecsOption is the EDNS Client Subnet option code (RFC 7871).
const ecsOption = 8

// stripClientSubnet removes an EDNS Client Subnet option from a query.
//
// A stub resolver that sets it is telling the upstream which network the user is on, and
// forwarding that to a resolver the user picked for privacy hands over the one thing they
// were hiding. Everything else in the OPT record -- the DO bit, the payload size, every
// other option -- is passed through untouched, so a client asking for DNSSEC still gets it.
//
// The message comes back unchanged when there is nothing to strip, so the common case
// copies nothing.
func stripClientSubnet(msg []byte) []byte {
	opt, ok := findOPT(msg)
	if !ok || len(opt.rdata) == 0 {
		return msg
	}
	kept := make([]byte, 0, len(opt.rdata))
	found := false
	for off := 0; off+4 <= len(opt.rdata); {
		code := binary.BigEndian.Uint16(opt.rdata[off:])
		length := int(binary.BigEndian.Uint16(opt.rdata[off+2:]))
		end := off + 4 + length
		if end > len(opt.rdata) {
			// A malformed option list: leave the message exactly as it came in rather
			// than rewrite bytes we cannot read.
			return msg
		}
		if code == ecsOption {
			found = true
		} else {
			kept = append(kept, opt.rdata[off:end]...)
		}
		off = end
	}
	if !found {
		return msg
	}
	rdataEnd := opt.rdlenOff + 2 + len(opt.rdata)
	out := make([]byte, 0, len(msg)-len(opt.rdata)+len(kept))
	out = append(out, msg[:opt.rdlenOff]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(kept)))
	out = append(out, kept...)
	out = append(out, msg[rdataEnd:]...)
	return out
}

// findOPT walks the message to the OPT record in the additional section.
//
// The walk is by hand rather than through the parser because the caller needs byte
// offsets to edit in place, and rebuilding the message instead would silently drop every
// record type the builder cannot encode.
func findOPT(msg []byte) (optRecord, bool) {
	if len(msg) < 12 {
		return optRecord{}, false
	}
	counts := [4]int{
		int(binary.BigEndian.Uint16(msg[4:])),
		int(binary.BigEndian.Uint16(msg[6:])),
		int(binary.BigEndian.Uint16(msg[8:])),
		int(binary.BigEndian.Uint16(msg[10:])),
	}
	off := 12
	var err error
	for i := 0; i < counts[0]; i++ {
		if off, err = skipName(msg, off); err != nil {
			return optRecord{}, false
		}
		off += 4 // QTYPE and QCLASS
		if off > len(msg) {
			return optRecord{}, false
		}
	}
	for section := 1; section < 4; section++ {
		for i := 0; i < counts[section]; i++ {
			nameEnd, err := skipName(msg, off)
			if err != nil || nameEnd+10 > len(msg) {
				return optRecord{}, false
			}
			rtype := binary.BigEndian.Uint16(msg[nameEnd:])
			rdlen := int(binary.BigEndian.Uint16(msg[nameEnd+8:]))
			rdataOff := nameEnd + 10
			if rdataOff+rdlen > len(msg) {
				return optRecord{}, false
			}
			if section == 3 && rtype == uint16(dnsmessage.TypeOPT) {
				return optRecord{
					class:    binary.BigEndian.Uint16(msg[nameEnd+2:]),
					rdlenOff: nameEnd + 8,
					rdata:    msg[rdataOff : rdataOff+rdlen],
				}, true
			}
			off = rdataOff + rdlen
		}
	}
	return optRecord{}, false
}

// skipName advances past a domain name, following the two forms a name can take: a chain
// of length-prefixed labels ending in a zero byte, or a pointer into the message, which
// ends the name where it stands.
func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errMalformed
		}
		length := int(msg[off])
		switch {
		case length == 0:
			return off + 1, nil
		case length&0xC0 == 0xC0:
			if off+2 > len(msg) {
				return 0, errMalformed
			}
			return off + 2, nil
		case length&0xC0 != 0:
			return 0, errMalformed
		default:
			off += 1 + length
		}
	}
}
