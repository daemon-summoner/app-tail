// SPDX-License-Identifier: MIT

// Package grants reads what an administrator has approved app-tail to do to this machine.
//
// The privileged helper changes routes and resolvers as root for an agent that runs as an
// ordinary account. Most of what that agent asks for stays inside the tailnet and the private
// ranges beside it, and needs nobody's approval. The rest moves this machine in ways its
// owner would want to have said yes to: carrying all of its traffic somewhere else, reaching
// public networks through a tunnel, deciding where its name lookups go, starting an OpenVPN
// connection to a particular server, and opening encrypted connections to read them. That yes
// is a file only root can write, and the helper reads it fresh on every request that needs it.
package grants

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Version is the shape of the document this build reads and writes.
const Version = 1

// maxFileSize bounds the document. The helper reads it as root on behalf of a request an
// unprivileged caller made, and a real one is a few hundred bytes.
const maxFileSize = 1 << 20

// Document is everything an administrator has approved.
type Document struct {
	Version int `json:"version"`
	// FullTunnel approves carrying all of this machine's traffic through app-tail: a default
	// route, as a whole or as the two halves that stand in for one.
	FullTunnel bool `json:"fullTunnel,omitempty"`
	// Routes approves sending these ranges, and anything inside them, to app-tail. A route
	// needs one when it reaches public addresses, or when it covers a network this machine is
	// attached to. It is a list of ranges rather than one switch because what is being
	// approved is a destination: a tunnel that reaches one company's public subnet is a
	// different decision from one that reaches everything, and the second is still
	// expressible as 0.0.0.0/0 and ::/0.
	Routes []netip.Prefix `json:"routes,omitempty"`
	// SystemDNS approves app-tail deciding how this machine resolves names in general: being
	// its primary resolver, or sending lookups to a resolver outside the tailnet. It covers
	// every domain as well.
	SystemDNS bool `json:"systemDns,omitempty"`
	// DNSDomains approves answering lookups for these domains and everything under them,
	// for the narrower case where app-tail resolves some names and the machine's own resolver
	// keeps the rest.
	DNSDomains []string `json:"dnsDomains,omitempty"`
	// OpenVPN approves starting a connection to each server, checked against the certificate
	// authority it was approved with.
	OpenVPN []OpenVPNRemote `json:"openvpn,omitempty"`
	// TLSInterception approves opening encrypted connections so the intrusion prevention
	// feature can read what they carry.
	TLSInterception bool `json:"tlsInterception,omitempty"`
}

// OpenVPNRemote is one server an OpenVPN connection may be started to.
type OpenVPNRemote struct {
	// Remote is the server as host:port, compared without regard to case.
	Remote string `json:"remote"`
	// CASHA256 is the SHA-256 of each certificate the connection's certificate authority
	// may hold, as lowercase hex. A connection is approved only when every certificate it
	// trusts is one of these: openvpn trusts each certificate in the bundle, so one added
	// to an approved bundle would be a server nobody approved.
	CASHA256 []string `json:"caSha256"`
}

// None is the document a machine with no approvals has.
func None() Document { return Document{Version: Version} }

// Parse reads a document, refusing one this build cannot be sure it understands.
//
// A field this build does not know is refused rather than ignored: an approval spelled wrong
// and silently dropped is a machine that refuses what its administrator meant to allow, with
// nothing saying why.
func Parse(data []byte) (Document, error) {
	if len(data) > maxFileSize {
		return Document{}, fmt.Errorf("the approvals file is %d bytes, over the %d-byte limit", len(data), maxFileSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("read the approvals file: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Document{}, errors.New("read the approvals file: it holds more than one document")
	}
	if doc.Version != Version {
		return Document{}, fmt.Errorf("the approvals file is version %d, and this build reads version %d", doc.Version, Version)
	}
	return doc.normalized()
}

// Encode is the document as it is stored.
func (d Document) Encode() ([]byte, error) {
	d.Version = Version
	norm, err := d.normalized()
	if err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(norm, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode the approvals: %w", err)
	}
	return append(raw, '\n'), nil
}

// With is this document with everything in other approved as well.
func (d Document) With(other Document) (Document, error) {
	out := Document{
		Version:         Version,
		FullTunnel:      d.FullTunnel || other.FullTunnel,
		Routes:          slices.Concat(d.Routes, other.Routes),
		SystemDNS:       d.SystemDNS || other.SystemDNS,
		DNSDomains:      slices.Concat(d.DNSDomains, other.DNSDomains),
		TLSInterception: d.TLSInterception || other.TLSInterception,
	}
	for _, remote := range slices.Concat(d.OpenVPN, other.OpenVPN) {
		i := slices.IndexFunc(out.OpenVPN, func(have OpenVPNRemote) bool { return strings.EqualFold(have.Remote, remote.Remote) })
		if i < 0 {
			out.OpenVPN = append(out.OpenVPN, OpenVPNRemote{Remote: remote.Remote, CASHA256: slices.Clone(remote.CASHA256)})
			continue
		}
		out.OpenVPN[i].CASHA256 = append(out.OpenVPN[i].CASHA256, remote.CASHA256...)
	}
	return out.normalized()
}

// normalized checks every value and puts it in the one form comparisons are made in: ranges
// masked, domains lowercase and fully qualified, digests lowercase, and no duplicates.
func (d Document) normalized() (Document, error) {
	out := Document{
		Version:         d.Version,
		FullTunnel:      d.FullTunnel,
		SystemDNS:       d.SystemDNS,
		TLSInterception: d.TLSInterception,
	}
	for _, prefix := range d.Routes {
		if !prefix.IsValid() {
			return Document{}, fmt.Errorf("%q is not an address range", prefix)
		}
		out.Routes = append(out.Routes, prefix.Masked())
	}
	out.Routes = sortedUnique(out.Routes, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	for _, domain := range d.DNSDomains {
		fqdn, err := NormalizeDomain(domain)
		if err != nil {
			return Document{}, err
		}
		out.DNSDomains = append(out.DNSDomains, fqdn)
	}
	out.DNSDomains = sortedUnique(out.DNSDomains, strings.Compare)
	for _, remote := range d.OpenVPN {
		if err := checkRemote(remote.Remote); err != nil {
			return Document{}, err
		}
		if len(remote.CASHA256) == 0 {
			return Document{}, fmt.Errorf("the approval for %s names no certificate authority to check the server against", remote.Remote)
		}
		var pins []string
		for _, pin := range remote.CASHA256 {
			pin = strings.ToLower(pin)
			if !sha256Hex.MatchString(pin) {
				return Document{}, fmt.Errorf("%q is not the SHA-256 of a certificate (64 hexadecimal digits)", pin)
			}
			pins = append(pins, pin)
		}
		out.OpenVPN = append(out.OpenVPN, OpenVPNRemote{Remote: remote.Remote, CASHA256: sortedUnique(pins, strings.Compare)})
	}
	return out, nil
}

func sortedUnique[T any](items []T, cmp func(a, b T) int) []T {
	if len(items) == 0 {
		return nil
	}
	slices.SortFunc(items, cmp)
	return slices.CompactFunc(items, func(a, b T) bool { return cmp(a, b) == 0 })
}

var (
	sha256Hex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	domainLabel = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)
)

// NormalizeDomain is a domain in the form approvals are compared in: lowercase, ending in a
// dot, and made only of the characters a DNS label carries.
func NormalizeDomain(domain string) (string, error) {
	fqdn := strings.ToLower(strings.TrimSpace(domain))
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	if fqdn == "." || len(fqdn) > 254 {
		return "", fmt.Errorf("%q is not a domain name", domain)
	}
	for _, label := range strings.Split(strings.TrimSuffix(fqdn, "."), ".") {
		if !domainLabel.MatchString(label) {
			return "", fmt.Errorf("%q is not a domain name", domain)
		}
	}
	return fqdn, nil
}

// checkRemote refuses a server that is not a host and a port.
func checkRemote(remote string) error {
	host, port, err := splitRemote(remote)
	if err != nil {
		return err
	}
	if host == "" || strings.ContainsAny(host, " \t\r\n/\\") {
		return fmt.Errorf("the server %q is not an address or a host name", remote)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("the server %q has no port between 1 and 65535", remote)
	}
	return nil
}

// splitRemote separates host:port, with an IPv6 address in brackets.
func splitRemote(remote string) (host, port string, err error) {
	if rest, ok := strings.CutPrefix(remote, "["); ok {
		end := strings.Index(rest, "]:")
		if end < 0 {
			return "", "", fmt.Errorf("the server %q is not a host and a port", remote)
		}
		return rest[:end], rest[end+2:], nil
	}
	i := strings.LastIndex(remote, ":")
	if i < 0 || strings.Count(remote, ":") > 1 {
		return "", "", fmt.Errorf("the server %q is not a host and a port", remote)
	}
	return remote[:i], remote[i+1:], nil
}
