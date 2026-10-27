// SPDX-License-Identifier: MIT

package config

// What an OpenVPN connection stores.
//
// An OpenVPN connection is a server to dial, the material that proves who this device is,
// and the networks the connection carries. Unlike the other two kinds it is not carried by
// code inside this process: the stock openvpn program does that, supervised as a separate
// program, so what is stored here is what that program has to be told.
//
// Two consequences run through every field below.
//
// The networks and resolvers are stored rather than taken from the server. openvpn is
// started so that nothing the server pushes changes this machine, because a pushed default
// route or a pushed resolver is a server reconfiguring the machine it is a guest on. What
// the connection carries is therefore what is written here, exactly as a WireGuard peer's
// allowed addresses are written there. The routes a server offers are still reported, so
// the values to fill in can be read off the connection rather than guessed.
//
// Every value here is rendered into a configuration file by a process holding
// administrator rights, so a value carrying a newline would be a directive that process
// would act on. The validators below are what stands between a stored string and that
// file: they are strict about the shape of a value rather than merely about its meaning,
// and the rendering re-encodes rather than copies.

import (
	"encoding/pem"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The transports an OpenVPN server answers on. There is no third: the protocol runs over
// one or the other, and a stored value naming anything else is a document to refuse rather
// than a transport to attempt.
const (
	OpenVPNProtoUDP = "udp"
	OpenVPNProtoTCP = "tcp"
)

// The key directions a static TLS key can be used in. Empty means the file did not say,
// which is what a tls-crypt key and a bidirectional tls-auth key both look like.
const (
	OpenVPNKeyDirectionNone   = ""
	OpenVPNKeyDirectionServer = "0"
	OpenVPNKeyDirectionClient = "1"
)

// MinOpenVPNMTU and MaxOpenVPNMTU bound the packet size, on the same reasoning as the
// WireGuard pair: below the IPv6 minimum a great deal of the internet stops working, and
// above a jumbo frame is a typo.
const (
	MinOpenVPNMTU = 1280
	MaxOpenVPNMTU = 9000
)

// MaxOpenVPNCredentialLen bounds a username or password. It is generous and finite: the
// value is answered over the management interface, where a line is a message, and an
// unbounded one is memory an untrusted configuration decides the size of.
const MaxOpenVPNCredentialLen = 512

// OpenVPNTunnel is one OpenVPN connection's server, credentials and carried networks.
type OpenVPNTunnel struct {
	// Remote is where the server answers, as host:port. A name is allowed and is resolved
	// by the openvpn program itself when the connection starts.
	Remote string `json:"remote"`
	// Proto is the transport, udp or tcp. Empty reads as udp.
	Proto string `json:"proto"`

	// CA is the certificate authority the server's certificate is checked against, in PEM.
	// It is not a secret: it is what the server's administrator publishes.
	CA string `json:"ca"`
	// Cert is this device's own certificate, in PEM. Also not a secret, and useless on its
	// own: it is the key below that proves it.
	Cert string `json:"cert"`
	// Key is the private key for that certificate, in PEM. Write-only across the API.
	Key string `json:"key"`
	// KeyPassphrase unlocks an encrypted private key. It is answered over the management
	// interface when openvpn asks for it, so it never reaches a file.
	KeyPassphrase string `json:"keyPassphrase"`

	// TLSCrypt is the static key that encrypts the control channel, from a <tls-crypt>
	// block. TLSAuth is the older form that only authenticates it, from <tls-auth>. A
	// configuration carries at most one; both are secrets.
	TLSCrypt string `json:"tlsCrypt"`
	TLSAuth  string `json:"tlsAuth"`
	// KeyDirection is which half of a tls-auth key this side uses. It applies to TLSAuth
	// only, and a client's is 1 when the file says anything at all.
	KeyDirection string `json:"keyDirection"`

	// AuthUserPass records that the server asks this connection to sign in. It is stored
	// separately from the credentials because it is a fact about the server rather than
	// about this device: an imported configuration says it long before anybody has typed a
	// username, and a connection that would be asked for one and has none should say so
	// rather than start and stall at a prompt nothing is reading.
	AuthUserPass bool `json:"authUserPass"`
	// Username and Password are the account this connection signs in with. Like the key
	// passphrase they are answered over the management interface rather than written
	// anywhere.
	Username string `json:"username"`
	Password string `json:"password"`

	// Cipher is the data-channel cipher to offer, such as AES-256-GCM. Empty leaves the
	// negotiation to openvpn, which is right for every server new enough to negotiate.
	Cipher string `json:"cipher"`
	// Auth is the digest the packet authentication uses, such as SHA256. Empty is
	// openvpn's own default, and it means nothing at all on a cipher that authenticates
	// its own data.
	Auth string `json:"auth"`
	// VerifyServerCert requires the server's certificate to be marked as a server
	// certificate, which is what stops another client of the same network presenting its
	// certificate and being taken for the server.
	VerifyServerCert bool `json:"verifyServerCert"`
	// VerifyName is the name the server's certificate must carry, and VerifyNameType how
	// it is matched -- the whole common name, a prefix of it, or the full subject. Both
	// are empty when the server is identified by its certificate authority alone.
	VerifyName     string `json:"verifyName"`
	VerifyNameType string `json:"verifyNameType"`

	// Routes are the networks reachable through this connection. They are what this app
	// installs and what it matches a destination against.
	Routes []netip.Prefix `json:"routes"`
	// DNS are the resolvers reachable inside the network.
	DNS []netip.Addr `json:"dns"`
	// MTU is the largest packet this connection carries. Zero leaves it to openvpn.
	MTU int `json:"mtu"`
}

// OVPN returns this connection's OpenVPN settings, and a zero value for a connection that
// has none, for the reason TS and WG do: a caller reading through it never has to decide
// what a missing block means.
func (t Tunnel) OVPN() OpenVPNTunnel {
	if t.OpenVPN == nil {
		return OpenVPNTunnel{}
	}
	return *t.OpenVPN
}

// ovpn returns the OpenVPN block to write into, creating it on the first write.
func (t *Tunnel) ovpn() *OpenVPNTunnel {
	if t.OpenVPN == nil {
		t.OpenVPN = &OpenVPNTunnel{}
	}
	return t.OpenVPN
}

// clone returns a copy sharing no slice with o.
func (o OpenVPNTunnel) clone() OpenVPNTunnel {
	o.Routes = append([]netip.Prefix(nil), o.Routes...)
	o.DNS = append([]netip.Addr(nil), o.DNS...)
	return o
}

// SameAs reports whether two stored OpenVPN connections would start the same program with
// the same configuration.
//
// Every value the program is built from is compared, for the reason the WireGuard
// comparison does it: a connection whose settings still render to this is left running,
// and a field missed here is an edit that is saved, reported as applied, and never reaches
// the running connection.
func (o OpenVPNTunnel) SameAs(other OpenVPNTunnel) bool {
	return o.Remote == other.Remote &&
		o.EffectiveProto() == other.EffectiveProto() &&
		o.CA == other.CA &&
		o.Cert == other.Cert &&
		o.Key == other.Key &&
		o.KeyPassphrase == other.KeyPassphrase &&
		o.TLSCrypt == other.TLSCrypt &&
		o.TLSAuth == other.TLSAuth &&
		o.KeyDirection == other.KeyDirection &&
		o.AuthUserPass == other.AuthUserPass &&
		o.Username == other.Username &&
		o.Password == other.Password &&
		o.Cipher == other.Cipher &&
		o.Auth == other.Auth &&
		o.VerifyServerCert == other.VerifyServerCert &&
		o.VerifyName == other.VerifyName &&
		o.VerifyNameType == other.VerifyNameType &&
		o.MTU == other.MTU &&
		slices.Equal(o.Routes, other.Routes) &&
		slices.Equal(o.DNS, other.DNS)
}

// EffectiveProto is the transport this connection actually uses, with an unset value
// reading as UDP.
func (o OpenVPNTunnel) EffectiveProto() string {
	if o.Proto == OpenVPNProtoTCP {
		return OpenVPNProtoTCP
	}
	return OpenVPNProtoUDP
}

// CarriedRoutes are the networks reachable through this connection: the stored routes
// without the default routes.
//
// A default route is dropped for the reason the WireGuard version drops one: it is not a
// route to a network but the statement that everything this machine sends should leave
// here, and reporting it as a network reached would have this connection claim every
// address in existence in the addressing report.
func (o OpenVPNTunnel) CarriedRoutes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(o.Routes))
	for _, prefix := range o.Routes {
		if prefix.Bits() == 0 {
			continue
		}
		out = append(out, prefix)
	}
	return out
}

// CarriesDefault reports that this connection is configured to take everything this
// machine sends. It is the OpenVPN half of the question an exit node answers on a tailnet,
// and it is read off the stored routes rather than off anything the server pushed: what a
// server offers is a suggestion, and what this machine does with its own traffic is not the
// server's to decide.
func (o OpenVPNTunnel) CarriesDefault() bool {
	for _, prefix := range o.Routes {
		if prefix.Bits() == 0 {
			return true
		}
	}
	return false
}

// The ways a server's certificate name can be checked. They are OpenVPN's own words for
// them, because they are what the imported file writes and what the rendered file has to
// carry back.
const (
	OpenVPNVerifyNone       = ""
	OpenVPNVerifyName       = "name"
	OpenVPNVerifyNamePrefix = "name-prefix"
	OpenVPNVerifySubject    = "subject"
)

// OpenVPNVerifyNameTypes are the matches in the order a picker offers them.
var OpenVPNVerifyNameTypes = []string{OpenVPNVerifyName, OpenVPNVerifyNamePrefix, OpenVPNVerifySubject}

// EffectiveVerifyNameType is how the server's certificate name is matched when one is
// required. An unset type with a name present matches the whole subject, which is what openvpn
// itself does with a bare --verify-x509-name -- and what the files that leave the match out are
// written for, since they carry the name as a subject line rather than as a common name.
func (o OpenVPNTunnel) EffectiveVerifyNameType() string {
	if slices.Contains(OpenVPNVerifyNameTypes, o.VerifyNameType) {
		return o.VerifyNameType
	}
	return OpenVPNVerifySubject
}

// The value shapes. Each one is checked here rather than where the configuration file is
// rendered, and each is deliberately a shape rather than a meaning: the file is written by
// a process holding administrator rights, and a value carrying a newline would be a
// directive in it. Nothing below accepts one.

// ovpnToken is the shape of an algorithm name: the characters OpenSSL and OpenVPN use for
// one, and nothing that could begin a second word in a configuration file.
var ovpnToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// staticKeyLine is one line of an OpenVPN static key: an even number of hex digits.
var staticKeyLine = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// staticKeyHeader matches the wrapper an OpenVPN static key is written in. The version is
// matched rather than fixed because the header is what the file says it is, and a key of a
// version this app has never seen is still material openvpn may understand.
var staticKeyHeader = regexp.MustCompile(`^-----BEGIN OpenVPN Static key V[0-9]+-----$`)

var staticKeyFooter = regexp.MustCompile(`^-----END OpenVPN Static key V[0-9]+-----$`)

// ValidOpenVPNRemote reports whether s is a server this connection can dial, and why not
// when it is not. The reason is bare: the caller names the field.
func ValidOpenVPNRemote(s string) (bool, string) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return false, "must not be empty"
	}
	host, port, err := splitHostPort(trimmed)
	if err != nil {
		return false, "must be the server's address and port, as host:port"
	}
	if host == "" {
		return false, "must name the server before the port"
	}
	if !validRemoteHost(host) {
		return false, "must name the server as an address or a host name"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false, "must end in a port between 1 and 65535"
	}
	return true, ""
}

// validRemoteHost reports whether a host is one a configuration file may carry: a literal
// address, or a name made of the characters a name is made of. It is stricter than the
// resolver would be, because the value ends up in a file a privileged process reads.
func validRemoteHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if ok, _ := ValidHostLabel(label); !ok {
			return false
		}
	}
	return true
}

// ValidHostLabel reports whether s is one label of a host name, and why not when it is
// not. It is the DNS rule with letters allowed in either case, which a configured server
// name may well be written in.
func ValidHostLabel(s string) (bool, string) {
	switch {
	case s == "":
		return false, "must not be empty"
	case len(s) > MaxSlugLen:
		return false, fmt.Sprintf("must be at most %d characters, got %d", MaxSlugLen, len(s))
	case strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-"):
		return false, "must not start or end with a hyphen"
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false, "may contain only letters, digits, hyphens and underscores"
		}
	}
	return true, ""
}

// ParseOpenVPNPEM reads one or more PEM blocks and reports them re-encoded canonically.
//
// The re-encoding is the point rather than a tidiness: what is stored is what a privileged
// process will write into a file, and a value that survives a decode and an encode carries
// only base64 and the block headers PEM allows. Anything a person pasted around the blocks
// -- a comment, a stray directive, the rest of a configuration file -- is gone from the
// result rather than trusted to be harmless.
//
// The error is bare: the caller names the field it came from.
func ParseOpenVPNPEM(text string) (string, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return "", fmt.Errorf("must not be empty")
	}
	var out strings.Builder
	rest := []byte(trimmed)
	blocks := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks++
		encoded, err := encodePEM(block)
		if err != nil {
			return "", err
		}
		out.WriteString(encoded)
	}
	if blocks == 0 {
		return "", fmt.Errorf("must be a PEM block, beginning with a -----BEGIN line")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return "", fmt.Errorf("has %d characters after the last PEM block that are not part of one",
			len(strings.TrimSpace(string(rest))))
	}
	return out.String(), nil
}

// encodePEM renders one block back to text. A block that will not re-encode is one whose
// headers carry something pem.Encode refuses, which is exactly the case this rejects
// rather than passes on.
func encodePEM(block *pem.Block) (string, error) {
	var b strings.Builder
	if err := pem.Encode(&b, block); err != nil {
		return "", fmt.Errorf("holds a PEM block that could not be read back: %w", err)
	}
	return b.String(), nil
}

// ParseOpenVPNStaticKey reads a tls-auth or tls-crypt key and reports it canonically, on
// the same terms as ParseOpenVPNPEM: what comes back is a header, hex lines and a footer,
// so nothing a person pasted around it reaches the file.
func ParseOpenVPNStaticKey(text string) (string, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return "", fmt.Errorf("must not be empty")
	}
	var header, footer string
	var body []string
	for _, raw := range strings.Split(trimmed, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case staticKeyHeader.MatchString(line):
			if header != "" {
				return "", fmt.Errorf("holds more than one key; a connection uses one")
			}
			header = line
		case staticKeyFooter.MatchString(line):
			if footer != "" {
				return "", fmt.Errorf("holds more than one key; a connection uses one")
			}
			footer = line
		case staticKeyLine.MatchString(line) && len(line)%2 == 0:
			if footer != "" {
				return "", fmt.Errorf("has key material after the -----END line")
			}
			body = append(body, strings.ToLower(line))
		default:
			return "", fmt.Errorf("has a line that is neither the key's own wrapper nor hexadecimal key material: %q", line)
		}
	}
	switch {
	case header == "":
		return "", fmt.Errorf("must begin with a -----BEGIN OpenVPN Static key----- line")
	case footer == "":
		return "", fmt.Errorf("must end with an -----END OpenVPN Static key----- line")
	case len(body) == 0:
		return "", fmt.Errorf("has no key material between its BEGIN and END lines")
	}
	return header + "\n" + strings.Join(body, "\n") + "\n" + footer + "\n", nil
}

// ValidOpenVPNCredential reports whether a username or password can be sent over the
// management interface, and why not when it cannot. A line is a message there, so a value
// carrying a newline is one that would be read as the next command.
func ValidOpenVPNCredential(s string) (bool, string) {
	if len(s) > MaxOpenVPNCredentialLen {
		return false, fmt.Sprintf("must be at most %d characters, got %d", MaxOpenVPNCredentialLen, len(s))
	}
	for _, r := range s {
		if r == '\n' || r == '\r' || r == 0 {
			return false, "must not contain a line break"
		}
	}
	return true, ""
}

// The registry's validators. Each accepts an empty value, on the same terms as the
// WireGuard set: a connection is added before it is configured, and what it needs before it
// can come up is checked where it comes up, with the whole of it in view.

func optionalOpenVPNRemote(v any) error {
	remote := strings.TrimSpace(typed[string](v))
	if remote == "" {
		return nil
	}
	if ok, why := ValidOpenVPNRemote(remote); !ok {
		return fmt.Errorf("%s", why)
	}
	return nil
}

func optionalOpenVPNPEM(v any) error {
	text := strings.TrimSpace(typed[string](v))
	if text == "" {
		return nil
	}
	_, err := ParseOpenVPNPEM(text)
	return err
}

func optionalOpenVPNStaticKey(v any) error {
	text := strings.TrimSpace(typed[string](v))
	if text == "" {
		return nil
	}
	_, err := ParseOpenVPNStaticKey(text)
	return err
}

func optionalOpenVPNToken(v any) error {
	token := strings.TrimSpace(typed[string](v))
	if token == "" {
		return nil
	}
	if !ovpnToken.MatchString(token) {
		return fmt.Errorf("must be an algorithm name such as AES-256-GCM: letters, digits, dots, " +
			"hyphens and underscores only")
	}
	return nil
}

// openVPNVerifyName checks the name a server's certificate must carry. It is written into
// the configuration file as a quoted argument, so the two characters that would end the
// quoting are refused outright rather than escaped: a distinguished name containing one is
// far likelier to be a paste that went wrong than a certificate anybody holds.
func openVPNVerifyName(v any) error {
	name := typed[string](v)
	if name == "" {
		return nil
	}
	if len(name) > 256 {
		return fmt.Errorf("must be at most 256 characters, got %d", len(name))
	}
	for _, r := range name {
		switch r {
		case '\n', '\r', 0:
			return fmt.Errorf("must not contain a line break")
		case '"', '\\':
			return fmt.Errorf("must not contain a quotation mark or a backslash")
		}
	}
	return nil
}

func openVPNCredential(v any) error {
	if ok, why := ValidOpenVPNCredential(typed[string](v)); !ok {
		return fmt.Errorf("%s", why)
	}
	return nil
}

// openVPNMTU accepts zero -- which means openvpn decides -- and otherwise the same band
// every other packet size on this app is held to.
func openVPNMTU(v any) error {
	mtu := typed[int](v)
	if mtu == 0 {
		return nil
	}
	if mtu < MinOpenVPNMTU || mtu > MaxOpenVPNMTU {
		return fmt.Errorf("must be 0 to let the connection decide, or between %d and %d, got %d",
			MinOpenVPNMTU, MaxOpenVPNMTU, mtu)
	}
	return nil
}
