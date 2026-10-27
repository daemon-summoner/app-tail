// SPDX-License-Identifier: MIT

package config

// Reading the .ovpn configuration file an OpenVPN server hands out.
//
// Nobody types an OpenVPN configuration either: the administrator sends a file with the
// certificates already pasted into it. This turns that file into a connection.
//
// It is strict in the same way the wg-quick reader is, and for a sharper reason. A .ovpn
// file is not only settings: several of its directives name a program to run, and the
// openvpn process that would run them holds administrator rights. So there is no arm here
// that passes an unrecognised line through. Every directive falls into one of three sets --
// one this connection stores, one this connection renders for itself and therefore has no
// use for, and one that does something to this machine and is refused by name with what it
// would have done. A directive in none of them is refused as unknown, which is either a
// typo worth hearing about or a feature this connection does not have.

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// dangerousDirectives are the .ovpn directives that run a program, change what account the
// connection runs as, or take the management interface this app drives. Each is refused
// with what it does.
var dangerousDirectives = map[string]string{
	"up":                         "runs a program on this machine once the connection is up",
	"down":                       "runs a program on this machine once the connection is down",
	"up-restart":                 "runs the up and down programs again on every reconnection",
	"route-up":                   "runs a program on this machine once the routes are in place",
	"route-pre-down":             "runs a program on this machine before the routes are removed",
	"ipchange":                   "runs a program on this machine when the server's address changes",
	"tls-verify":                 "runs a program to decide whether to trust the server",
	"tls-export-cert":            "writes the server's certificate into a directory for a program to read",
	"auth-user-pass-verify":      "runs a program to check an account, which is a server's directive rather than a client's",
	"client-connect":             "runs a program when a client connects, which is a server's directive rather than a client's",
	"client-disconnect":          "runs a program when a client disconnects, which is a server's directive rather than a client's",
	"learn-address":              "runs a program as addresses are learned, which is a server's directive rather than a client's",
	"plugin":                     "loads a shared library into the connection",
	"script-security":            "chooses how much the directives that run programs are allowed to do, and none of them are supported here",
	"iproute":                    "names a program to run instead of this machine's own routing command",
	"chroot":                     "confines the connection to a directory on this machine",
	"daemon":                     "detaches the connection from the program supervising it, which is what reports its state",
	"setcon":                     "changes the security context the connection runs in",
	"user":                       "changes the account the connection runs as, which app-tail decides",
	"group":                      "changes the group the connection runs as, which app-tail decides",
	"askpass":                    "reads the private key's passphrase from a file, and app-tail holds it instead",
	"config":                     "reads a second configuration file from this machine",
	"management":                 "opens a control channel, and app-tail already opens its own to run this connection",
	"management-client":          "opens a control channel, and app-tail already opens its own to run this connection",
	"management-hold":            "opens a control channel, and app-tail already opens its own to run this connection",
	"management-query-passwords": "opens a control channel, and app-tail already opens its own to run this connection",
	"management-external-key":    "opens a control channel, and app-tail already opens its own to run this connection",
	"http-proxy":                 "sends this connection through another proxy, which would put its traffic somewhere app-tail cannot account for",
	"socks-proxy":                "sends this connection through another proxy, which would put its traffic somewhere app-tail cannot account for",
	"pkcs11-providers":           "loads a smart-card library into the connection",
	"pkcs12":                     "carries the certificate and key in one binary file; export them as PEM and paste those instead",
	"secret":                     "runs the connection on a shared static key with no TLS at all",
}

// renderedDirectives are the ones this connection writes for itself. They are accepted and
// dropped: the file said something true about how an OpenVPN client behaves, and app-tail
// already decides that same thing -- which interface to open, how loud the log is, how the
// program is supervised. Naming them here rather than ignoring every unknown line is what
// keeps the unknown arm meaningful.
var renderedDirectives = map[string]bool{
	"client": true, "tls-client": true, "pull": true, "nobind": true,
	"dev": true, "dev-type": true, "dev-node": true,
	"persist-key": true, "persist-tun": true, "resolv-retry": true,
	"verb": true, "mute": true, "mute-replay-warnings": true, "nice": true,
	"float": true, "explicit-exit-notify": true, "ping": true, "ping-restart": true,
	"ping-timer-rem": true, "keepalive": true, "inactive": true,
	"reneg-sec": true, "reneg-bytes": true, "reneg-pkts": true,
	"remote-random": true, "remote-random-hostname": true,
	"connect-retry": true, "connect-retry-max": true, "connect-timeout": true,
	"sndbuf": true, "rcvbuf": true, "txqueuelen": true, "fast-io": true,
	"socket-flags": true, "mssfix": true, "tun-mtu-extra": true, "link-mtu": true,
	"topology": true, "disable-occ": true, "auth-nocache": true, "auth-retry": true,
	"ignore-unknown-option": true, "setenv": true, "machine-readable-output": true,
	"comp-noadapt": true, "allow-compression": true, "providers": true,
	"route-nopull": true, "route-noexec": true, "ifconfig-noexec": true,
	"pull-filter": true, "block-outside-dns": true, "register-dns": true,
	"windows-driver": true, "route-method": true, "route-delay": true,
	"tls-version-min": true, "tls-version-max": true, "ncp-disable": true,
	"data-ciphers": true, "data-ciphers-fallback": true, "capath": true,
	"engine": true, "nobind-local": true, "multihome": true, "suppress-timestamps": true,
}

// inlineBlocks are the file's <name>...</name> sections and where each one lands. A block
// this app has no field for is not listed, and so is refused by name like any other
// directive rather than dropped.
var inlineBlocks = map[string]func(*OpenVPNTunnel, string) error{
	"ca":        func(o *OpenVPNTunnel, body string) error { return setPEM(&o.CA, "ca", body) },
	"cert":      func(o *OpenVPNTunnel, body string) error { return setPEM(&o.Cert, "cert", body) },
	"key":       func(o *OpenVPNTunnel, body string) error { return setPEM(&o.Key, "key", body) },
	"tls-auth":  func(o *OpenVPNTunnel, body string) error { return setStaticKey(&o.TLSAuth, "tls-auth", body) },
	"tls-crypt": func(o *OpenVPNTunnel, body string) error { return setStaticKey(&o.TLSCrypt, "tls-crypt", body) },
}

// ParseOpenVPNFile reads a .ovpn configuration into a connection.
//
// It is pure: no file is read, nothing is resolved and nothing is started, so every refusal
// below is reachable from a test with a string.
func ParseOpenVPNFile(text string) (OpenVPNTunnel, error) {
	var out OpenVPNTunnel
	var port string
	remotes := 0

	lines := strings.Split(text, "\n")
	for number := 0; number < len(lines); number++ {
		line := strings.TrimSpace(strings.TrimSuffix(lines[number], "\r"))
		at := func(format string, args ...any) error {
			return fmt.Errorf("line %d: %s", number+1, fmt.Sprintf(format, args...))
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "<") {
			name, body, last, err := readInlineBlock(lines, number)
			if err != nil {
				return OpenVPNTunnel{}, at("%s", err)
			}
			apply, known := inlineBlocks[name]
			if !known {
				return OpenVPNTunnel{}, at("<%s> is not a section this connection has", name)
			}
			if err := apply(&out, body); err != nil {
				return OpenVPNTunnel{}, at("%s", err)
			}
			number = last
			continue
		}

		written, args, err := splitDirective(line)
		if err != nil {
			return OpenVPNTunnel{}, at("%s", err)
		}
		// The directive is reported as the file wrote it so it can be found in the file that
		// was pasted; only the lookup is case-insensitive, which is how openvpn reads them.
		key := strings.ToLower(strings.TrimPrefix(written, "--"))
		if why, dangerous := dangerousDirectives[key]; dangerous {
			return OpenVPNTunnel{}, at("%s is not supported here: it %s", written, why)
		}
		if renderedDirectives[key] {
			continue
		}
		if key == "remote" {
			remotes++
			// A file naming several servers is the ordinary shape of one a provider hands out:
			// the same host on four ports, or a few hosts openvpn would pick between. This
			// connection dials one, and the one it dials is the first the file names -- which
			// is the server shown on the connection afterwards, so the choice is on screen
			// rather than hidden. Add another connection for any of the others.
			if remotes > 1 {
				continue
			}
		}
		if key == "port" {
			if len(args) != 1 {
				return OpenVPNTunnel{}, at("port takes one port number")
			}
			port = args[0]
			continue
		}
		if err := applyOpenVPNDirective(&out, written, key, args); err != nil {
			return OpenVPNTunnel{}, at("%s", err)
		}
	}

	if err := completeRemote(&out, port); err != nil {
		return OpenVPNTunnel{}, err
	}
	if err := openVPNCompleteEnoughToConnect(out); err != nil {
		return OpenVPNTunnel{}, err
	}
	return out, nil
}

// applyOpenVPNDirective reads one directive into the connection.
func applyOpenVPNDirective(out *OpenVPNTunnel, written, key string, args []string) error {
	switch key {
	case "remote":
		return applyRemote(out, args)
	case "proto":
		if len(args) != 1 {
			return fmt.Errorf("proto takes one transport")
		}
		proto, err := normalizeOpenVPNProto(args[0])
		if err != nil {
			return err
		}
		out.Proto = proto
	case "ca", "cert", "key", "tls-auth", "tls-crypt":
		// A directive naming a file rather than carrying the material. There is no
		// directory to resolve it against here, and reading one off this machine on behalf
		// of a pasted configuration is not something this does.
		return fmt.Errorf("%s points at %q on this machine. Paste the file's contents into "+
			"the configuration as a <%s> section, or into the connection's own field",
			written, strings.Join(args, " "), key)
	case "key-direction":
		if len(args) != 1 || (args[0] != OpenVPNKeyDirectionServer && args[0] != OpenVPNKeyDirectionClient) {
			return fmt.Errorf("key-direction takes 0 or 1")
		}
		out.KeyDirection = args[0]
	case "cipher":
		if len(args) != 1 {
			return fmt.Errorf("cipher takes one algorithm name")
		}
		if !ovpnToken.MatchString(args[0]) {
			return fmt.Errorf("cipher %q is not an algorithm name", args[0])
		}
		out.Cipher = args[0]
	case "auth":
		if len(args) != 1 {
			return fmt.Errorf("auth takes one digest name")
		}
		if !ovpnToken.MatchString(args[0]) {
			return fmt.Errorf("auth %q is not a digest name", args[0])
		}
		out.Auth = args[0]
	case "auth-user-pass":
		if len(args) > 0 {
			return fmt.Errorf("auth-user-pass points at %q on this machine. Leave it bare: "+
				"app-tail holds the username and password and hands them over when the server asks",
				strings.Join(args, " "))
		}
		out.AuthUserPass = true
	case "remote-cert-tls":
		if len(args) != 1 || args[0] != "server" {
			return fmt.Errorf("remote-cert-tls takes server on a client configuration")
		}
		out.VerifyServerCert = true
	case "remote-cert-eku":
		// The general form of the directive above. Only the one meaning is carried, because
		// that is the only one this connection has a field for -- and quietly storing a
		// narrower check than the file asked for is the failure this whole file avoids.
		if len(args) == 1 && args[0] == "TLS Web Server Authentication" {
			out.VerifyServerCert = true
			return nil
		}
		return fmt.Errorf("remote-cert-eku %q is not a check this connection can make. "+
			"Use remote-cert-tls server, which is the same check for a client", strings.Join(args, " "))
	case "verify-x509-name":
		return applyVerifyName(out, args)
	case "comp-lzo", "compress":
		return applyCompression(written, key, args)
	case "tun-mtu":
		if len(args) != 1 {
			return fmt.Errorf("tun-mtu takes one packet size")
		}
		mtu, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("tun-mtu must be a number, got %q", args[0])
		}
		if mtu < MinOpenVPNMTU || mtu > MaxOpenVPNMTU {
			return fmt.Errorf("tun-mtu must be between %d and %d, got %d", MinOpenVPNMTU, MaxOpenVPNMTU, mtu)
		}
		out.MTU = mtu
	case "route":
		return applyOpenVPNRoute(out, args)
	case "redirect-gateway", "redirect-private":
		// The file asking for every destination to leave through this server. It is stored
		// as the route it amounts to, so this connection reports that it carries everything
		// -- and whether this machine's traffic actually goes that way stays the separate
		// choice it is on the other kinds of connection.
		out.Routes = appendPrefix(out.Routes, netip.PrefixFrom(netip.IPv4Unspecified(), 0))
	case "dhcp-option":
		return applyDHCPOption(out, args)
	default:
		return fmt.Errorf("%s is not a directive this connection supports", written)
	}
	return nil
}

// applyRemote reads a remote line: the server, and optionally the port and transport it
// answers on.
func applyRemote(out *OpenVPNTunnel, args []string) error {
	if len(args) == 0 || len(args) > 3 {
		return fmt.Errorf("remote takes a server, and optionally a port and a transport")
	}
	host := args[0]
	if !validRemoteHost(host) {
		return fmt.Errorf("remote %q is not an address or a host name", host)
	}
	out.Remote = host
	if len(args) >= 2 {
		if n, err := strconv.Atoi(args[1]); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("remote's port must be between 1 and 65535, got %q", args[1])
		}
		out.Remote = joinHostPort(host, args[1])
	}
	if len(args) == 3 {
		proto, err := normalizeOpenVPNProto(args[2])
		if err != nil {
			return err
		}
		out.Proto = proto
	}
	return nil
}

// applyVerifyName reads the check on the name in the server's certificate.
//
// A line that names no match is matched against the whole subject, which is openvpn's own
// default for a bare verify-x509-name. It matters: the files that leave the match out write
// the name as a subject line (CN=server.example.com), and matching that against a common
// name compares it to a name no certificate carries -- a connection that reaches its server,
// refuses its certificate and reports nothing a user can act on.
func applyVerifyName(out *OpenVPNTunnel, args []string) error {
	if len(args) == 0 || len(args) > 2 {
		return fmt.Errorf("verify-x509-name takes a name and optionally how to match it")
	}
	if err := openVPNVerifyName(args[0]); err != nil {
		return fmt.Errorf("verify-x509-name's name %w", err)
	}
	kind := OpenVPNVerifySubject
	if len(args) == 2 {
		switch args[1] {
		case OpenVPNVerifyName, OpenVPNVerifyNamePrefix, OpenVPNVerifySubject:
			kind = args[1]
		default:
			return fmt.Errorf("verify-x509-name's match must be name, name-prefix or subject, got %q", args[1])
		}
	}
	out.VerifyName, out.VerifyNameType = args[0], kind
	return nil
}

// compressionOff is the one argument each compression directive takes that turns compression
// off. Every other form of either directive turns it on.
var compressionOff = map[string]string{"comp-lzo": "no", "compress": "stub-v2"}

// applyCompression accepts a compression directive that turns compression off and refuses one
// that turns it on.
//
// The off form is accepted and dropped, because this connection never compresses and a file
// saying so agrees with it. It is worth accepting by name rather than refusing along with the
// rest: nearly every configuration a provider hands out carries one, and a whole file refused
// over a line asking for what already happens is a file nobody can import.
func applyCompression(written, key string, args []string) error {
	if len(args) == 1 && args[0] == compressionOff[key] {
		return nil
	}
	return fmt.Errorf("%s is not supported here: it compresses the tunnel, which lets an "+
		"observer recover parts of what is inside it. Write %s %s to turn compression off",
		written, key, compressionOff[key])
}

// applyOpenVPNRoute reads a route line into the networks this connection carries. openvpn
// writes a network and a mask; a gateway and a metric may follow and are the connection's
// own business rather than this app's, since the route is installed against the interface
// this connection opens.
func applyOpenVPNRoute(out *OpenVPNTunnel, args []string) error {
	if len(args) == 0 || len(args) > 4 {
		return fmt.Errorf("route takes a network, and optionally a mask, a gateway and a metric")
	}
	if strings.Contains(args[0], "/") {
		prefix, err := netip.ParsePrefix(args[0])
		if err != nil {
			return fmt.Errorf("route %q is not a network", args[0])
		}
		out.Routes = appendPrefix(out.Routes, prefix.Masked())
		return nil
	}
	network, err := netip.ParseAddr(args[0])
	if err != nil || !network.Is4() {
		return fmt.Errorf("route %q is not an IPv4 network, and a mask is only written for one", args[0])
	}
	// openvpn's own default when the mask is left out: a single host.
	bits := 32
	if len(args) >= 2 {
		if bits, err = maskBits(args[1]); err != nil {
			return fmt.Errorf("route's mask %q %w", args[1], err)
		}
	}
	prefix := netip.PrefixFrom(network, bits)
	if !prefix.IsValid() {
		return fmt.Errorf("route %s %s is not a network", args[0], strings.Join(args[1:], " "))
	}
	out.Routes = appendPrefix(out.Routes, prefix.Masked())
	return nil
}

// maskBits turns a dotted IPv4 mask into a prefix length. Only a contiguous mask has one,
// and a mask that is not contiguous is a typo rather than a network: no routing table on
// any platform this runs on can express it.
func maskBits(mask string) (int, error) {
	addr, err := netip.ParseAddr(mask)
	if err != nil || !addr.Is4() {
		return 0, fmt.Errorf("is not an IPv4 mask")
	}
	raw := addr.As4()
	bits := 0
	seenZero := false
	for _, b := range raw {
		for shift := 7; shift >= 0; shift-- {
			if b&(1<<shift) != 0 {
				if seenZero {
					return 0, fmt.Errorf("has ones after zeros, which is not a network mask")
				}
				bits++
				continue
			}
			seenZero = true
		}
	}
	return bits, nil
}

// applyDHCPOption reads the options a server's configuration carries for the client's own
// machine. Only the resolvers are stored: the rest name Windows settings this app does not
// write, and storing them would report a connection doing something it does not do.
func applyDHCPOption(out *OpenVPNTunnel, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("dhcp-option takes an option and its value")
	}
	switch strings.ToUpper(args[0]) {
	case "DNS", "DNS6":
		if len(args) != 2 {
			return fmt.Errorf("dhcp-option %s takes one resolver address", args[0])
		}
		addr, err := netip.ParseAddr(args[1])
		if err != nil {
			return fmt.Errorf("dhcp-option %s %q is not an address", args[0], args[1])
		}
		for _, held := range out.DNS {
			if held == addr {
				return nil
			}
		}
		out.DNS = append(out.DNS, addr)
	case "DOMAIN", "ADAPTER_DOMAIN_SUFFIX", "DOMAIN-SEARCH":
		// A search domain. This connection answers the names it is given rather than
		// completing short ones, and its own suffix comes from its short name, so saying so
		// is better than storing a value nothing would read.
		return fmt.Errorf("dhcp-option %s sets a search domain, and names on this connection "+
			"end in the suffix its short name gives it instead", args[0])
	default:
		return fmt.Errorf("dhcp-option %s is not an option this connection has", args[0])
	}
	return nil
}

// completeRemote folds a separate port line into the server address, and refuses one that
// still has no port: a connection with nowhere to dial is one that fails at the moment it is
// switched on rather than at the moment it is imported.
func completeRemote(out *OpenVPNTunnel, port string) error {
	if out.Remote == "" {
		return nil
	}
	if _, _, err := splitHostPort(out.Remote); err == nil {
		return nil
	}
	if port == "" {
		// openvpn's own default, and the port every OpenVPN server answers on unless its
		// administrator moved it.
		port = "1194"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("the port must be between 1 and 65535, got %q", port)
	}
	out.Remote = joinHostPort(out.Remote, port)
	return nil
}

// openVPNCompleteEnoughToConnect refuses a file missing something a connection cannot be
// made without, on the same terms the WireGuard reader applies: a truncated or half-pasted
// file is far likelier than a deliberate one.
func openVPNCompleteEnoughToConnect(held OpenVPNTunnel) error {
	switch {
	case held.Remote == "":
		return fmt.Errorf("this file has no remote line, so it names no server to connect to")
	case held.CA == "":
		return fmt.Errorf("this file has no <ca> section, so there is nothing to check the " +
			"server's certificate against")
	case held.Cert != "" && held.Key == "":
		return fmt.Errorf("this file has a <cert> section and no <key>, so it says who this " +
			"device is without the key that proves it")
	case held.Key != "" && held.Cert == "":
		return fmt.Errorf("this file has a <key> section and no <cert>, so it proves an " +
			"identity it does not carry")
	case held.Cert == "" && !held.AuthUserPass:
		return fmt.Errorf("this file has neither a <cert> section nor auth-user-pass, so it " +
			"gives the server no way to tell who is connecting")
	}
	return nil
}

// readInlineBlock reads a <name>...</name> section starting at the given line and reports
// its body and the line its closing tag is on.
func readInlineBlock(lines []string, start int) (name, body string, last int, err error) {
	open := strings.TrimSpace(lines[start])
	if !strings.HasSuffix(open, ">") {
		return "", "", 0, fmt.Errorf("%q opens a section and never closes the tag", open)
	}
	name = strings.ToLower(strings.TrimSpace(open[1 : len(open)-1]))
	if name == "" || strings.ContainsAny(name, " \t/") {
		return "", "", 0, fmt.Errorf("%q is not a section name", open)
	}
	closing := "</" + name + ">"
	var held []string
	for i := start + 1; i < len(lines); i++ {
		line := strings.TrimSuffix(lines[i], "\r")
		if strings.EqualFold(strings.TrimSpace(line), closing) {
			return name, strings.Join(held, "\n"), i, nil
		}
		held = append(held, line)
	}
	return "", "", 0, fmt.Errorf("the <%s> section is never closed with %s", name, closing)
}

// splitDirective splits a line into its directive and arguments, honouring the double
// quotes openvpn uses to hold an argument with spaces in it.
func splitDirective(line string) (written string, args []string, err error) {
	fields, err := splitQuoted(line)
	if err != nil {
		return "", nil, err
	}
	if len(fields) == 0 {
		return "", nil, fmt.Errorf("%q is not a directive", line)
	}
	return fields[0], fields[1:], nil
}

// splitQuoted splits on whitespace, keeping a double-quoted run together and honouring the
// backslash escape openvpn allows inside one. An unterminated quote is refused rather than
// read to the end of the line: the two readings differ, and guessing would take a value the
// file did not write.
func splitQuoted(line string) ([]string, error) {
	var fields []string
	var current strings.Builder
	inQuotes, inField, escaped := false, false, false
	for _, r := range line {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\' && inQuotes:
			escaped = true
		case r == '"':
			inQuotes, inField = !inQuotes, true
		case (r == ' ' || r == '\t') && !inQuotes:
			if inField {
				fields = append(fields, current.String())
				current.Reset()
				inField = false
			}
		default:
			current.WriteRune(r)
			inField = true
		}
	}
	if inQuotes {
		return nil, fmt.Errorf("has a quotation mark that is never closed")
	}
	if escaped {
		return nil, fmt.Errorf("ends in a backslash with nothing after it")
	}
	if inField {
		fields = append(fields, current.String())
	}
	return fields, nil
}

// setPEM stores a certificate or key block, canonically re-encoded.
func setPEM(into *string, name, body string) error {
	encoded, err := ParseOpenVPNPEM(body)
	if err != nil {
		return fmt.Errorf("the <%s> section %w", name, err)
	}
	*into = encoded
	return nil
}

// setStaticKey stores a tls-auth or tls-crypt key, canonically re-encoded.
func setStaticKey(into *string, name, body string) error {
	encoded, err := ParseOpenVPNStaticKey(body)
	if err != nil {
		return fmt.Errorf("the <%s> section %w", name, err)
	}
	*into = encoded
	return nil
}

// normalizeOpenVPNProto reduces the transport names a configuration may write to the two
// this connection stores. The suffixed forms pin an address family, which openvpn works out
// for itself from the server it resolves; the -client forms are the same transport said
// from the client's side.
func normalizeOpenVPNProto(raw string) (string, error) {
	switch strings.ToLower(raw) {
	case "udp", "udp4", "udp6", "udp-client":
		return OpenVPNProtoUDP, nil
	case "tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client":
		return OpenVPNProtoTCP, nil
	case "tcp-server", "tcp4-server", "tcp6-server":
		return "", fmt.Errorf("proto %s is a server's transport; the file to import here is the "+
			"one describing this device", raw)
	}
	return "", fmt.Errorf("proto %q is not a transport this connection speaks", raw)
}

// joinHostPort writes host:port, bracketing a literal IPv6 address so the result reads back
// as one value.
func joinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// appendPrefix adds a network to a list, keeping it free of repeats: a network entered
// twice is one network, and a duplicate makes a later decision about which entry it was
// made against ambiguous.
func appendPrefix(held []netip.Prefix, prefix netip.Prefix) []netip.Prefix {
	for _, existing := range held {
		if existing == prefix {
			return held
		}
	}
	return append(held, prefix)
}
