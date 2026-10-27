// SPDX-License-Identifier: MIT

package config

// Reading the configuration file a WireGuard server hands out.
//
// Nobody types a WireGuard configuration: the server's administrator sends a file or a QR
// code and it is pasted whole. This turns that file into a connection.
//
// It refuses what it cannot honour rather than dropping it. A wg-quick file can carry
// directives that run commands on this machine, choose a routing table or mark packets for
// the machine's firewall -- none of which apply to a connection that lives inside this
// process and touches nothing outside it. Accepting such a file and quietly ignoring those
// lines would produce a connection that looks like the one the administrator described and
// silently does less, which is how a firewall rule goes missing and is never found. Every
// one is named, with what it would have done.

import (
	"fmt"
	"strconv"
	"strings"
)

// unsupportedDirectives are the wg-quick directives that do something to this machine, with
// what each one does. They are refused rather than ignored.
var unsupportedDirectives = map[string]string{
	"table":      "chooses which of this machine's routing tables the connection's routes go in, and this connection installs no routes on this machine",
	"preup":      "runs a command on this machine before the connection comes up",
	"postup":     "runs a command on this machine once the connection is up",
	"predown":    "runs a command on this machine before the connection goes down",
	"postdown":   "runs a command on this machine once the connection is down",
	"saveconfig": "has wg-quick rewrite this file when the connection stops",
	"fwmark":     "marks this connection's packets for this machine's own routing and firewall rules",
	"listenport": "pins the port this connection sends from, and this connection takes a free one so that several can run at once",
}

// ParseWireGuardQuick reads a wg-quick configuration file into a connection.
//
// It is pure: no file is read, nothing is resolved and nothing is started, so every refusal
// below is reachable from a test with a string.
func ParseWireGuardQuick(text string) (WireGuardTunnel, error) {
	var out WireGuardTunnel
	section := ""
	peers := 0

	for number, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		at := func(format string, args ...any) error {
			return fmt.Errorf("line %d: %s", number+1, fmt.Sprintf(format, args...))
		}

		if strings.HasPrefix(line, "[") {
			name, err := sectionName(line)
			if err != nil {
				return WireGuardTunnel{}, at("%s", err)
			}
			if name == "peer" {
				peers++
				if peers > 1 {
					return WireGuardTunnel{}, at("this file describes more than one server. A " +
						"connection here dials one, so add each server as its own connection")
				}
			}
			section = name
			continue
		}

		written, value, found := strings.Cut(line, "=")
		if !found {
			return WireGuardTunnel{}, at("%q is not a setting and a value", line)
		}
		// Every refusal below names the setting as the file wrote it, so it can be found in
		// the file that was pasted. Only the lookup is case-insensitive, which is how
		// wg-quick itself reads these names.
		written, value = strings.TrimSpace(written), strings.TrimSpace(value)
		key := strings.ToLower(written)
		if why, unsupported := unsupportedDirectives[key]; unsupported {
			return WireGuardTunnel{}, at("%s is not supported here: it %s", written, why)
		}
		if section == "" {
			return WireGuardTunnel{}, at("%s comes before any [Interface] or [Peer] section", written)
		}
		if err := applyDirective(&out, section, written, value); err != nil {
			return WireGuardTunnel{}, at("%s", err)
		}
	}

	if peers == 0 {
		return WireGuardTunnel{}, fmt.Errorf("this file has no [Peer] section, so it names no server to connect to")
	}
	if err := completeEnoughToConnect(out); err != nil {
		return WireGuardTunnel{}, err
	}
	return out, nil
}

// applyDirective reads one setting into the connection.
//
// A setting this does not know is refused rather than skipped: an unknown name is either a
// typo, which the user wants to hear about, or a directive with a meaning this connection
// does not implement, which is the case the whole file is strict about.
func applyDirective(out *WireGuardTunnel, section, written, value string) error {
	if section == "peer" {
		return applyPeerDirective(&out.Peer, written, value)
	}
	return applyInterfaceDirective(out, written, value)
}

func applyInterfaceDirective(out *WireGuardTunnel, written, value string) error {
	switch strings.ToLower(written) {
	case "privatekey":
		if _, err := ParseWireGuardKey(value); err != nil {
			return fmt.Errorf("PrivateKey %w", err)
		}
		out.PrivateKey = value
	case "address":
		addrs, err := ParseInterfaceAddrList(splitList(value))
		if err != nil {
			return fmt.Errorf("Address %w", err)
		}
		out.Addresses = addrs
	case "dns":
		resolvers, err := ParseAddrList(splitList(value))
		if err != nil {
			// wg-quick also accepts search domains on this line. This connection resolves
			// names it is given rather than completing short ones, so a domain here would
			// change nothing and saying so is better than dropping it.
			return fmt.Errorf("DNS must be the addresses of resolvers inside the network; "+
				"search domains are set on the connection itself: %w", err)
		}
		out.DNS = resolvers
	case "mtu":
		mtu, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("MTU must be a number, got %q", value)
		}
		if mtu < MinWireGuardMTU || mtu > MaxWireGuardMTU {
			return fmt.Errorf("MTU must be between %d and %d, got %d", MinWireGuardMTU, MaxWireGuardMTU, mtu)
		}
		out.MTU = mtu
	default:
		return fmt.Errorf("%s is not a setting the [Interface] section has", written)
	}
	return nil
}

func applyPeerDirective(out *WireGuardPeer, written, value string) error {
	switch strings.ToLower(written) {
	case "publickey":
		if _, err := ParseWireGuardKey(value); err != nil {
			return fmt.Errorf("PublicKey %w", err)
		}
		out.PublicKey = value
	case "presharedkey":
		if _, err := ParseWireGuardKey(value); err != nil {
			return fmt.Errorf("PresharedKey %w", err)
		}
		out.PresharedKey = value
	case "endpoint":
		if ok, why := ValidWireGuardEndpoint(value); !ok {
			return fmt.Errorf("Endpoint %s", why)
		}
		out.Endpoint = value
	case "allowedips":
		carried, err := ParsePrefixList(splitList(value))
		if err != nil {
			return fmt.Errorf("AllowedIPs %w", err)
		}
		out.AllowedIPs = carried
	case "persistentkeepalive":
		// wg-quick writes "off" for none, which is what this connection does with zero.
		if strings.EqualFold(value, "off") {
			out.KeepaliveSec = 0
			return nil
		}
		seconds, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("PersistentKeepalive must be a number of seconds or off, got %q", value)
		}
		if seconds < 0 || seconds > MaxWireGuardKeepaliveSec {
			return fmt.Errorf("PersistentKeepalive must be between 0 and %d seconds, got %d",
				MaxWireGuardKeepaliveSec, seconds)
		}
		out.KeepaliveSec = seconds
	default:
		return fmt.Errorf("%s is not a setting the [Peer] section has", written)
	}
	return nil
}

// completeEnoughToConnect refuses a file missing something a connection cannot be made
// without. A truncated or half-pasted file is far likelier than a deliberate one, and a
// connection saved without these is one that fails at the moment it is switched on rather
// than at the moment it is imported.
func completeEnoughToConnect(held WireGuardTunnel) error {
	switch {
	case held.PrivateKey == "":
		return fmt.Errorf("this file has no PrivateKey, so it does not say who this device is on the network")
	case len(held.Addresses) == 0:
		return fmt.Errorf("this file has no Address, so it does not say what this device answers at inside the network")
	case held.Peer.PublicKey == "":
		return fmt.Errorf("this file's [Peer] section has no PublicKey, so it does not say which server to trust")
	case held.Peer.Endpoint == "":
		return fmt.Errorf("this file's [Peer] section has no Endpoint. A server's own configuration " +
			"has none because it waits to be dialled; the file to import here is the one describing this device")
	case len(held.Peer.AllowedIPs) == 0:
		return fmt.Errorf("this file's [Peer] section has no AllowedIPs, so the connection would come " +
			"up and carry nothing")
	}
	return nil
}

// sectionName reads a [Section] header.
func sectionName(line string) (string, error) {
	if !strings.HasSuffix(line, "]") {
		return "", fmt.Errorf("%q opens a section and never closes it", line)
	}
	// Reported as it was written: a refusal that quotes back something the user cannot find
	// in the file they pasted is a refusal they have to translate first.
	written := strings.TrimSpace(line[1 : len(line)-1])
	name := strings.ToLower(written)
	if name != "interface" && name != "peer" {
		return "", fmt.Errorf("[%s] is not a section a WireGuard configuration has", written)
	}
	return name, nil
}

// stripComment removes a trailing comment. A '#' inside a value has no meaning in this
// format, so there is no quoting to respect.
func stripComment(line string) string {
	if at := strings.IndexByte(line, '#'); at >= 0 {
		return line[:at]
	}
	return line
}
