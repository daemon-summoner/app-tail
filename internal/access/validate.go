// SPDX-License-Identifier: MIT

package access

import (
	"errors"
	"fmt"
	"strings"
)

// Validate reports what would make this rule unusable, in the words the person editing
// it needs. A rule that cannot be read back is worse than a missing one: it sits in the
// list looking like a grant while matching nothing.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return errors.New("a rule needs an id")
	}
	switch r.Action {
	case Allow, Deny:
	case "":
		return errors.New("a rule must say whether it allows or refuses")
	default:
		return fmt.Errorf("%q is not an action; use allow or deny", r.Action)
	}
	switch r.Protocol {
	case AnyProtocol, TCP, UDP:
	default:
		return fmt.Errorf("%q is not a transport; use tcp, udp, or leave it out for both", r.Protocol)
	}
	if r.Host != "" {
		if err := ValidHostPattern(r.Host); err != nil {
			return err
		}
	}
	// A rule about nothing in particular is legitimate -- it is how a whole connection is
	// granted -- but one whose every field is empty grants the entire world through every
	// tunnel, which is never what somebody meant to type.
	if r.Tunnel == "" && r.Host == "" && !r.CIDR.IsValid() && len(r.Ports) == 0 && r.Protocol == AnyProtocol {
		return errors.New("this rule names no connection, host, address, port or transport, so it covers everything; name at least one")
	}
	if r.Ports != nil && len(r.Ports) == 0 {
		return errors.New("this rule carries an empty port list; leave the list out to cover every port")
	}
	for _, spec := range r.Ports {
		if _, _, err := ParsePorts(spec); err != nil {
			return err
		}
	}
	return nil
}

// ValidateRules checks a whole ordered list. Order is the meaning, so the list is
// validated as a list: two rules under one id make "which rule decided" unanswerable,
// which is the one question the model has to be able to answer.
func ValidateRules(rules []Rule) error {
	seen := make(map[string]bool, len(rules))
	for i, r := range rules {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
		if seen[r.ID] {
			return fmt.Errorf("rule %d repeats the id %q", i+1, r.ID)
		}
		seen[r.ID] = true
	}
	return nil
}

// ValidHostPattern reports what would make a glob unmatchable.
func ValidHostPattern(pattern string) error {
	name := normalizeHost(pattern)
	if name == "" {
		return errors.New("a host pattern cannot be blank; leave it out to cover every host")
	}
	labels := strings.Split(name, ".")
	for i, label := range labels {
		if label == "" {
			return fmt.Errorf("%q has an empty label, so nothing can match it", pattern)
		}
		if label == "**" {
			if i != 0 {
				return fmt.Errorf("%q uses ** in the middle; ** stands for the leading labels, so it belongs at the front", pattern)
			}
			continue
		}
		if strings.Contains(label, "**") {
			return fmt.Errorf("%q uses ** inside a label; within a label a single * already covers any run of characters", pattern)
		}
		if bad := strings.IndexFunc(label, notHostRune); bad >= 0 {
			return fmt.Errorf("%q carries %q, which cannot appear in a host name", pattern, label[bad:bad+1])
		}
	}
	return nil
}

// notHostRune reports a character that cannot appear in a host name or in the glob
// standing for one. Underscores are allowed because service records and a good deal of
// internal naming use them, whatever the letter of the DNS specification says.
func notHostRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return false
	case r == '-' || r == '_' || r == '*':
		return false
	}
	return true
}
