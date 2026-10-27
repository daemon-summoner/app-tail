// SPDX-License-Identifier: MIT

package routing

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sellitus/app-tail/internal/access"
)

// Validate reports what would make this rule unusable, in the words the person editing it
// needs. A rule that cannot be read back is worse than a missing one: it sits in the table
// looking like it moves traffic while moving none.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return errors.New("a rule needs an id")
	}
	switch r.Action {
	case Via:
		if strings.TrimSpace(r.Tunnel) == "" {
			return errors.New("this rule sends traffic through a connection without saying which one")
		}
	case Direct, Block:
		if r.Tunnel != "" {
			// Silently keeping it would leave a connection id in a rule that never reads
			// it, which is how a rule ends up looking like it points somewhere it does not.
			return fmt.Errorf("this rule names the connection %s but its action is %s, "+
				"which does not go through a connection", r.Tunnel, r.Action)
		}
	case "":
		return errors.New("a rule must say where the destination goes")
	default:
		return fmt.Errorf("%q is not an action; use via, direct or block", r.Action)
	}
	if r.Host != "" {
		if err := access.ValidHostPattern(r.Host); err != nil {
			return err
		}
	}
	if r.CIDR.IsValid() && r.CIDR != r.CIDR.Masked() {
		return fmt.Errorf("%s carries host bits below its prefix; write it as %s", r.CIDR, r.CIDR.Masked())
	}
	// A rule naming neither would cover every destination, which is what the egress
	// setting already is. Accepting it would give one fact two homes, and the rule would
	// win silently over the setting the user thinks is in charge.
	if r.Host == "" && !r.CIDR.IsValid() {
		return errors.New("this rule names no host and no address range, so it covers every destination; name at least one")
	}
	return nil
}

// ValidateRules checks a whole ordered list. Order is the meaning, so the list is
// validated as a list: two rules under one id make "which rule decided" unanswerable,
// which is the one question a routing table has to be able to answer.
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
