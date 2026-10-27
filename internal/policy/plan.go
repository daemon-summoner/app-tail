// SPDX-License-Identifier: MIT

// Package policy implements the opt-in, run-once tailnet policy bootstrap: it adds
// the app-tail tagOwner (and optionally a grant) to an existing ACL policy without
// disturbing anything else in it.
package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tailscale/hujson"
)

// DefaultTagOwner is who may apply the app-tail tag when the caller names nobody.
const DefaultTagOwner = "autogroup:admin"

// Options describes the bootstrap the admin asked for.
type Options struct {
	// Tag is the tag app-tail nodes self-assign, e.g. "tag:app-tail".
	Tag string
	// Owners may apply Tag. Empty means DefaultTagOwner.
	Owners []string
	// GrantDsts are the destinations tagged nodes may reach. A grant is written
	// only when this is non-empty: inventing reachability for someone else's
	// tailnet is not a decision this command gets to make silently.
	GrantDsts []string
	// GrantIPs restricts the grant's ports. Empty means all ports ("*").
	GrantIPs []string
}

// Plan is what the bootstrap would change. An empty Patch means the policy already
// says everything it needs to, which is what makes the command safe to re-run.
type Plan struct {
	AddTagOwner bool
	AddGrant    bool
	// Patch is an RFC 6902 JSON Patch applied to the policy document.
	Patch []byte
	// Notes explain what was skipped and why, for the operator to read.
	Notes []string
}

// Empty reports whether applying this plan would change nothing.
func (p Plan) Empty() bool { return len(p.Patch) == 0 }

// Summary renders the plan for the terminal.
func (p Plan) Summary() string {
	var parts []string
	if p.AddTagOwner {
		parts = append(parts, "add tagOwners entry")
	}
	if p.AddGrant {
		parts = append(parts, "add grant")
	}
	if len(parts) == 0 {
		return "no policy changes needed"
	}
	return strings.Join(parts, ", ")
}

// policyShape is the sliver of the ACL document this command reads. Everything else
// in the policy is left untouched, so unknown fields are deliberately ignored.
type policyShape struct {
	TagOwners map[string][]string `json:"tagOwners"`
	Grants    []grantShape        `json:"grants"`
}

type grantShape struct {
	Src []string `json:"src"`
	Dst []string `json:"dst"`
	IP  []string `json:"ip"`
}

// Validate checks the options before any network call is made.
func (o Options) Validate() error {
	if !strings.HasPrefix(o.Tag, "tag:") {
		return fmt.Errorf("tag %q must start with %q", o.Tag, "tag:")
	}
	if strings.TrimSpace(strings.TrimPrefix(o.Tag, "tag:")) == "" {
		return fmt.Errorf("tag %q has no name after the prefix", o.Tag)
	}
	for _, owner := range o.Owners {
		if strings.TrimSpace(owner) == "" {
			return fmt.Errorf("tag owner list contains an empty entry")
		}
	}
	for _, dst := range o.GrantDsts {
		if strings.TrimSpace(dst) == "" {
			return fmt.Errorf("grant destination list contains an empty entry")
		}
	}
	return nil
}

func (o Options) owners() []string {
	if len(o.Owners) == 0 {
		return []string{DefaultTagOwner}
	}
	return o.Owners
}

func (o Options) grantIPs() []string {
	if len(o.GrantIPs) == 0 {
		return []string{"*"}
	}
	return o.GrantIPs
}

// PlanBootstrap decides what a policy document is missing. It is pure: give it the
// current policy and it reports the patch, without touching the network.
func PlanBootstrap(document []byte, opts Options) (Plan, error) {
	if err := opts.Validate(); err != nil {
		return Plan{}, err
	}

	standard, err := standardize(document)
	if err != nil {
		return Plan{}, err
	}
	var current policyShape
	if err := json.Unmarshal(standard, &current); err != nil {
		return Plan{}, fmt.Errorf("read tailnet policy: %w", err)
	}

	var plan Plan
	var ops []json.RawMessage

	if _, ok := current.TagOwners[opts.Tag]; ok {
		plan.Notes = append(plan.Notes,
			fmt.Sprintf("tagOwners already defines %s; left as-is", opts.Tag))
	} else {
		plan.AddTagOwner = true
		op, err := tagOwnerOp(current.TagOwners == nil, opts)
		if err != nil {
			return Plan{}, err
		}
		ops = append(ops, op)
	}

	switch {
	case len(opts.GrantDsts) == 0:
		plan.Notes = append(plan.Notes,
			"no grant destinations were given, so no grant was written; tagged nodes can enroll but reach nothing until the policy grants them access")
	case hasGrantFor(current.Grants, opts.Tag):
		plan.Notes = append(plan.Notes,
			fmt.Sprintf("a grant already lists %s as a source; left as-is", opts.Tag))
	default:
		plan.AddGrant = true
		op, err := grantOp(current.Grants == nil, opts)
		if err != nil {
			return Plan{}, err
		}
		ops = append(ops, op)
	}

	if len(ops) == 0 {
		return plan, nil
	}
	patch, err := json.Marshal(ops)
	if err != nil {
		return Plan{}, fmt.Errorf("build policy patch: %w", err)
	}
	plan.Patch = patch
	return plan, nil
}

// PlanAll plans a bootstrap for each option set against the progressively patched
// document, returning the fully-patched document and every plan. This lets one
// call bring several tags into the policy while it is still written exactly once.
func PlanAll(document []byte, opts []Options) ([]byte, []Plan, error) {
	updated := document
	plans := make([]Plan, 0, len(opts))
	for _, o := range opts {
		plan, err := PlanBootstrap(updated, o)
		if err != nil {
			return nil, nil, err
		}
		next, err := Apply(updated, plan)
		if err != nil {
			return nil, nil, err
		}
		updated = next
		plans = append(plans, plan)
	}
	return updated, plans, nil
}

// CombinePlans folds per-tag plans into one summary: the booleans OR together and
// the notes concatenate. The concrete patched bytes come from PlanAll, so this
// carries no Patch of its own; use the per-plan Empty results to decide changed-ness.
func CombinePlans(plans []Plan) Plan {
	var out Plan
	for _, p := range plans {
		out.AddTagOwner = out.AddTagOwner || p.AddTagOwner
		out.AddGrant = out.AddGrant || p.AddGrant
		out.Notes = append(out.Notes, p.Notes...)
	}
	return out
}

// parsePolicy parses a HuJSON document. It parses a copy because a parsed Value
// aliases the input buffer, and every transform below mutates in place -- reading
// the caller's document would otherwise strip the comments out of it.
func parsePolicy(document []byte) (hujson.Value, error) {
	parsed, err := hujson.Parse(append([]byte(nil), document...))
	if err != nil {
		return hujson.Value{}, fmt.Errorf("parse tailnet policy: %w", err)
	}
	return parsed, nil
}

// standardize strips a HuJSON document's comments and trailing commas so
// encoding/json can read it. The caller's document is left untouched: it is what
// gets patched, and that is what preserves the admin's comments.
func standardize(document []byte) ([]byte, error) {
	parsed, err := parsePolicy(document)
	if err != nil {
		return nil, err
	}
	parsed.Standardize()
	return parsed.Pack(), nil
}

// Apply returns the patched policy document, preserving the original's comments and
// formatting everywhere the patch does not touch.
func Apply(document []byte, plan Plan) ([]byte, error) {
	if plan.Empty() {
		return document, nil
	}
	parsed, err := parsePolicy(document)
	if err != nil {
		return nil, err
	}
	if err := parsed.Patch(plan.Patch); err != nil {
		return nil, fmt.Errorf("apply policy patch: %w", err)
	}
	parsed.Format()
	return parsed.Pack(), nil
}

func tagOwnerOp(createParent bool, opts Options) (json.RawMessage, error) {
	if createParent {
		return marshalOp(map[string]any{
			"op":    "add",
			"path":  "/tagOwners",
			"value": map[string][]string{opts.Tag: opts.owners()},
		})
	}
	return marshalOp(map[string]any{
		"op":    "add",
		"path":  "/tagOwners/" + escapePointer(opts.Tag),
		"value": opts.owners(),
	})
}

func grantOp(createParent bool, opts Options) (json.RawMessage, error) {
	grant := grantShape{Src: []string{opts.Tag}, Dst: opts.GrantDsts, IP: opts.grantIPs()}
	if createParent {
		return marshalOp(map[string]any{
			"op":    "add",
			"path":  "/grants",
			"value": []grantShape{grant},
		})
	}
	// "-" appends to an existing array rather than replacing an element.
	return marshalOp(map[string]any{"op": "add", "path": "/grants/-", "value": grant})
}

func marshalOp(op map[string]any) (json.RawMessage, error) {
	raw, err := json.Marshal(op)
	if err != nil {
		return nil, fmt.Errorf("build policy patch operation: %w", err)
	}
	return raw, nil
}

func hasGrantFor(grants []grantShape, tag string) bool {
	for _, g := range grants {
		for _, src := range g.Src {
			if src == tag {
				return true
			}
		}
	}
	return false
}

// escapePointer encodes a JSON Pointer token per RFC 6901.
func escapePointer(token string) string {
	token = strings.ReplaceAll(token, "~", "~0")
	return strings.ReplaceAll(token, "/", "~1")
}
