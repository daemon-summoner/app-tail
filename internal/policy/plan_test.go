// SPDX-License-Identifier: MIT

package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

const appTailTag = "tag:app-tail"

// parseResult reads a packed policy document back into the shape the planner sees.
func parseResult(t *testing.T, document []byte) policyShape {
	t.Helper()
	var shape policyShape
	standard, err := standardize(document)
	if err != nil {
		t.Fatalf("standardize result: %v", err)
	}
	if err := json.Unmarshal(standard, &shape); err != nil {
		t.Fatalf("unmarshal result %q: %v", document, err)
	}
	return shape
}

// planAndApply runs the whole pure pipeline the way Bootstrap does.
func planAndApply(t *testing.T, document string, opts Options) ([]byte, Plan) {
	t.Helper()
	plan, err := PlanBootstrap([]byte(document), opts)
	if err != nil {
		t.Fatalf("PlanBootstrap: %v", err)
	}
	updated, err := Apply([]byte(document), plan)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return updated, plan
}

func TestBootstrapAddsTheTagOwnerToAPolicyThatLacksOne(t *testing.T) {
	const document = `{
	// Existing policy the admin already maintains.
	"acls": [
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
	],
}`

	updated, plan := planAndApply(t, document, Options{Tag: appTailTag})
	if !plan.AddTagOwner {
		t.Fatal("plan did not add a tagOwner to a policy that has none")
	}

	got := parseResult(t, updated)
	owners, ok := got.TagOwners[appTailTag]
	if !ok {
		t.Fatalf("tagOwners has no %s entry: %s", appTailTag, updated)
	}
	if len(owners) != 1 || owners[0] != DefaultTagOwner {
		t.Fatalf("owners = %v, want [%s]", owners, DefaultTagOwner)
	}
}

// Clobbering an admin's comments would make this command unusable on a real,
// hand-maintained policy file.
func TestBootstrapPreservesCommentsAndUnrelatedContent(t *testing.T) {
	const document = `{
	// Engineering owns production access. Do not widen without review.
	"groups": {
		"group:eng": ["alice@example.com"], // on-call rotation
	},
	/* Classic ACL rules stay exactly as written. */
	"acls": [
		{"action": "accept", "src": ["group:eng"], "dst": ["tag:prod:22"]},
	],
}`

	updated, _ := planAndApply(t, document, Options{Tag: appTailTag})
	text := string(updated)

	for _, comment := range []string{
		"Engineering owns production access",
		"on-call rotation",
		"Classic ACL rules stay exactly as written",
	} {
		if !strings.Contains(text, comment) {
			t.Errorf("comment %q was lost:\n%s", comment, text)
		}
	}

	got := parseResult(t, updated)
	if _, ok := got.TagOwners[appTailTag]; !ok {
		t.Errorf("the tagOwner was not added:\n%s", text)
	}
	if !strings.Contains(text, "group:eng") || !strings.Contains(text, "tag:prod:22") {
		t.Errorf("unrelated policy content was lost:\n%s", text)
	}
}

// Config-management tools re-run this command; the second run must be a no-op.
func TestBootstrapIsIdempotent(t *testing.T) {
	const document = `{
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
}`
	opts := Options{Tag: appTailTag, GrantDsts: []string{"tag:llm:8100"}}

	first, firstPlan := planAndApply(t, document, opts)
	if firstPlan.Empty() {
		t.Fatal("the first run found nothing to do on a policy with no app-tail entries")
	}

	secondPlan, err := PlanBootstrap(first, opts)
	if err != nil {
		t.Fatalf("PlanBootstrap on the already-bootstrapped policy: %v", err)
	}
	if !secondPlan.Empty() {
		t.Fatalf("the second run wanted to change the policy again: %s", secondPlan.Patch)
	}

	second, err := Apply(first, secondPlan)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if string(second) != string(first) {
		t.Fatalf("re-running changed the document:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

// An existing tagOwner may name a specific team; overwriting it would silently
// widen or narrow who can enroll nodes.
func TestBootstrapLeavesAnExistingTagOwnerAlone(t *testing.T) {
	const document = `{
	"tagOwners": {
		"tag:app-tail": ["group:platform"],
	},
}`

	updated, plan := planAndApply(t, document, Options{Tag: appTailTag})
	if plan.AddTagOwner {
		t.Fatal("plan overwrote an existing tagOwner")
	}
	if !plan.Empty() {
		t.Fatalf("plan wanted to change a policy that is already correct: %s", plan.Patch)
	}

	owners := parseResult(t, updated).TagOwners[appTailTag]
	if len(owners) != 1 || owners[0] != "group:platform" {
		t.Fatalf("owners = %v, want the pre-existing [group:platform]", owners)
	}
	if len(plan.Notes) == 0 {
		t.Error("nothing explained why the tagOwner was left alone")
	}
}

func TestBootstrapAddsToAnExistingTagOwnersBlock(t *testing.T) {
	const document = `{
	"tagOwners": {
		"tag:prod": ["group:sre"],
	},
}`

	updated, plan := planAndApply(t, document, Options{Tag: appTailTag})
	if !plan.AddTagOwner {
		t.Fatal("plan did not add the app-tail tagOwner")
	}

	got := parseResult(t, updated).TagOwners
	if _, ok := got["tag:prod"]; !ok {
		t.Errorf("the existing tag:prod owner was dropped: %s", updated)
	}
	if _, ok := got[appTailTag]; !ok {
		t.Errorf("the app-tail owner was not added: %s", updated)
	}
}

func TestBootstrapHonorsExplicitOwners(t *testing.T) {
	updated, _ := planAndApply(t, `{}`, Options{
		Tag:    appTailTag,
		Owners: []string{"group:platform", "alice@example.com"},
	})

	owners := parseResult(t, updated).TagOwners[appTailTag]
	if len(owners) != 2 || owners[0] != "group:platform" || owners[1] != "alice@example.com" {
		t.Fatalf("owners = %v, want the explicitly supplied list", owners)
	}
}

// Reachability for someone else's tailnet is not this command's decision to make.
func TestNoGrantIsWrittenWithoutExplicitDestinations(t *testing.T) {
	updated, plan := planAndApply(t, `{}`, Options{Tag: appTailTag})
	if plan.AddGrant {
		t.Fatal("a grant was planned even though no destinations were given")
	}
	if len(parseResult(t, updated).Grants) != 0 {
		t.Fatalf("a grant was written: %s", updated)
	}

	var explained bool
	for _, note := range plan.Notes {
		if strings.Contains(note, "grant") {
			explained = true
		}
	}
	if !explained {
		t.Errorf("nothing told the operator that no grant was written: %v", plan.Notes)
	}
}

func TestGrantIsWrittenWhenDestinationsAreGiven(t *testing.T) {
	updated, plan := planAndApply(t, `{}`, Options{
		Tag:       appTailTag,
		GrantDsts: []string{"tag:llm:8100", "tag:db:5432"},
	})
	if !plan.AddGrant {
		t.Fatal("no grant was planned despite explicit destinations")
	}

	grants := parseResult(t, updated).Grants
	if len(grants) != 1 {
		t.Fatalf("got %d grants, want 1: %s", len(grants), updated)
	}
	g := grants[0]
	if len(g.Src) != 1 || g.Src[0] != appTailTag {
		t.Errorf("grant src = %v, want [%s]", g.Src, appTailTag)
	}
	if len(g.Dst) != 2 || g.Dst[0] != "tag:llm:8100" || g.Dst[1] != "tag:db:5432" {
		t.Errorf("grant dst = %v", g.Dst)
	}
	if len(g.IP) != 1 || g.IP[0] != "*" {
		t.Errorf("grant ip = %v, want the default [*]", g.IP)
	}
}

func TestGrantHonorsExplicitPorts(t *testing.T) {
	updated, _ := planAndApply(t, `{}`, Options{
		Tag:       appTailTag,
		GrantDsts: []string{"tag:llm"},
		GrantIPs:  []string{"tcp:8100"},
	})

	grants := parseResult(t, updated).Grants
	if len(grants) != 1 || len(grants[0].IP) != 1 || grants[0].IP[0] != "tcp:8100" {
		t.Fatalf("grant = %+v, want ip [tcp:8100]", grants)
	}
}

func TestGrantIsAppendedToAnExistingGrantsList(t *testing.T) {
	const document = `{
	"grants": [
		{"src": ["group:eng"], "dst": ["tag:prod"], "ip": ["tcp:22"]},
	],
}`

	updated, plan := planAndApply(t, document,
		Options{Tag: appTailTag, GrantDsts: []string{"tag:llm:8100"}})
	if !plan.AddGrant {
		t.Fatal("no grant was planned")
	}

	grants := parseResult(t, updated).Grants
	if len(grants) != 2 {
		t.Fatalf("got %d grants, want 2 (the existing one plus ours): %s", len(grants), updated)
	}
	if grants[0].Src[0] != "group:eng" {
		t.Errorf("the existing grant was replaced: %+v", grants[0])
	}
	if grants[1].Src[0] != appTailTag {
		t.Errorf("our grant was not appended: %+v", grants[1])
	}
}

// A tailnet may already grant app-tail narrower access than the flags request;
// adding a second, broader grant would silently widen it.
func TestNoSecondGrantIsAddedWhenOneAlreadyNamesTheTag(t *testing.T) {
	const document = `{
	"grants": [
		{"src": ["tag:app-tail"], "dst": ["tag:llm"], "ip": ["tcp:8100"]},
	],
}`

	updated, plan := planAndApply(t, document,
		Options{Tag: appTailTag, GrantDsts: []string{"*"}})
	if plan.AddGrant {
		t.Fatal("a second grant was planned for a tag that already has one")
	}

	grants := parseResult(t, updated).Grants
	if len(grants) != 1 {
		t.Fatalf("got %d grants, want the single pre-existing one", len(grants))
	}
	if len(grants[0].Dst) != 1 || grants[0].Dst[0] != "tag:llm" {
		t.Fatalf("the existing grant was widened: %+v", grants[0])
	}
}

func TestPlanRejectsBadOptions(t *testing.T) {
	tests := []struct {
		name string
		opts Options
	}{
		{"no tag", Options{}},
		{"tag without prefix", Options{Tag: "app-tail"}},
		{"tag with empty name", Options{Tag: "tag:"}},
		{"empty owner", Options{Tag: appTailTag, Owners: []string{"group:x", ""}}},
		{"empty destination", Options{Tag: appTailTag, GrantDsts: []string{""}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PlanBootstrap([]byte(`{}`), tt.opts); err == nil {
				t.Fatalf("PlanBootstrap accepted %+v", tt.opts)
			}
		})
	}
}

// A policy the API cannot parse must stop the run, not be silently replaced.
func TestPlanRefusesAnUnparsablePolicy(t *testing.T) {
	if _, err := PlanBootstrap([]byte(`{"tagOwners": `), Options{Tag: appTailTag}); err == nil {
		t.Fatal("PlanBootstrap accepted a truncated policy document")
	}
}

// A parsed HuJSON value aliases its input buffer and every transform mutates in
// place, so reading the caller's slice would quietly strip the comments out of the
// document that is about to be patched.
func TestPlanningAndApplyingDoNotMutateTheCallersDocument(t *testing.T) {
	const document = `{
	// Keep this comment.
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
}`
	buf := []byte(document)
	opts := Options{Tag: appTailTag, GrantDsts: []string{"tag:llm:8100"}}

	plan, err := PlanBootstrap(buf, opts)
	if err != nil {
		t.Fatalf("PlanBootstrap: %v", err)
	}
	if string(buf) != document {
		t.Fatalf("PlanBootstrap rewrote its input:\n%s", buf)
	}

	updated, err := Apply(buf, plan)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if string(buf) != document {
		t.Fatalf("Apply rewrote its input:\n%s", buf)
	}
	if !strings.Contains(string(updated), "Keep this comment") {
		t.Fatalf("the comment was lost from the result:\n%s", updated)
	}
}

func TestApplyOnAnEmptyPlanReturnsTheDocumentUnchanged(t *testing.T) {
	const document = "{\n\t// untouched\n}"
	got, err := Apply([]byte(document), Plan{})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if string(got) != document {
		t.Fatalf("Apply on an empty plan rewrote the document:\n%s", got)
	}
}

func TestPlanSummaryDescribesWhatWillChange(t *testing.T) {
	tests := []struct {
		plan Plan
		want string
	}{
		{Plan{}, "no policy changes needed"},
		{Plan{AddTagOwner: true}, "add tagOwners entry"},
		{Plan{AddGrant: true}, "add grant"},
		{Plan{AddTagOwner: true, AddGrant: true}, "add tagOwners entry, add grant"},
	}
	for _, tt := range tests {
		if got := tt.plan.Summary(); got != tt.want {
			t.Errorf("Summary() = %q, want %q", got, tt.want)
		}
	}
}

// PlanAll must bring every tag into the policy in one pass while preserving the
// admin's comments and unrelated content.
func TestPlanAllBringsEveryTagIntoThePolicy(t *testing.T) {
	document := `{
	// operator-maintained policy
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
}`
	updated, plans, err := PlanAll([]byte(document), []Options{
		{Tag: "tag:app-tail"},
		{Tag: "tag:app-tail-edge"},
	})
	if err != nil {
		t.Fatalf("PlanAll: %v", err)
	}
	if len(plans) != 2 {
		t.Fatalf("got %d plans, want one per option", len(plans))
	}
	got := parseResult(t, updated)
	for _, tag := range []string{"tag:app-tail", "tag:app-tail-edge"} {
		if _, ok := got.TagOwners[tag]; !ok {
			t.Errorf("tagOwners is missing %s:\n%s", tag, updated)
		}
	}
	if !strings.Contains(string(updated), "operator-maintained policy") {
		t.Errorf("the admin's comment was lost:\n%s", updated)
	}
}

// A second tag whose owner block already exists must not be duplicated: PlanAll
// plans each option against the document the prior one already patched.
func TestPlanAllIsIdempotentAcrossTags(t *testing.T) {
	document := `{"tagOwners": {"tag:app-tail": ["autogroup:admin"]}}`
	_, plans, err := PlanAll([]byte(document), []Options{
		{Tag: "tag:app-tail"},
		{Tag: "tag:app-tail"},
	})
	if err != nil {
		t.Fatalf("PlanAll: %v", err)
	}
	for i, p := range plans {
		if !p.Empty() {
			t.Errorf("plan %d proposed a change for an already-present tag: %s", i, p.Summary())
		}
	}
}

func TestCombinePlansOrsFlagsAndConcatenatesNotes(t *testing.T) {
	_, plans, err := PlanAll([]byte(`{}`), []Options{
		{Tag: "tag:app-tail"},
		{Tag: "tag:app-tail-edge", GrantDsts: []string{"tag:app-tail-edge:*"}},
	})
	if err != nil {
		t.Fatalf("PlanAll: %v", err)
	}
	combined := CombinePlans(plans)
	if !combined.AddTagOwner {
		t.Error("combined plan does not report the tag-owner additions")
	}
	if !combined.AddGrant {
		t.Error("combined plan does not report the grant addition")
	}
	if !combined.Empty() {
		t.Error("the combined summary must carry no patch of its own; apply the PlanAll document")
	}
	if len(combined.Notes) == 0 {
		t.Error("combined plan dropped the per-tag notes")
	}
}
