// SPDX-License-Identifier: MIT

package httpapi

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// The connection list is the connections screen. A client reads configuration and status
// from one answer, so the two cannot describe different moments.
func TestTheConnectionListCarriesBothWhatIsStoredAndWhatIsHappening(t *testing.T) {
	h := newHarness(t)

	body := decode[struct {
		Tunnels []TunnelView `json:"tunnels"`
	}](t, h.do(t, http.MethodGet, "/api/tunnels", nil))

	if len(body.Tunnels) != 1 {
		t.Fatalf("got %d connections, want the one every install has", len(body.Tunnels))
	}
	held := body.Tunnels[0]
	if held.ID != config.PrimaryTunnelID || held.Slug != config.PrimaryTunnelSlug {
		t.Errorf("connection = %+v, want the primary one", held)
	}
	if held.State == "" || held.StateLabel == "" {
		t.Error("the connection carries no state, so a list row has nothing to show")
	}
	if held.Settings["slug"] != config.PrimaryTunnelSlug {
		t.Errorf("settings = %v, want the stored fields under their schema keys", held.Settings)
	}
}

// An empty list must serialize as an array. A nil would reach a client as null, which
// every list renderer treats as a failure rather than as "no connections yet".
func TestAnEmptyConnectionListIsAnArray(t *testing.T) {
	h := newHarness(t)
	h.tunnels.held = nil

	rec := h.do(t, http.MethodGet, "/api/tunnels", nil)

	if got := rec.Body.String(); got != "{\"tunnels\":[]}\n" {
		t.Errorf("body = %q, want an empty array", got)
	}
}

func TestOneConnectionIsFetchedByItsID(t *testing.T) {
	h := newHarness(t)

	view := decode[TunnelView](t, h.do(t, http.MethodGet, "/api/tunnels/"+config.PrimaryTunnelID, nil))

	if view.ID != config.PrimaryTunnelID {
		t.Errorf("id = %q, want %q", view.ID, config.PrimaryTunnelID)
	}
}

func TestAConnectionThatDoesNotExistIsNotFound(t *testing.T) {
	h := newHarness(t)

	requireStatus(t, h.do(t, http.MethodGet, "/api/tunnels/tn_absent", nil), http.StatusNotFound)
}

// A device belongs to the network that issued its id, so the device list has to be asked
// for per connection. A form offering one connection's devices while another is selected
// would build a forward pointing at a name the chosen network cannot resolve.
func TestTheDevicesOnOneConnectionAreServedForThatConnection(t *testing.T) {
	h := newHarness(t)
	h.tunnels.peers = map[string][]tsnode.Peer{
		config.PrimaryTunnelID: {{ID: "nA", HostName: "alpha", Online: true}},
	}

	body := decode[struct {
		Peers []tsnode.Peer `json:"peers"`
	}](t, h.do(t, http.MethodGet, "/api/tunnels/"+config.PrimaryTunnelID+"/peers", nil))

	if len(body.Peers) != 1 || body.Peers[0].ID != "nA" {
		t.Errorf("peers = %+v, want the one device on that connection", body.Peers)
	}
}

// A connection with no devices answers with an array. A nil reaches a client as null,
// which every list renderer treats as a failure rather than as "nothing on this network".
func TestAConnectionWithNoDevicesServesAnArray(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodGet, "/api/tunnels/"+config.PrimaryTunnelID+"/peers", nil)

	if got := rec.Body.String(); got != "{\"peers\":[]}\n" {
		t.Errorf("body = %q, want an empty array", got)
	}
}

func TestTheDevicesOfAConnectionThatDoesNotExistAreNotFound(t *testing.T) {
	h := newHarness(t)

	requireStatus(t, h.do(t, http.MethodGet, "/api/tunnels/tn_absent/peers", nil), http.StatusNotFound)
}

// servedSchema is the schema as it reaches a client. The field metadata is decoded as
// maps because it is serialized with named kinds a client reads and the Go type does not
// parse back -- reading it as a map is what a client actually does.
type servedSchema struct {
	Fields  []map[string]any `json:"fields"`
	Groups  []map[string]any `json:"groups"`
	Modules []map[string]any `json:"modules"`
	Types   []TunnelTypeInfo `json:"types"`
}

// The add menu is built from what the agent offers, so a client never has to hold its own
// list of protocols -- which is how one ends up offering a kind of network the build it is
// talking to cannot bring up.
func TestTheConnectionSchemaCarriesTheKindsThatCanBeAdded(t *testing.T) {
	h := newHarness(t)

	served := decode[servedSchema](t, h.do(t, http.MethodGet, "/api/tunnels/schema", nil))

	if len(served.Types) == 0 {
		t.Fatal("no kind of connection is offered, so an add menu would have nothing in it")
	}
	for _, offered := range served.Types {
		if offered.Value == "" || offered.Label == "" {
			t.Errorf("offered kind %+v is missing a value or a label", offered)
		}
	}
}

// The form is rendered from the schema, so the schema has to carry the sections its
// fields name -- otherwise a client knows a field belongs to "connection" and has no way
// to label that section.
func TestTheConnectionSchemaCarriesItsSections(t *testing.T) {
	h := newHarness(t)

	served := decode[servedSchema](t, h.do(t, http.MethodGet, "/api/tunnels/schema", nil))

	if len(served.Fields) == 0 {
		t.Fatal("the schema is empty, so the connection form would render nothing")
	}
	named := make(map[string]bool, len(served.Groups))
	for _, g := range served.Groups {
		named[g["id"].(string)] = true
	}
	for _, f := range served.Fields {
		if group, _ := f["group"].(string); !named[group] {
			t.Errorf("field %q is in section %q, which the schema does not describe", f["key"], group)
		}
	}
}

// And nothing but its sections. A client draws a heading per served section, so a section
// no connection field is in would put an empty panel on the form -- and serving the whole
// settings list would put every settings section there.
func TestTheConnectionSchemaCarriesNoSectionWithoutAField(t *testing.T) {
	h := newHarness(t)

	served := decode[servedSchema](t, h.do(t, http.MethodGet, "/api/tunnels/schema", nil))

	if len(served.Groups) == 0 {
		t.Fatal("the schema names no sections, so the form has nothing to head its fields with")
	}
	filled := make(map[string]bool, len(served.Fields))
	for _, f := range served.Fields {
		group, _ := f["group"].(string)
		filled[group] = true
	}
	for _, g := range served.Groups {
		if id, _ := g["id"].(string); !filled[id] {
			t.Errorf("section %q is served with no field in it", id)
		}
	}
}

// Several connection settings are gated on a module switched on the installation rather
// than on the connection. The schema resolves availability against how those switches
// stand when it is served, so a client that is not told which switch governs a field has
// only that frozen answer: turning the module on leaves its settings hidden until the page
// is loaded again.
func TestTheConnectionSchemaCarriesTheModulesItsFieldsAreGatedOn(t *testing.T) {
	h := newHarness(t)

	served := decode[servedSchema](t, h.do(t, http.MethodGet, "/api/tunnels/schema", nil))

	gated := make(map[string]bool, len(served.Fields))
	for _, f := range served.Fields {
		if module, _ := f["module"].(string); module != "" && module != config.ModuleCore.String() {
			gated[module] = true
		}
	}
	if len(gated) == 0 {
		t.Fatal("no connection field is gated on a module, so this rule has nothing to check " +
			"and the schema's module list would be dead weight")
	}
	described := make(map[string]bool, len(served.Modules))
	for _, m := range served.Modules {
		id, _ := m["id"].(string)
		described[id] = true
		if key, _ := m["switchKey"].(string); key == "" {
			t.Errorf("module %q is served without the key that switches it, which is the only "+
				"part a form gating on it can use", id)
		}
		if !gated[id] {
			t.Errorf("module %q is served with no connection field gated on it", id)
		}
	}
	for module := range gated {
		if !described[module] {
			t.Errorf("a connection field is gated on module %q, which the schema does not describe", module)
		}
	}
}

// A field with no label and no kind renders as a bare box with no way to know what goes
// in it, which is the failure a schema-driven form has instead of a compile error.
func TestEveryServedConnectionFieldCarriesWhatAFormNeeds(t *testing.T) {
	h := newHarness(t)

	served := decode[servedSchema](t, h.do(t, http.MethodGet, "/api/tunnels/schema", nil))

	for _, f := range served.Fields {
		for _, needed := range []string{"key", "kind", "label", "help", "group"} {
			if value, _ := f[needed].(string); value == "" {
				t.Errorf("served field %v is missing %q", f["key"], needed)
			}
		}
	}
}

// The schema path must not be read as a connection id. Both are under /api/tunnels/, and
// a mux that preferred the wildcard would answer a form request with "not found".
func TestTheSchemaPathIsNotMistakenForAConnection(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodGet, "/api/tunnels/schema", nil)

	requireStatus(t, rec, http.StatusOK)
	if len(decode[servedSchema](t, rec).Fields) == 0 {
		t.Error("the schema route answered with a connection lookup")
	}
}

func TestRenamingAConnectionReturnsItAsItNowStands(t *testing.T) {
	h := newHarness(t)

	view := decode[TunnelView](t, h.do(t, http.MethodPut,
		"/api/tunnels/"+config.PrimaryTunnelID, map[string]any{"name": "Work"}))

	if view.Name != "Work" {
		t.Errorf("name = %q, want the connection as it stands after the write", view.Name)
	}
	if _, carried := h.tunnels.patched["name"]; !carried {
		t.Errorf("the patch reached the module as %v, want the name key carried through", h.tunnels.patched)
	}
}

// A patch carries only what changed, so a body naming one field must not be read as a
// whole connection with the rest blank.
func TestAWriteCarriesOnlyTheKeysItNamed(t *testing.T) {
	h := newHarness(t)

	h.do(t, http.MethodPut, "/api/tunnels/"+config.PrimaryTunnelID, map[string]any{"name": "Work"})

	if len(h.tunnels.patched) != 1 {
		t.Errorf("the patch carried %d keys, want only the one the request named", len(h.tunnels.patched))
	}
}

func TestWritingToAConnectionThatDoesNotExistIsNotFound(t *testing.T) {
	h := newHarness(t)

	requireStatus(t, h.do(t, http.MethodPut, "/api/tunnels/tn_absent",
		map[string]any{"name": "Work"}), http.StatusNotFound)
}

// A refused write is the user's to fix, so it has to arrive as a rejection with a reason
// rather than as a fault in the agent.
func TestARefusedRenameIsReportedAsABadRequest(t *testing.T) {
	h := newHarness(t)
	h.tunnels.updateErr = &config.ValidationError{
		Field: "slug", Message: `slug "office" is already used by connection "tn_b"`,
	}

	rec := h.do(t, http.MethodPut, "/api/tunnels/"+config.PrimaryTunnelID,
		map[string]any{"slug": "office"})

	requireStatus(t, rec, http.StatusBadRequest)
	body := decode[errorBody](t, rec)
	if body.Field != "slug" {
		t.Errorf("field = %q, want the rejected control named so the form can mark it", body.Field)
	}
}

func TestAMalformedConnectionWriteIsRejected(t *testing.T) {
	h := newHarness(t)

	requireError(t, h.doRaw(t, http.MethodPut, "/api/tunnels/"+config.PrimaryTunnelID, "{not json"),
		http.StatusBadRequest, "")
}

// Adding a connection answers with the connection, and with 201 rather than 200: a client
// that has just been handed a new id has to be able to tell it was created rather than
// matched against something already there.
func TestAddingAConnectionReturnsItAsCreated(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/tunnels",
		map[string]any{"type": "tailscale", "name": "Office"})

	requireStatus(t, rec, http.StatusCreated)
	view := decode[TunnelView](t, rec)
	if view.ID == "" || view.Name != "Office" {
		t.Errorf("created %+v, want the connection that was added", view)
	}
	if h.tunnels.created == nil || h.tunnels.created.Type != config.TunnelTailscale {
		t.Errorf("the module was asked for %+v, want the type the request named", h.tunnels.created)
	}
	if len(h.tunnels.List()) != 2 {
		t.Errorf("the list holds %d connections, want the one that was there plus the new one",
			len(h.tunnels.List()))
	}
}

// The label is optional on the wire because it is derivable, and a request that leaves it
// out must not store a connection with no name a resolver can use.
func TestAddingAConnectionWithoutASlugStillGetsOne(t *testing.T) {
	h := newHarness(t)

	view := decode[TunnelView](t, h.do(t, http.MethodPost, "/api/tunnels",
		map[string]any{"type": "tailscale", "name": "Office VPN"}))

	if view.Slug != "office-vpn" {
		t.Errorf("slug = %q, want one derived from the name", view.Slug)
	}
}

// An unusable protocol is the caller's mistake, so it arrives as a rejection naming the
// control rather than as a fault in the agent.
func TestAddingAConnectionOfAnUnknownTypeIsRefused(t *testing.T) {
	h := newHarness(t)
	h.tunnels.createErr = &config.ValidationError{
		Field: "type", Message: `"ipsec" is not a kind of connection this build knows`,
	}

	rec := h.do(t, http.MethodPost, "/api/tunnels", map[string]any{"type": "ipsec"})

	requireStatus(t, rec, http.StatusBadRequest)
	if body := decode[errorBody](t, rec); body.Field != "type" {
		t.Errorf("field = %q, want the rejected control named so the form can mark it", body.Field)
	}
}

func TestAMalformedConnectionCreateIsRejected(t *testing.T) {
	h := newHarness(t)

	requireError(t, h.doRaw(t, http.MethodPost, "/api/tunnels", "{not json"),
		http.StatusBadRequest, "")
}

// Removing one answers with no content: there is no connection left to describe, and a
// body would have to invent one.
func TestRemovingAConnectionAnswersWithNoContent(t *testing.T) {
	h := newHarness(t)

	requireStatus(t, h.do(t, http.MethodDelete, "/api/tunnels/"+config.PrimaryTunnelID, nil),
		http.StatusNoContent)

	if len(h.tunnels.deleted) != 1 || h.tunnels.deleted[0] != config.PrimaryTunnelID {
		t.Errorf("the module was asked to remove %v, want the connection the path named",
			h.tunnels.deleted)
	}
}

func TestRemovingAConnectionThatDoesNotExistIsNotFound(t *testing.T) {
	h := newHarness(t)

	requireStatus(t, h.do(t, http.MethodDelete, "/api/tunnels/tn_absent", nil), http.StatusNotFound)
}

// The file has to reach the module whole. Anything that trimmed, split or re-encoded it on
// the way would change a configuration the user pasted from their server into one they
// never saw, and the difference would only show as a connection that does not come up.
func TestImportingAConfigurationHandsTheWholeFileToTheModule(t *testing.T) {
	h := newHarness(t)
	file := "[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = p\n"

	rec := h.do(t, http.MethodPost, "/api/tunnels/"+config.PrimaryTunnelID+"/import",
		map[string]any{"file": file})

	requireStatus(t, rec, http.StatusOK)
	if h.tunnels.imported != file {
		t.Errorf("the module was given %q, want the file exactly as it was sent", h.tunnels.imported)
	}
	if view := decode[TunnelView](t, rec); view.ID != config.PrimaryTunnelID {
		t.Errorf("the answer describes %q, want the connection that was imported into", view.ID)
	}
}

// A file this app cannot honour is the user's to fix -- a directive that would run a command,
// a key that is not a key -- so it arrives as a rejection carrying the reason, not as a fault.
func TestAConfigurationThatIsRefusedIsReportedAsABadRequest(t *testing.T) {
	h := newHarness(t)
	h.tunnels.importErr = &config.ValidationError{
		Field: "file", Message: "line 4: PostUp is not supported here",
	}

	rec := h.do(t, http.MethodPost, "/api/tunnels/"+config.PrimaryTunnelID+"/import",
		map[string]any{"file": "[Interface]\nPostUp = true\n"})

	requireStatus(t, rec, http.StatusBadRequest)
	body := decode[errorBody](t, rec)
	if body.Field != "file" {
		t.Errorf("field = %q, want the rejected control named so the form can mark it", body.Field)
	}
	if !strings.Contains(body.Error, "PostUp") {
		t.Errorf("error = %q, want it to name what in the file was refused", body.Error)
	}
}

func TestImportingIntoAConnectionThatDoesNotExistIsNotFound(t *testing.T) {
	h := newHarness(t)
	h.tunnels.importErr = fmt.Errorf("connection %q: %w", "tn_absent", config.ErrNotFound)

	requireStatus(t, h.do(t, http.MethodPost, "/api/tunnels/tn_absent/import",
		map[string]any{"file": "[Interface]\n"}), http.StatusNotFound)
}

func TestAMalformedImportIsRejected(t *testing.T) {
	h := newHarness(t)

	requireError(t, h.doRaw(t, http.MethodPost,
		"/api/tunnels/"+config.PrimaryTunnelID+"/import", "{not json"), http.StatusBadRequest, "")
}

// A retry asks for work rather than describing a change, so what the caller gets back is the
// connection as it now stands -- the same shape every other write on this resource answers
// with, which is what lets the screen update from the reply instead of asking again.
func TestRetryingAConnectionAsksTheModuleToBuildThatOneAgain(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/tunnels/"+config.PrimaryTunnelID+"/retry", nil)

	requireStatus(t, rec, http.StatusOK)
	if want := []string{config.PrimaryTunnelID}; !slices.Equal(h.tunnels.retried, want) {
		t.Errorf("the module was asked to build %v again, want %v", h.tunnels.retried, want)
	}
	if view := decode[TunnelView](t, rec); view.ID != config.PrimaryTunnelID {
		t.Errorf("the answer describes %q, want the connection that was retried", view.ID)
	}
}

// A connection that cannot be built again -- switched off, or a kind this build does not start
// -- is refused with the reason, because a retry that reported success and did nothing would
// leave somebody pressing it.
func TestRetryingAConnectionThatCannotBeBuiltAgainIsRefusedWithTheReason(t *testing.T) {
	h := newHarness(t)
	h.tunnels.retryErr = &config.ValidationError{Field: "id", Message: "lab is switched off."}

	rec := h.do(t, http.MethodPost, "/api/tunnels/"+config.PrimaryTunnelID+"/retry", nil)

	requireStatus(t, rec, http.StatusBadRequest)
	if body := decode[errorBody](t, rec); !strings.Contains(body.Error, "switched off") {
		t.Errorf("error = %q, want it to say why the connection was not built again", body.Error)
	}
}

func TestRetryingAConnectionThatDoesNotExistIsNotFound(t *testing.T) {
	h := newHarness(t)
	h.tunnels.retryErr = fmt.Errorf("connection %q: %w", "tn_absent", config.ErrNotFound)

	requireStatus(t, h.do(t, http.MethodPost, "/api/tunnels/tn_absent/retry", nil), http.StatusNotFound)
}
