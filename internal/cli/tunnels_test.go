// SPDX-License-Identifier: MIT

package cli

// Connections from a terminal. The agent stand-in here is backed by the real connection
// registry -- the same schema, the same patch decoder, the same refusals -- so these
// tests exercise the contract rather than a restatement of it.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// fakeAgentTunnels is the connection list a stand-in agent holds, plus the live half no
// stored document carries.
type fakeAgentTunnels struct {
	mu      sync.Mutex
	stored  *config.Config
	health  map[string]*httpapi.TunnelHealth
	detail  map[string]string
	imports map[string]string
	retried []string
}

func newFakeAgentTunnels(tunnels ...config.Tunnel) *fakeAgentTunnels {
	cfg := config.Defaults()
	cfg.Tunnels = tunnels
	return &fakeAgentTunnels{
		stored:  cfg,
		health:  map[string]*httpapi.TunnelHealth{},
		detail:  map[string]string{},
		imports: map[string]string{},
	}
}

func (f *fakeAgentTunnels) view(t config.Tunnel) httpapi.TunnelView {
	state, label := tunnel.StateConnected, tunnel.StateConnected.Label()
	if !t.Enabled {
		state, label = tunnel.StateOff, tunnel.StateOff.Label()
	}
	return httpapi.TunnelView{
		ID:         t.ID,
		Type:       t.Type,
		TypeLabel:  t.Type.Label(),
		Name:       t.Name,
		Slug:       t.Slug,
		Enabled:    t.Enabled,
		Removable:  t.ID != config.PrimaryTunnelID,
		Retryable:  t.ID != config.PrimaryTunnelID && t.Enabled,
		Settings:   config.BuildTunnelView(t, &f.stored.Settings),
		State:      string(state),
		StateLabel: label,
		Live:       state.Live(),
		Detail:     f.detail[t.ID],
		Health:     f.health[t.ID],
	}
}

func (f *fakeAgentTunnels) views() []httpapi.TunnelView {
	out := make([]httpapi.TunnelView, 0, len(f.stored.Tunnels))
	for _, t := range f.stored.Tunnels {
		out = append(out, f.view(t))
	}
	return out
}

func (f *fakeAgentTunnels) find(id string) (int, bool) {
	for i, t := range f.stored.Tunnels {
		if t.ID == id {
			return i, true
		}
	}
	return 0, false
}

// routes is the connection half of the agent's API, served from the real registry.
func (f *fakeAgentTunnels) routes(t *testing.T) map[string]http.HandlerFunc {
	notFound := func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "no such connection"})
	}
	return map[string]http.HandlerFunc{
		"GET /api/tunnels": func(w http.ResponseWriter, _ *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"tunnels": f.views()})
		},
		"GET /api/tunnels/schema": func(w http.ResponseWriter, _ *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			fields := config.TunnelSchema(&f.stored.Settings)
			writeJSONResponse(t, w, http.StatusOK, httpapi.TunnelSchemaView{
				Fields:  fields,
				Groups:  config.GroupsFor(fields),
				Modules: config.ModulesFor(fields),
				Types: []httpapi.TunnelTypeInfo{
					{Value: config.TunnelWireGuard, Label: config.TunnelWireGuard.Label()},
					{Value: config.TunnelOpenVPN, Label: config.TunnelOpenVPN.Label()},
				},
			})
		},
		"GET /api/tunnels/{id}": func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			i, ok := f.find(r.PathValue("id"))
			if !ok {
				notFound(w)
				return
			}
			writeJSONResponse(t, w, http.StatusOK, f.view(f.stored.Tunnels[i]))
		},
		"POST /api/tunnels": func(w http.ResponseWriter, r *http.Request) {
			var spec httpapi.TunnelSpec
			if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
				t.Errorf("decode the connection spec: %v", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			name := spec.Name
			if name == "" {
				name = spec.Type.Label()
			}
			slug := spec.Slug
			if slug == "" {
				slug = config.SuggestSlug(name, nil)
			}
			made := config.NewTunnel("tn_made", slug, name, spec.Type)
			f.stored.Tunnels = append(f.stored.Tunnels, made)
			writeJSONResponse(t, w, http.StatusCreated, f.view(made))
		},
		"PUT /api/tunnels/{id}": func(w http.ResponseWriter, r *http.Request) {
			var patch map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Errorf("decode the patch: %v", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			i, ok := f.find(r.PathValue("id"))
			if !ok {
				notFound(w)
				return
			}
			held := f.stored.Tunnels[i]
			if err := config.ApplyTunnelPatch(&held, &f.stored.Settings, patch); err != nil {
				writeJSONResponse(t, w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			f.stored.Tunnels[i] = held
			writeJSONResponse(t, w, http.StatusOK, f.view(held))
		},
		"POST /api/tunnels/{id}/import": func(w http.ResponseWriter, r *http.Request) {
			var body httpapi.TunnelImport
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode the import: %v", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			i, ok := f.find(r.PathValue("id"))
			if !ok {
				notFound(w)
				return
			}
			f.imports[r.PathValue("id")] = body.File
			writeJSONResponse(t, w, http.StatusOK, f.view(f.stored.Tunnels[i]))
		},
		"POST /api/tunnels/{id}/retry": func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			i, ok := f.find(r.PathValue("id"))
			if !ok {
				notFound(w)
				return
			}
			f.retried = append(f.retried, r.PathValue("id"))
			writeJSONResponse(t, w, http.StatusOK, f.view(f.stored.Tunnels[i]))
		},
		"DELETE /api/tunnels/{id}": func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			i, ok := f.find(r.PathValue("id"))
			if !ok {
				notFound(w)
				return
			}
			f.stored.Tunnels = append(f.stored.Tunnels[:i], f.stored.Tunnels[i+1:]...)
			w.WriteHeader(http.StatusNoContent)
		},
	}
}

// heldOf is one stored connection as the stand-in agent now holds it.
func (f *fakeAgentTunnels) heldOf(t *testing.T, id string) config.Tunnel {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := f.find(id)
	if !ok {
		t.Fatalf("no connection %q is stored", id)
	}
	return f.stored.Tunnels[i]
}

func wireGuardTunnel(id, slug, name string) config.Tunnel {
	return config.NewTunnel(id, slug, name, config.TunnelWireGuard)
}

func openVPNTunnel(id, slug, name string) config.Tunnel {
	return config.NewTunnel(id, slug, name, config.TunnelOpenVPN)
}

// The whole reason this command exists: on a machine with no dashboard, the list of what
// this app is attached to was unreachable.
func TestConnectionListShowsEveryConnectionAndWhatItIsDoing(t *testing.T) {
	agent := newFakeAgentTunnels(
		wireGuardTunnel("tn_office", "office", "Office"),
		openVPNTunnel("tn_nord", "nord", "Nord"),
	)
	h := newHarness(t, agent.routes(t))

	if err := h.exec(append([]string{"connection", "list"}, h.cfg()...)...); err != nil {
		t.Fatalf("connection list: %v", err)
	}
	out := h.out()
	for _, want := range []string{"tn_office", "Office", "tn_nord", "Nord", "WireGuard", "OpenVPN"} {
		if !strings.Contains(out, want) {
			t.Errorf("connection list is missing %q:\n%s", want, out)
		}
	}
}

// A connection that cannot start reads as a bare state word without this, which is the
// one case somebody runs the command to understand.
func TestConnectionListFoldsInWhyAConnectionIsNotCarrying(t *testing.T) {
	agent := newFakeAgentTunnels(wireGuardTunnel("tn_office", "office", "Office"))
	agent.detail["tn_office"] = "the server refused the key"
	h := newHarness(t, agent.routes(t))

	if err := h.exec(append([]string{"connection", "list"}, h.cfg()...)...); err != nil {
		t.Fatalf("connection list: %v", err)
	}
	if out := h.out(); !strings.Contains(out, "the server refused the key") {
		t.Errorf("connection list drops the reason the connection is not carrying:\n%s", out)
	}
}

// A connection that is switched off is a choice somebody made, not a failure, and the
// state word is the only thing that says which.
func TestConnectionListSaysAConnectionIsSwitchedOffRatherThanBroken(t *testing.T) {
	held := wireGuardTunnel("tn_office", "office", "Office")
	held.Enabled = false
	h := newHarness(t, newFakeAgentTunnels(held).routes(t))

	if err := h.exec(append([]string{"connection", "list"}, h.cfg()...)...); err != nil {
		t.Fatalf("connection list: %v", err)
	}
	if out := h.out(); !strings.Contains(out, "disabled") {
		t.Errorf("a connection that is switched off does not say so:\n%s", out)
	}
}

// The settings a connection has depend on what it speaks. Printing another protocol's
// fields would invite somebody to set one, and the agent would refuse it by name.
func TestConnectionGetPrintsOnlyTheSettingsThatKindOfConnectionHas(t *testing.T) {
	agent := newFakeAgentTunnels(wireGuardTunnel("tn_office", "office", "Office"))
	h := newHarness(t, agent.routes(t))

	if err := h.exec("connection", "get", "--config", h.configPath, "office"); err != nil {
		t.Fatalf("connection get: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "wg.peer.endpoint") {
		t.Errorf("connection get leaves out a WireGuard setting of a WireGuard connection:\n%s", out)
	}
	if strings.Contains(out, "ovpn.remote") {
		t.Errorf("connection get prints an OpenVPN setting on a WireGuard connection:\n%s", out)
	}
}

// The figures that separate a connection that is up and working from one that is up and
// carrying nothing. Both report themselves connected.
func TestConnectionGetPrintsWhatTheConnectionCarried(t *testing.T) {
	agent := newFakeAgentTunnels(wireGuardTunnel("tn_office", "office", "Office"))
	agent.health["tn_office"] = &httpapi.TunnelHealth{
		Up:            2048,
		Down:          4096,
		Since:         time.Now().Add(-3 * time.Hour),
		LastHandshake: time.Now().Add(-2 * time.Minute),
	}
	h := newHarness(t, agent.routes(t))

	if err := h.exec("connection", "get", "--config", h.configPath, "office"); err != nil {
		t.Fatalf("connection get: %v", err)
	}
	out := h.out()
	for _, want := range []string{"2.0 KB sent, 4.0 KB received", "3h", "2m ago"} {
		if !strings.Contains(out, want) {
			t.Errorf("connection get is missing %q:\n%s", want, out)
		}
	}
}

// A kind that counts nothing of its own reports nothing, and the command prints nothing
// rather than a confident zero.
func TestConnectionGetPrintsNoCarriedFiguresForAConnectionNothingIsCounting(t *testing.T) {
	h := newHarness(t, newFakeAgentTunnels(wireGuardTunnel("tn_office", "office", "Office")).routes(t))

	if err := h.exec("connection", "get", "--config", h.configPath, "office"); err != nil {
		t.Fatalf("connection get: %v", err)
	}
	if out := h.out(); strings.Contains(out, "Carried") {
		t.Errorf("connection get invents carried figures for a connection nothing counts:\n%s", out)
	}
}

// Adding a connection and giving it the file its server issued is the whole headless
// setup path. Both halves have to land, in that order.
func TestConnectionAddCreatesTheConnectionAndImportsTheFileIntoIt(t *testing.T) {
	agent := newFakeAgentTunnels()
	h := newHarness(t, agent.routes(t))
	file := filepath.Join(t.TempDir(), "office.conf")
	if err := writeFile(file, "[Interface]\nPrivateKey = abc\n"); err != nil {
		t.Fatalf("write the configuration file: %v", err)
	}

	if err := h.exec("connection", "add", "--config", h.configPath,
		"--type", "wireguard", "--name", "Office", "--from-file", file); err != nil {
		t.Fatalf("connection add: %v", err)
	}

	held := agent.heldOf(t, "tn_made")
	if held.Name != "Office" || held.Type != config.TunnelWireGuard {
		t.Errorf("the connection was added as %q of kind %q, want Office of kind wireguard", held.Name, held.Type)
	}
	if got := agent.imports["tn_made"]; !strings.Contains(got, "PrivateKey = abc") {
		t.Errorf("the file was imported as %q, want the file that was read from disk", got)
	}
	if out := h.out(); !strings.Contains(out, "Office") || !strings.Contains(out, file) {
		t.Errorf("connection add does not report what it added and imported:\n%s", out)
	}
}

// The file is read before anything is created. Otherwise a typo in the path leaves an
// empty connection behind that nobody asked for and nothing explains.
func TestConnectionAddCreatesNothingWhenTheFileCannotBeRead(t *testing.T) {
	agent := newFakeAgentTunnels()
	h := newHarness(t, agent.routes(t))

	err := h.exec("connection", "add", "--config", h.configPath,
		"--type", "wireguard", "--from-file", filepath.Join(t.TempDir(), "absent.conf"))
	if err == nil {
		t.Fatal("adding a connection from a file that is not there was accepted")
	}
	for _, r := range h.recorded() {
		if r.Method == http.MethodPost && r.Path == "/api/tunnels" {
			t.Fatalf("a connection was created before the file was read; the calls were %v", h.recorded())
		}
	}
}

// --disabled means this connection never dials, so it is switched off before the file
// that tells it where to dial lands.
func TestConnectionAddSwitchesTheConnectionOffBeforeTheFileLands(t *testing.T) {
	agent := newFakeAgentTunnels()
	h := newHarness(t, agent.routes(t))
	file := filepath.Join(t.TempDir(), "office.conf")
	if err := writeFile(file, "[Interface]\nPrivateKey = abc\n"); err != nil {
		t.Fatalf("write the configuration file: %v", err)
	}

	if err := h.exec("connection", "add", "--config", h.configPath,
		"--type", "wireguard", "--from-file", file, "--disabled"); err != nil {
		t.Fatalf("connection add: %v", err)
	}

	if held := agent.heldOf(t, "tn_made"); held.Enabled {
		t.Error("a connection added with --disabled is switched on")
	}
	var order []string
	for _, r := range h.recorded() {
		if r.Method == http.MethodPut || strings.HasSuffix(r.Path, "/import") {
			order = append(order, r.Method+" "+r.Path)
		}
	}
	want := []string{"PUT /api/tunnels/tn_made", "POST /api/tunnels/tn_made/import"}
	if strings.Join(order, ", ") != strings.Join(want, ", ") {
		t.Errorf("the calls were %v, want %v -- the connection dialled before it was switched off", order, want)
	}
}

// The kinds come from the agent, so the message names what this installation can bring up.
func TestConnectionAddNamesTheKindsThisBuildOffers(t *testing.T) {
	h := newHarness(t, newFakeAgentTunnels().routes(t))

	err := h.exec("connection", "add", "--config", h.configPath, "--type", "ipsec")
	if err == nil {
		t.Fatal("a kind of connection this build cannot add was accepted")
	}
	for _, want := range []string{"wireguard", "openvpn"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal reads %q, want it to name %q as a kind that can be added", err, want)
		}
	}
}

func TestConnectionAddWithNoKindNamesTheKindsThisBuildOffers(t *testing.T) {
	h := newHarness(t, newFakeAgentTunnels().routes(t))

	err := h.exec("connection", "add", "--config", h.configPath)
	if err == nil {
		t.Fatal("adding a connection of no particular kind was accepted")
	}
	if !strings.Contains(err.Error(), "wireguard") {
		t.Errorf("the refusal reads %q, want it to name the kinds that can be added", err)
	}
}

// The value is parsed by the field's own parser, so what reaches the agent is the type
// the field stores. A number sent as the string "1400" is refused by the patch decoder.
func TestConnectionSetSendsTheValueAsTheTypeTheFieldStores(t *testing.T) {
	agent := newFakeAgentTunnels(wireGuardTunnel("tn_office", "office", "Office"))
	h := newHarness(t, agent.routes(t))

	if err := h.exec("connection", "set", "--config", h.configPath, "office", "wg.mtu", "1400"); err != nil {
		t.Fatalf("connection set: %v", err)
	}

	if got := agent.heldOf(t, "tn_office").WG().MTU; got != 1400 {
		t.Errorf("the stored MTU is %d, want 1400", got)
	}
}

// A value the field refuses never reaches the agent, and the reason is the field's own.
func TestConnectionSetRefusesAValueTheFieldDoesNotAccept(t *testing.T) {
	agent := newFakeAgentTunnels(wireGuardTunnel("tn_office", "office", "Office"))
	h := newHarness(t, agent.routes(t))

	err := h.exec("connection", "set", "--config", h.configPath, "office", "wg.mtu", "enormous")
	if err == nil {
		t.Fatal("a value that is not a number was accepted for a number field")
	}
	for _, r := range h.recorded() {
		if r.Method == http.MethodPut {
			t.Errorf("a value the field refuses was sent to the agent anyway: %v", r)
		}
	}
}

// A secret in argv is readable by every other process on the machine and lands in the
// shell history of the person who typed it.
func TestConnectionSetRefusesASecretOnTheCommandLine(t *testing.T) {
	agent := newFakeAgentTunnels(wireGuardTunnel("tn_office", "office", "Office"))
	h := newHarness(t, agent.routes(t))

	err := h.exec("connection", "set", "--config", h.configPath, "office", "wg.privateKey", "SECRETKEYMATERIAL")
	if err == nil {
		t.Fatal("a private key passed on the command line was accepted")
	}
	if !strings.Contains(err.Error(), "--value-file") {
		t.Errorf("the refusal reads %q, want it to name the way to pass a secret instead", err)
	}
	for _, r := range h.recorded() {
		if strings.Contains(r.Body, "SECRETKEYMATERIAL") {
			t.Error("the secret was sent to the agent despite the refusal")
		}
	}
}

// The way a secret is meant to be set on a machine with no dashboard.
func TestConnectionSetTakesASecretFromAFile(t *testing.T) {
	agent := newFakeAgentTunnels(wireGuardTunnel("tn_office", "office", "Office"))
	h := newHarness(t, agent.routes(t))
	key := "aFmZ0lLwtoAJRe6dpBqp1TXKPmMKMBkgPMhO+iqLbXM="
	file := filepath.Join(t.TempDir(), "private.key")
	if err := writeFile(file, key+"\n"); err != nil {
		t.Fatalf("write the key file: %v", err)
	}

	if err := h.exec("connection", "set", "--config", h.configPath,
		"--value-file", file, "office", "wg.privateKey"); err != nil {
		t.Fatalf("connection set: %v", err)
	}

	// The trailing newline every editor writes is not part of the key: stored with it, the
	// key is rejected by the device and the connection never comes up.
	if got := agent.heldOf(t, "tn_office").WG().PrivateKey; got != key {
		t.Errorf("the stored key is %q, want %q", got, key)
	}
}

func TestConnectionSetTakesAValueFromStandardInput(t *testing.T) {
	agent := newFakeAgentTunnels(openVPNTunnel("tn_nord", "nord", "Nord"))
	h := newHarness(t, agent.routes(t))
	env := h.env()
	env.Stdin = strings.NewReader("hunter2\n")

	err := Run(t.Context(), []string{"connection", "set", "--config", h.configPath,
		"--value-stdin", "nord", "ovpn.password"}, env)
	if err != nil {
		t.Fatalf("connection set: %v", err)
	}

	if got := agent.heldOf(t, "tn_nord").OVPN().Password; got != "hunter2" {
		t.Errorf("the stored password is %q, want %q", got, "hunter2")
	}
}

// A read-only field is refused by the agent's own patch decoder, and that refusal reaches
// the person who typed it. Swallowed, changing the kind of a connection would report
// success and change nothing.
func TestConnectionSetCarriesTheAgentsRefusalOfAFieldThatCannotBeWritten(t *testing.T) {
	agent := newFakeAgentTunnels(wireGuardTunnel("tn_office", "office", "Office"))
	h := newHarness(t, agent.routes(t))

	err := h.exec("connection", "set", "--config", h.configPath, "office", "type", "openvpn")
	if err == nil {
		t.Fatal("a read-only field was accepted")
	}
	if !strings.Contains(err.Error(), "read-only") {
		t.Errorf("the refusal reads %q, want it to say the field is read-only", err)
	}
	if got := agent.heldOf(t, "tn_office").Type; got != config.TunnelWireGuard {
		t.Errorf("the connection is now a %q connection, want the refused write to have changed nothing", got)
	}
}

func TestConnectionImportWritesTheFileOntoTheNamedConnection(t *testing.T) {
	agent := newFakeAgentTunnels(openVPNTunnel("tn_nord", "nord", "Nord"))
	h := newHarness(t, agent.routes(t))
	file := filepath.Join(t.TempDir(), "nord.ovpn")
	if err := writeFile(file, "client\nremote vpn.example.com 1194\n"); err != nil {
		t.Fatalf("write the configuration file: %v", err)
	}

	if err := h.exec("connection", "import", "--config", h.configPath, "Nord", file); err != nil {
		t.Fatalf("connection import: %v", err)
	}

	if got := agent.imports["tn_nord"]; !strings.Contains(got, "remote vpn.example.com 1194") {
		t.Errorf("the connection was sent %q, want the file that was read from disk", got)
	}
}

// An empty file names no server. The agent's own answer to it is true and no help to
// somebody who pointed at the wrong path.
func TestConnectionImportRefusesAnEmptyFile(t *testing.T) {
	agent := newFakeAgentTunnels(openVPNTunnel("tn_nord", "nord", "Nord"))
	h := newHarness(t, agent.routes(t))
	file := filepath.Join(t.TempDir(), "nord.ovpn")
	if err := writeFile(file, "\n  \n"); err != nil {
		t.Fatalf("write the configuration file: %v", err)
	}

	err := h.exec("connection", "import", "--config", h.configPath, "Nord", file)
	if err == nil {
		t.Fatal("an empty configuration file was imported")
	}
	if len(agent.imports) != 0 {
		t.Error("an empty file was sent to the agent")
	}
}

func TestConnectionRemoveTakesTheConnectionAway(t *testing.T) {
	agent := newFakeAgentTunnels(wireGuardTunnel("tn_office", "office", "Office"))
	h := newHarness(t, agent.routes(t))

	if err := h.exec("connection", "rm", "--config", h.configPath, "Office"); err != nil {
		t.Fatalf("connection rm: %v", err)
	}

	agent.mu.Lock()
	defer agent.mu.Unlock()
	if len(agent.stored.Tunnels) != 0 {
		t.Errorf("%d connections remain after removing the only one", len(agent.stored.Tunnels))
	}
}

func TestConnectionEnableAndDisableSwitchTheConnection(t *testing.T) {
	agent := newFakeAgentTunnels(wireGuardTunnel("tn_office", "office", "Office"))
	h := newHarness(t, agent.routes(t))

	if err := h.exec("connection", "disable", "--config", h.configPath, "office"); err != nil {
		t.Fatalf("connection disable: %v", err)
	}
	if agent.heldOf(t, "tn_office").Enabled {
		t.Fatal("the connection is still switched on after being disabled")
	}

	if err := h.exec("connection", "enable", "--config", h.configPath, "office"); err != nil {
		t.Fatalf("connection enable: %v", err)
	}
	if !agent.heldOf(t, "tn_office").Enabled {
		t.Error("the connection is still switched off after being enabled")
	}
}

func TestConnectionRetryAsksTheAgentToBuildThatOneAgain(t *testing.T) {
	agent := newFakeAgentTunnels(wireGuardTunnel("tn_office", "office", "Office"))
	h := newHarness(t, agent.routes(t))

	if err := h.exec("connection", "retry", "--config", h.configPath, "Office"); err != nil {
		t.Fatalf("connection retry: %v", err)
	}

	agent.mu.Lock()
	defer agent.mu.Unlock()
	if strings.Join(agent.retried, ",") != "tn_office" {
		t.Errorf("the agent was asked to build %v again, want just tn_office", agent.retried)
	}
}

// Every command that names a connection resolves an id, a slug or a name, because those
// are the three things on screen and nobody should have to know which one is which.
func TestAConnectionIsNamedByItsIDItsSlugOrItsName(t *testing.T) {
	tunnels := []httpapi.TunnelView{{ID: "tn_office", Slug: "office", Name: "Office VPN"}}
	for _, wanted := range []string{"tn_office", "office", "Office VPN", "office vpn"} {
		got, err := resolveTunnel(tunnels, wanted)
		if err != nil {
			t.Errorf("naming the connection %q: %v", wanted, err)
			continue
		}
		if got.ID != "tn_office" {
			t.Errorf("naming the connection %q found %q, want tn_office", wanted, got.ID)
		}
	}
}

// Removing the wrong connection is not recoverable from a terminal, so an ambiguous name
// is refused rather than resolved arbitrarily.
func TestAnAmbiguousConnectionNameIsRefusedRatherThanGuessedAt(t *testing.T) {
	tunnels := []httpapi.TunnelView{
		{ID: "tn_one", Slug: "vpn-1", Name: "VPN"},
		{ID: "tn_two", Slug: "vpn-2", Name: "VPN"},
	}

	_, err := resolveTunnel(tunnels, "VPN")
	if err == nil {
		t.Fatal("a name two connections answer to was resolved to one of them")
	}
	for _, want := range []string{"tn_one", "tn_two"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal reads %q, want it to name %q as one of the connections to choose from", err, want)
		}
	}
}

func TestANameNoConnectionAnswersToSaysHowToSeeTheList(t *testing.T) {
	_, err := resolveTunnel([]httpapi.TunnelView{{ID: "tn_office", Name: "Office"}}, "absent")
	if err == nil {
		t.Fatal("a name no connection answers to was accepted")
	}
	if !strings.Contains(err.Error(), "connection list") {
		t.Errorf("the refusal reads %q, want it to say how to see the connections", err)
	}
}

// The overview is built from the command table, so a command that dispatches is one the
// help lists. A connections command nobody can find is the gap this closes only halfway.
func TestTheHelpOverviewListsTheConnectionCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run(t.Context(), []string{"help"}, Env{Stdout: &out, Stderr: &errOut}); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(out.String(), "app-tail connection") {
		t.Errorf("the help overview never mentions the connection command:\n%s", out.String())
	}
}

func TestAnUnknownConnectionCommandIsAUsageErrorNamingTheOnesThereAre(t *testing.T) {
	h := newHarness(t, newFakeAgentTunnels().routes(t))

	err := h.exec("connection", "frobnicate", "--config", h.configPath)
	if err == nil {
		t.Fatal("an unknown connection command was accepted")
	}
	if !strings.Contains(err.Error(), "import") {
		t.Errorf("the refusal reads %q, want it to list the connection commands", err)
	}
}

// A connection that has been up for a while and one that came back a second ago report
// the same state word; the duration is what tells them apart, and a clock that moved must
// not turn it into a negative.
func TestHowLongAgoAMomentWasIsSaidToOneUnit(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		at   time.Time
		want string
	}{
		{now.Add(-30 * time.Second), "30s"},
		{now.Add(-5 * time.Minute), "5m"},
		{now.Add(-3 * time.Hour), "3h"},
		{now.Add(-50 * time.Hour), "2d"},
		{now.Add(time.Hour), "0s"},
	} {
		if got := formatSince(c.at); got != c.want {
			t.Errorf("a moment at %v reads as %q, want %q", c.at, got, c.want)
		}
	}
}

func TestByteCountsReadTheSameWayTheDashboardWritesThem(t *testing.T) {
	for _, c := range []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{2048, "2.0 KB"},
		{20 * 1024, "20 KB"},
		{5 * 1024 * 1024, "5.0 MB"},
		{3 * 1024 * 1024 * 1024, "3.0 GB"},
	} {
		if got := formatBytes(c.n); got != c.want {
			t.Errorf("%d bytes reads as %q, want %q", c.n, got, c.want)
		}
	}
}
