// SPDX-License-Identifier: MIT

package config

// A registry is a field table with its lookups built once, and the machinery every
// surface of a configurable entity derives from: the redacted view the API returns, the
// patch it accepts, the schema a form renders, and the validation each of those passes.
//
// The global settings document is one entity; a tunnel is another. The rule for a third
// is worth stating, because the wrong choice here is expensive either way: an entity
// with a fixed field set gets a registry, and an entity that is a list of tuples with
// match semantics gets a hand-written editor. Forwards and resolver profiles are the
// second kind, which is why they are not here.

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// Registry holds one entity's field table and the indexes over it. Build it once at
// package level: the indexes are read on every patch and every schema request.
type Registry[T any] struct {
	fields    []FieldOf[T]
	byJSONKey map[string]FieldOf[T]
	byCLIName map[string]FieldOf[T]
	// variantOf reads which kind of entity a value is, for a table whose fields do not
	// all apply to every one. Nil for an entity that has only one kind, where every
	// field applies to every value.
	variantOf func(*T) string
}

// NewRegistry indexes a field table. It panics on a duplicate wire key or CLI name,
// because two fields answering to one name is a table error that would otherwise show up
// as a setting that silently cannot be written -- the index keeps whichever came last.
func NewRegistry[T any](fields []FieldOf[T]) *Registry[T] {
	byJSON := indexBy(fields, func(f FieldOf[T]) string { return f.JSONKey })
	byCLI := indexBy(fields, func(f FieldOf[T]) string { return f.CLIName })
	if want := countNamed(fields, func(f FieldOf[T]) string { return f.JSONKey }); len(byJSON) != want {
		panic(fmt.Sprintf("config: %d fields declare %d distinct wire keys", want, len(byJSON)))
	}
	if want := countNamed(fields, func(f FieldOf[T]) string { return f.CLIName }); len(byCLI) != want {
		panic(fmt.Sprintf("config: %d fields declare %d distinct CLI names", want, len(byCLI)))
	}
	return &Registry[T]{fields: fields, byJSONKey: byJSON, byCLIName: byCLI}
}

// NewVariantRegistry indexes a table whose fields do not all apply to every value, with
// variantOf reading which kind a given value is. A field's Variant is then checked
// against that on every read, write and validation, so a field that does not apply is
// absent rather than stored empty against an entity that has no such thing.
func NewVariantRegistry[T any](fields []FieldOf[T], variantOf func(*T) string) *Registry[T] {
	r := NewRegistry(fields)
	r.variantOf = variantOf
	return r
}

// applies reports whether f is a field of this particular value. A table with no variants
// answers yes for everything.
func (r *Registry[T]) applies(f FieldOf[T], v *T) bool {
	return f.Variant == "" || r.variantOf == nil || f.Variant == r.variantOf(v)
}

func countNamed[T any](fields []FieldOf[T], key func(FieldOf[T]) string) int {
	n := 0
	for _, f := range fields {
		if key(f) != "" {
			n++
		}
	}
	return n
}

// Fields returns the table in its authored order, which is the order the interactive
// menu and every generated surface present fields in.
func (r *Registry[T]) Fields() []FieldOf[T] { return r.fields }

// ByJSONKey looks up a field by the key the wire uses.
func (r *Registry[T]) ByJSONKey(key string) (FieldOf[T], bool) {
	f, ok := r.byJSONKey[key]
	return f, ok
}

// ByCLIName looks up a settable field by its CLI/menu name.
func (r *Registry[T]) ByCLIName(name string) (FieldOf[T], bool) {
	f, ok := r.byCLIName[name]
	return f, ok
}

// View projects a stored entity onto the outward-facing map the API returns. Secrets
// emit only a presence boolean under their view key; a value is never included. Every
// field appears whether or not it is currently writable: availability is reported by the
// schema, so a client always finds a value where it expects one.
func (r *Registry[T]) View(v T, app *Settings) map[string]any {
	view := make(map[string]any, len(r.fields))
	for _, f := range r.fields {
		// A field of another kind of entity is left out rather than reported empty: an
		// absent key says "this connection has no such thing", and a zero value says it
		// has one and it is unset.
		if !r.applies(f, &v) {
			continue
		}
		switch {
		case f.Derived:
			view[f.JSONKey] = f.derive(v, app)
		case f.Kind.Secret():
			view[f.viewKey()] = f.present(&v)
		default:
			view[f.JSONKey] = f.get(&v)
		}
	}
	return view
}

// Schema is the table projected to its serializable form, in authored order. It is pure:
// availability depends on configuration, so it is left unset here and this is the form
// the generator renders into the dashboard's fallback copy.
func (r *Registry[T]) Schema() []FieldSchema {
	out := make([]FieldSchema, 0, len(r.fields))
	for _, f := range r.fields {
		out = append(out, FieldSchema{
			Key:          f.JSONKey,
			ViewKey:      f.viewKey(),
			CLIName:      f.CLIName,
			Kind:         f.Kind,
			Secret:       f.Kind.Secret(),
			ReadOnly:     f.Derived || f.Write == WriteNone,
			Derived:      f.Derived,
			Restart:      f.Restart,
			Write:        f.Write,
			Label:        f.Label,
			Group:        f.Group,
			Tier:         f.Tier,
			Module:       f.Module,
			ModuleSwitch: f.ModuleSwitch,
			Example:      f.Example,
			ExampleFrom:  f.ExampleFrom,
			Tray:         f.Tray,
			Options:      f.Options,
			OptionsFrom:  f.OptionsFrom,
			Default:      f.declaredDefault(),
			Constraint:   f.Constraint,
			Variant:      f.Variant,
			Help:         f.Help,
			Pinnable:     f.Pinnable,
			Deprecated:   f.Deprecated,
		})
	}
	return out
}

// SchemaFor is Schema with each field's availability resolved against the app's global
// settings, which is where the module switches and the platform gates are decided. It is
// what a schema endpoint serves, so a client renders exactly the fields this
// configuration can write right now.
func (r *Registry[T]) SchemaFor(app *Settings) []FieldSchema {
	out := r.Schema()
	for i := range out {
		field := r.byJSONKey[out[i].Key]
		available, reason := field.Available(app)
		out[i].Available = &available
		out[i].AvailableReason = reason
		supported := field.onThisPlatform()
		out[i].PlatformSupported = &supported
	}
	return out
}

// ApplyPatch overlays the fields a request carried onto v. A present key is a change; an
// absent key is left alone. Unknown, read-only, autostart-managed and unavailable keys
// are rejected by name, and a secret sent as the redaction mask is treated as absent so
// a form round-trip cannot store the mask as the secret.
//
// app carries the module switches and is separate from v because a module is a fact
// about the installation rather than about any one entity. For the settings document
// itself the two are the same value.
func (r *Registry[T]) ApplyPatch(v *T, app *Settings, patch map[string]json.RawMessage) error {
	for key, raw := range patch {
		f, ok := r.byJSONKey[key]
		if !ok {
			return invalid(key, "is not a known setting")
		}
		if err := r.applyField(v, app, f, raw); err != nil {
			return err
		}
	}
	return nil
}

// applyField applies one decoded, validated patch entry.
func (r *Registry[T]) applyField(v *T, app *Settings, f FieldOf[T], raw json.RawMessage) error {
	key := f.JSONKey
	if !r.applies(f, v) {
		return invalid(key, "does not apply to a %s connection", r.variantOf(v))
	}
	if f.Derived || f.Write == WriteNone {
		// A field kept only because callers still name it owes them the replacement. A
		// bare "is read-only" leaves a script that has worked for a year failing with
		// nothing said about what to run instead.
		if f.Deprecated != "" {
			return invalid(key, "is read-only: %s", f.Deprecated)
		}
		return invalid(key, "is read-only")
	}
	if f.Write == WriteAutostart {
		return invalid(key, "is managed through the autostart control, not settings")
	}
	if ok, reason := f.Available(app); !ok {
		return invalid(key, "%s", reason)
	}
	decoded, err := f.decode(raw)
	if err != nil {
		return invalid(key, "%v", err)
	}
	// The view renders a stored secret as RedactedSecret, so a client saving the form it
	// was served sends that sentinel back. It means "leave the stored value alone".
	if f.Kind.Secret() && typed[string](decoded) == RedactedSecret {
		return nil
	}
	if err := f.ValidateValue(decoded); err != nil {
		return err
	}
	if f.validateWrite != nil {
		if err := f.validateWrite(decoded); err != nil {
			return invalid(key, "%v", err)
		}
	}
	f.set(v, decoded)
	return nil
}

// Defaults writes every field's declared default into v, which is what a freshly created
// entity starts from. Derived and read-only fields are skipped: nothing stores them.
func (r *Registry[T]) Defaults(v *T) {
	for _, f := range r.fields {
		if f.set == nil || !r.applies(f, v) {
			continue
		}
		f.set(v, f.defaultValue())
	}
}

// BackfillDefaults fills the fields of v that hold nothing with the default their field
// declares, so a partial or older document stays loadable.
//
// Booleans and lists are left alone: false and the empty list are values a user can mean
// and are indistinguishable from an absent key, so back-filling them would overwrite a
// deliberate choice on every load.
func (r *Registry[T]) BackfillDefaults(v *T) {
	for _, f := range r.fields {
		if f.Default == nil || f.get == nil || f.set == nil || f.Kind == KindBool || f.Kind == KindStringList {
			continue
		}
		if !r.applies(f, v) {
			continue
		}
		if reflect.ValueOf(f.get(v)).IsZero() {
			f.set(v, f.defaultValue())
		}
	}
}

// Validate checks every stored value in v against everything its field declares. It is
// how a document that was hand-edited, or written by an older version, is refused with
// the same reason a live write would have been refused with.
func (r *Registry[T]) Validate(v *T) error {
	for _, f := range r.fields {
		if f.get == nil || !r.applies(f, v) {
			continue
		}
		if err := f.ValidateValue(f.get(v)); err != nil {
			return err
		}
	}
	return nil
}
