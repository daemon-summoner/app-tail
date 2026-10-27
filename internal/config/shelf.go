// SPDX-License-Identifier: MIT

package config

// Remembering what a module owned while it is switched off.
//
// Turning a module off returns every setting it owns to its default, which is what makes
// "off" mean off: a stored value that kept applying under a switch reading off would be a
// setting the user can neither see nor turn off. On its own that is destructive -- one
// click on a switch is not a request to forget a resolver profile, a set of local
// suffixes and a listen address -- so the values are kept beside the entity and put back
// when the module comes on again.
//
// The shelf is the app's own bookkeeping. Nothing chooses it, no surface offers it, and a
// value only ever enters it as a copy of a setting the user made.

import (
	"encoding/json"
	"reflect"
)

// shelve records what module's fields hold on v and returns them to their defaults,
// reporting the shelf to store.
//
// A field already at its default is not recorded: an absent entry and one holding the
// default restore identically, and leaving it out keeps the stored document to what
// somebody actually chose. A secret is never recorded at all -- a credential kept
// somewhere no screen shows and no switch reaches is how a key outlives the module it was
// for -- so turning a module off still forgets its credentials.
func (r *Registry[T]) shelve(v *T, module FeatureModule, shelf map[string]json.RawMessage) map[string]json.RawMessage {
	for _, f := range r.fields {
		if f.Module != module || f.set == nil || !r.applies(f, v) {
			continue
		}
		if !f.Kind.Secret() && !reflect.DeepEqual(f.get(v), f.defaultValue()) {
			// A value that cannot be encoded is one this build could not put back either,
			// so the field is reset with nothing recorded rather than half-recorded.
			if raw, err := json.Marshal(f.get(v)); err == nil {
				if shelf == nil {
					shelf = map[string]json.RawMessage{}
				}
				shelf[f.JSONKey] = raw
			}
		}
		f.set(v, f.defaultValue())
	}
	return shelf
}

// unshelve puts back what shelve took, and clears each entry as it goes: a restored value
// is the live setting again, and a second copy of it would go stale the moment the setting
// changed.
//
// An entry this build cannot decode or would refuse is dropped rather than failing the
// save. It is a value from a field that has since changed shape, and refusing to turn a
// module on because of a record the user never made is a worse answer than the default
// they get instead.
func (r *Registry[T]) unshelve(v *T, module FeatureModule, shelf map[string]json.RawMessage) map[string]json.RawMessage {
	for _, f := range r.fields {
		if f.Module != module || f.set == nil || !r.applies(f, v) {
			continue
		}
		raw, ok := shelf[f.JSONKey]
		if !ok {
			continue
		}
		delete(shelf, f.JSONKey)
		value, err := f.decode(raw)
		if err != nil {
			continue
		}
		if err := f.ValidateValue(value); err != nil {
			continue
		}
		f.set(v, value)
	}
	if len(shelf) == 0 {
		return nil
	}
	return shelf
}
