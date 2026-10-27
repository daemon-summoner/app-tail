// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"reflect"
)

// SettingChange is one setting whose stored value moved, described in the terms a log
// may keep.
//
// It exists so that "what changed" is answered from the registry rather than at the call
// site. A caller that assembled this itself would have to decide, per setting, whether
// the value is safe to write down -- and would get it wrong the first time somebody adds
// a setting after them.
type SettingChange struct {
	// Key is the wire key, always recorded. Knowing which setting was touched is the
	// point of the record, and a key is not a value.
	Key string
	// Label is the setting's name on screen, so a log entry reads as a sentence rather
	// than as a dotted path.
	Label string
	// From and To are the old and new values rendered for display. They are empty when
	// the setting's kind is one whose values are not recorded, which Redacted reports.
	From string
	To   string
	// Redacted marks a change whose values were deliberately withheld. The entry still
	// says the setting changed; it just does not say to what.
	Redacted bool
}

// recordsValue reports whether a kind's values may be written into a log.
//
// This is the whole privacy rule, and it is a property of the kind rather than a list of
// setting names on purpose: a list would have to be extended every time a setting is
// added, and the failure mode of forgetting is that a value nobody meant to keep ends up
// in a log. Booleans, numbers and enum choices are recorded because each is drawn from a
// small declared set that carries nothing personal. Everything else -- hostnames, tags,
// URLs, addresses, file paths, subnet lists and every kind of secret -- is not, because
// the values are the user's rather than the app's.
func (k FieldKind) recordsValue() bool {
	switch k {
	case KindBool, KindInt, KindEnum:
		return true
	default:
		return false
	}
}

// SettingsChanged reports every setting whose stored value differs between two documents,
// in registry order.
//
// Derived and read-only fields are skipped: neither is something a user changed, and a
// derived value moving is a consequence of some other setting in the same list.
func SettingsChanged(before, after Settings) []SettingChange {
	return changedIn(settingsRegistry, before, after)
}

// TunnelChanged reports every field of one connection whose stored value moved, under the
// same privacy rule. A device name and a tag list are the user's on a connection for the
// same reason they were the user's as settings.
func TunnelChanged(before, after Tunnel) []SettingChange {
	return changedIn(tunnelRegistry, before, after)
}

// TunnelsChanged reports what moved across a whole connection list, matching connections
// by id so a rename is a change rather than a removal and an addition. A connection that
// appeared or disappeared is reported as one change naming it, because "which connection"
// is the useful record and its fields at that moment are not.
func TunnelsChanged(before, after []Tunnel) []SettingChange {
	held := make(map[string]Tunnel, len(before))
	for _, t := range before {
		held[t.ID] = t
	}
	var out []SettingChange
	for _, t := range after {
		old, existed := held[t.ID]
		delete(held, t.ID)
		if !existed {
			out = append(out, SettingChange{Key: "connection." + t.ID, Label: "Connection added", Redacted: true})
			continue
		}
		for _, change := range TunnelChanged(old, t) {
			change.Key = "connection." + t.ID + "." + change.Key
			out = append(out, change)
		}
	}
	for _, t := range before {
		if _, gone := held[t.ID]; gone {
			out = append(out, SettingChange{Key: "connection." + t.ID, Label: "Connection removed", Redacted: true})
		}
	}
	return out
}

// changedIn is the comparison itself, over whichever registry describes the entity. The
// rule that decides what may be written down belongs to the field's kind, so it holds for
// every entity without being restated per entity.
func changedIn[T any](r *Registry[T], before, after T) []SettingChange {
	var out []SettingChange
	for _, f := range r.Fields() {
		if f.get == nil || f.Derived || !r.applies(f, &after) {
			continue
		}
		old, current := f.get(&before), f.get(&after)
		if reflect.DeepEqual(old, current) {
			continue
		}
		change := SettingChange{Key: f.JSONKey, Label: f.Label}
		if f.Kind.recordsValue() {
			change.From = fmt.Sprintf("%v", old)
			change.To = fmt.Sprintf("%v", current)
		} else {
			change.Redacted = true
		}
		out = append(out, change)
	}
	return out
}
