// SPDX-License-Identifier: MIT

// The pure half of the settings form: turning a served schema and a settings view into
// editable draft values, deciding which fields are reachable, and turning the edited
// draft back into the smallest patch that expresses what changed. Nothing here touches
// the DOM or the network, so every rule below is testable on its own.

import type { FeatureModuleInfo, SettingFieldSchema, SettingsPatch } from '../../api'

/** A draft value is always a string except for booleans, because a half-typed number
 *  ("", "-", "12e") has no numeric value yet and must survive until the user is done. */
export type DraftValue = string | boolean
export type Draft = Record<string, DraftValue>

/** The settings document the API returns, keyed by view key. */
export type SettingsView = Record<string, unknown>

/** isPatchable marks the settings a save can carry. Read-only facts and the login item
 *  are rendered too, but never through the patch. */
export function isPatchable(f: SettingFieldSchema): boolean {
  return f.write === 'patch' && !f.readOnly
}

/** draftValueOf reads one field out of the settings view. A secret is never sent
 *  outward, so it starts empty and means "leave the stored one alone". */
export function draftValueOf(f: SettingFieldSchema, view: SettingsView): DraftValue {
  if (f.secret) return ''
  const raw = view[f.viewKey]
  switch (f.kind) {
    case 'bool':
      return raw === true
    case 'stringList':
    case 'tunnelRefList':
    case 'cidrList':
    case 'interfaceAddrList':
    case 'ipList':
      return Array.isArray(raw) ? raw.join(', ') : ''
    case 'int':
      return typeof raw === 'number' ? String(raw) : ''
    default:
      return typeof raw === 'string' ? raw : ''
  }
}

/** draftFrom builds the editable state for every field in the schema, patchable or not,
 *  so a read-only fact renders from the same place a writable one does. */
export function draftFrom(schema: readonly SettingFieldSchema[], view: SettingsView): Draft {
  const draft: Draft = {}
  for (const f of schema) draft[f.key] = draftValueOf(f, view)
  return draft
}

/** secretIsStored reports whether the agent already holds a value for a secret. The
 *  view carries only that fact -- `hasAuthKey`, never the key. */
export function secretIsStored(f: SettingFieldSchema, view: SettingsView): boolean {
  return view[f.viewKey] === true
}

/** exampleFor is the greyed sample an empty control shows. A field that names a view
 *  key shows what is actually in force -- an empty device name is really the rendered
 *  template -- and falls back to its static example when that value is not a string. */
export function exampleFor(f: SettingFieldSchema, view: SettingsView): string {
  if (f.exampleFrom !== undefined) {
    const live = view[f.exampleFrom]
    if (typeof live === 'string' && live !== '') return live
  }
  return f.example ?? ''
}

/** moduleIsOn reports whether the module a field belongs to is switched on in the given
 *  draft. Reading a draft rather than the served schema is what lets flipping a module's
 *  switch reveal its settings immediately, before any save. */
export function moduleIsOn(
  f: SettingFieldSchema,
  modules: readonly FeatureModuleInfo[],
  draft: Draft,
): boolean {
  if (f.module === 'core') return true
  // An entity that carries no module switches of its own cannot answer this locally, and
  // failing closed here would hide every module-gated field it has. The agent resolved the
  // gate against the installation before serving the schema, so `available` is the answer
  // and the filter below is what reads it.
  if (modules.length === 0) return true
  const owner = modules.find((m) => m.id === f.module)
  // No switch governs this module, so its settings fail closed -- the same answer the
  // agent gives, rather than showing a control that can never be saved.
  if (!owner) return false
  return draft[owner.switchKey] === true
}

/**
 * availableFields are the settings this configuration can write, in schema order.
 *
 * `served` is the configuration the schema's `available` flags were resolved against --
 * what was in force when the agent answered, which is not what is in force now once a
 * module switch has moved. Where the draft holds a field's module in a different position
 * than that, the agent's answer is about a configuration nobody is in any more and the
 * draft alone decides. Everywhere else the agent's answer wins, because it knows reasons
 * this page does not.
 *
 * The platform is the exception, and it is checked first: it is the one reason for
 * unavailability that no edit on this page can move, so a setting the machine does not
 * have stays hidden even where the draft has taken over the module question. A form that
 * showed it would offer a control whose save the agent refuses by name, taking the rest
 * of the save down with it.
 */
export function availableFields(
  schema: readonly SettingFieldSchema[],
  modules: readonly FeatureModuleInfo[],
  draft: Draft,
  served: Draft,
): SettingFieldSchema[] {
  return schema.filter((f) => {
    if (f.platformSupported === false) return false
    if (!moduleIsOn(f, modules, draft)) return false
    if (!moduleIsOn(f, modules, served)) return true
    return f.available !== false
  })
}

/** fieldsInGroup narrows already-available fields to one section and the tier the user
 *  has open. */
export function fieldsInGroup(
  fields: readonly SettingFieldSchema[],
  group: string,
  showAdvanced: boolean,
): SettingFieldSchema[] {
  return fields.filter((f) => f.group === group && (showAdvanced || f.tier === 'basic'))
}

/**
 * patchOne is the write for a control that applies as soon as it is used, rather than
 * waiting behind a Save button.
 *
 * It carries exactly the one field, which is what keeps a switch in the control panel
 * from also writing whatever else the draft happens to hold. An empty secret is nothing
 * to write for the same reason it is in a save: it means "leave the stored one alone".
 */
export function patchOne(f: SettingFieldSchema, value: DraftValue): Record<string, unknown> {
  if (f.secret) return value === '' ? {} : { [f.key]: value }
  return { [f.key]: parseDraftValue(f, value) }
}

/** parseDraftValue converts one draft value to the JSON shape the patch expects. */
function parseDraftValue(f: SettingFieldSchema, value: DraftValue): unknown {
  switch (f.kind) {
    case 'bool':
      return value === true
    case 'int':
      return Number(value)
    case 'stringList':
    case 'tunnelRefList':
    case 'cidrList':
    case 'interfaceAddrList':
    case 'ipList':
      return String(value)
        .split(',')
        .map((part) => part.trim())
        .filter((part) => part !== '')
    default:
      return String(value).trim()
  }
}

function sameValue(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, i) => item === b[i])
  }
  return a === b
}

/**
 * patchFrom builds the write for a save: only the fields whose value actually moved.
 *
 * Sending every field would make a stale form clobber a change another surface made to a
 * setting the user never looked at -- the CLI and the tray write the same document. It
 * carries only available fields, because the agent refuses an unavailable one by name and
 * refuses the whole save with it; a module being switched off in the same save is exactly
 * when its old values are still sitting in the draft.
 *
 * `stored` is what the agent holds, which is what "changed" is measured against. `served`
 * is what its schema's availability was resolved against, and defaults to `stored` for a
 * document whose values arrived with the schema describing them.
 */
export function patchFrom(
  schema: readonly SettingFieldSchema[],
  modules: readonly FeatureModuleInfo[],
  draft: Draft,
  stored: Draft,
  served: Draft = stored,
): SettingsPatch {
  // Keyed by the registry's wire key rather than by a member name: which settings a
  // patch can carry is the schema's answer, not this file's.
  const patch: Record<string, unknown> = {}
  for (const f of availableFields(schema, modules, draft, served)) {
    if (!isPatchable(f)) continue
    const value = draft[f.key]
    if (value === undefined) continue
    // A secret is absent from the view, so "changed" can only mean the user typed
    // something. An empty box leaves the stored secret in place.
    if (f.secret) {
      if (value !== '') patch[f.key] = value
      continue
    }
    const next = parseDraftValue(f, value)
    if (sameValue(next, parseDraftValue(f, stored[f.key] ?? ''))) continue
    patch[f.key] = next
  }
  return patch
}

/** fieldReason strips the leading key from the agent's rejection, so the control that
 *  caused it can carry the reason alone -- its label is already beside it. */
export function fieldReason(message: string, key: string): string {
  const prefix = `${key}: `
  return message.startsWith(prefix) ? message.slice(prefix.length) : message
}
