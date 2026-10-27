// SPDX-License-Identifier: MIT

// A feature's settings, on the card for that feature.
//
// Every setting the agent declares for a group is here: the few worth reaching without
// thinking sit in the open, and the rest wait behind one disclosure. Nothing is dropped,
// so a setting added to the registry reaches its card with no work in this file.

import { useState } from 'react'
import type { SettingFieldSchema } from '../../api'
import { fieldsInGroup } from './fieldState'
import { SettingField } from './SettingField'
import type { EntityForm } from './useEntityDraft'
import { Toggle } from '../primitives'

/** The kinds SettingField renders as a picker. A reference to a device, a resolver
 *  profile or a connection is an enum whose choices the agent fills at run time, so it
 *  is the same control and needs the same treatment below. A set of connections is the
 *  same thing offering all of them at once: each tick is a decision on its own. */
const PICKER_KINDS: readonly string[] = [
  'enum',
  'nodeRef',
  'profileRef',
  'tunnelRef',
  'tunnelRefList',
]

/**
 * Whether a control applies the moment it is used.
 *
 * A switch and a picker have one gesture that means "I have decided", so waiting for a
 * Save afterwards is a second gesture for nothing. A text box has no such moment -- its
 * value is half-typed for as long as someone is typing -- so writing on every keystroke
 * would send the agent a stream of values nobody chose. A picker the agent filled no
 * choices for is one of those text boxes: EnumControl degrades to one rather than render
 * an empty select.
 */
function appliesAtOnce(field: SettingFieldSchema): boolean {
  if (field.kind === 'bool') return true
  return PICKER_KINDS.includes(field.kind) && (field.options?.length ?? 0) > 0
}

interface CardSettingsProps {
  form: EntityForm
  /** groups are the settings groups this card owns. Most cards own one; the connection
   *  card owns the three that together describe how this device is enrolled. */
  groups: readonly string[]
  /** omit are keys the card renders somewhere else, such as the module switch that
   *  lives in the card's head. */
  omit?: readonly string[] | undefined
  /** collapseLabel puts every setting behind one disclosure under that name, for a card
   *  whose subject is what it is reporting rather than what it is configured to do. */
  collapseLabel?: string | undefined
}

export function CardSettings({ form, groups, omit = [], collapseLabel }: CardSettingsProps) {
  const [showAdvanced, setShowAdvanced] = useState(false)

  const all = groups
    .flatMap((group) => fieldsInGroup(form.available, group, true))
    .filter((f) => !omit.includes(f.key))
  const basic = all.filter((f) => f.tier === 'basic')
  const advanced = all.filter((f) => f.tier === 'advanced')

  if (all.length === 0) return null

  const dirty = groups.some((group) => form.dirtyGroups.has(group))

  const render = (field: SettingFieldSchema) => (
    <SettingField
      key={field.key}
      field={field}
      {...(appliesAtOnce(field) ? form.bindImmediate(field) : form.bind(field))}
    />
  )

  // A named disclosure holding nothing but a second disclosure is two clicks to reach one
  // setting, and the inner name says less than the outer one already did. When the card
  // names its own settings and every one of them is advanced, that name is the disclosure.
  const flattened = collapseLabel !== undefined && basic.length === 0

  const fields = flattened ? (
    <div className="card-settings-fields">{advanced.map(render)}</div>
  ) : (
    <>
      {basic.length > 0 ? <div className="card-settings-fields">{basic.map(render)}</div> : null}

      {advanced.length > 0 ? (
        <details
          className="advanced"
          open={showAdvanced}
          onToggle={(e) => setShowAdvanced(e.currentTarget.open)}
        >
          <summary>
            Advanced settings <span className="count">{advanced.length}</span>
          </summary>
          <div className="advanced-body">
            <div className="card-settings-fields">{advanced.map(render)}</div>
          </div>
        </details>
      ) : null}
    </>
  )

  return (
    <div className="card-settings">
      {collapseLabel === undefined ? (
        fields
      ) : (
        <details className="advanced">
          <summary>
            {collapseLabel} <span className="count">{all.length}</span>
          </summary>
          <div className="advanced-body">{fields}</div>
        </details>
      )}

      {/* One Save for the whole group, and only once something is waiting on it. The
          switches above have already applied; this is here for the boxes that cannot. */}
      {dirty ? (
        <div className="card-settings-save">
          <span className="hint">Unsaved changes</span>
          <button
            className="btn primary small"
            disabled={form.saving}
            onClick={() => void form.saveGroup(groups)}
          >
            {form.saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      ) : null}
    </div>
  )
}

/**
 * The switch that turns a module on, for the head of the card it governs.
 *
 * It cannot live in the body: a card whose module is off has no body to put it in, and a
 * feature reachable only once it is already on is one nobody finds.
 */
export function ModuleSwitch({ form, switchKey }: { form: EntityForm; switchKey: string }) {
  const field = form.available.find((f) => f.key === switchKey)
  if (field === undefined) return null

  const binding = form.bindImmediate(field)
  return (
    <Toggle
      checked={binding.value === true}
      onChange={binding.onChange}
      label={field.label}
      disabled={binding.disabled}
    />
  )
}

/** Whether a module's switch is on, read from the draft so a card reflects the switch
 *  the moment it is flipped rather than after the agent has answered. */
export function switchIsOn(form: EntityForm, switchKey: string): boolean {
  const field = form.available.find((f) => f.key === switchKey)
  return field !== undefined && form.bind(field).value === true
}
