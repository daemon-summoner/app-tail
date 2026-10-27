// SPDX-License-Identifier: MIT

// The kind switchboard: one setting rendered as the control its kind calls for. Adding
// a kind to the registry means adding a case here; the default arm renders a text input
// and says so, because a dashboard built before a kind existed must still let the user
// reach the setting rather than blanking it out.

import type { ReactNode } from 'react'
import type { SettingFieldSchema } from '../../api'
import type { DraftValue } from './fieldState'
import {
  EnumControl,
  FactControl,
  MultiEnumControl,
  NumberControl,
  SecretControl,
  SecretTextControl,
  SwitchControl,
  TextAreaControl,
  TextControl,
  type ControlProps,
} from './controls'

export interface SettingFieldProps {
  field: SettingFieldSchema
  value: DraftValue
  /** The greyed sample for an empty control, already resolved against the live
   *  settings. */
  example: string
  onChange: (next: DraftValue) => void
  /** stored reports whether a secret already has a value, which is the only thing the
   *  view says about one. */
  stored: boolean
  error: string | undefined
  /** disabled turns off a control whose real state is still loading, so a switch never
   *  renders a guess the user could act on. */
  disabled: boolean
}

export function SettingField({
  field,
  value,
  example,
  onChange,
  stored,
  error,
  disabled,
}: SettingFieldProps) {
  const id = `set-${field.key}`

  if (field.kind === 'bool') {
    return (
      <div className="field">
        <SwitchControl
          field={field}
          checked={value === true}
          onChange={onChange}
          disabled={disabled}
        />
        {error ? <span className="field-error">{error}</span> : null}
      </div>
    )
  }

  const text = typeof value === 'string' ? value : ''
  const control = renderControl(
    { field, id, value: text, example, onChange, invalid: error !== undefined },
    stored,
  )

  return (
    <div className="field">
      <label htmlFor={id}>{field.label}</label>
      {control.node}
      {control.note ? <span className="hint warn-text">{control.note}</span> : null}
      <span className="hint">{field.help}</span>
      {/* Identified so a control that cannot carry aria-invalid can point at it instead. */}
      {error ? (
        <span className="field-error" id={`${id}-error`}>
          {error}
        </span>
      ) : null}
    </div>
  )
}

function renderControl(
  props: ControlProps,
  stored: boolean,
): { node: ReactNode; note?: string } {
  const { field } = props
  if (field.readOnly) {
    return { node: <FactControl value={props.value} /> }
  }
  switch (field.kind) {
    case 'int':
      return { node: <NumberControl {...props} /> }
    // A device, resolver-profile or connection reference is an enum whose choices the agent
    // fills at run time, so it renders the same way -- including the two behaviours that
    // matter here: a stored choice that is no longer on offer stays selected and visible,
    // and an empty list degrades to a text box so an id can still be pasted in.
    case 'enum':
    case 'nodeRef':
    case 'profileRef':
    case 'tunnelRef':
      return { node: <EnumControl {...props} /> }
    case 'secret':
      return { node: <SecretControl {...props} stored={stored} /> }
    case 'text':
      return { node: <TextAreaControl {...props} /> }
    case 'secretText':
      return { node: <SecretTextControl {...props} stored={stored} /> }
    // A set of this install's own connections, in the order they were chosen. The choices
    // arrive from the agent the same way a single connection reference's do, so the control
    // is the same picker offering all of them at once rather than one.
    case 'tunnelRefList':
      return {
        node: (
          <MultiEnumControl
            {...props}
            emptyMeans="Nothing is chosen, so every connection that is running takes a share."
          />
        ),
      }
    case 'string':
    case 'stringList':
    case 'cidrList':
    case 'interfaceAddrList':
    case 'ipList':
    case 'secretFile':
    case 'addrPort':
    case 'url':
      // A list is one text box holding comma-separated entries. The draft carries it as
      // typed and the agent parses it, so a half-written entry survives editing and the
      // rules about what an entry may be are stated in exactly one place.
      return { node: <TextControl {...props} /> }
    default:
      // A kind this build has never heard of. A plain text box still reaches the
      // agent, which is the authority on the value either way -- and the note is what
      // tells the user the dashboard is older than the agent it is talking to.
      return {
        node: <TextControl {...props} />,
        note: `This copy of the dashboard does not know the "${field.kind}" setting type, so it is offering a plain text box. Update the app if this setting rejects a value you expect it to take.`,
      }
  }
}
