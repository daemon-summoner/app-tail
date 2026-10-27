// SPDX-License-Identifier: MIT

// The input controls a settings field renders through. Each takes the same shape --
// a schema entry, the current draft value, and a change callback -- so SettingField.tsx
// can switch on kind and nothing else. Labels come from the schema, never from a
// hand-maintained map, which is what keeps a new setting from needing UI work.

import { Toggle } from '../primitives'
import type { SettingFieldSchema } from '../../api'

export interface ControlProps {
  field: SettingFieldSchema
  /** The control's DOM id, so the section's label points at it. */
  id: string
  value: string
  /** The greyed sample to show while empty, already resolved: a static example or the
   *  live value the setting stands in for. Empty means show nothing. */
  example: string
  onChange: (next: string) => void
  invalid: boolean
}

export interface SwitchProps {
  field: SettingFieldSchema
  checked: boolean
  onChange: (next: boolean) => void
  disabled: boolean
}

/** TextControl backs every string-shaped kind: plain strings, addresses, URLs, paths
 *  and comma-separated lists. The kinds differ in how the agent validates them, not in
 *  how they are typed. */
export function TextControl({ id, value, example, onChange, invalid }: ControlProps) {
  return (
    <input
      id={id}
      type="text"
      value={value}
      placeholder={example}
      aria-invalid={invalid || undefined}
      onChange={(e) => onChange(e.target.value)}
    />
  )
}

/** TextAreaControl backs the kinds whose value has newlines in it -- a certificate, a
 *  key, a block pasted out of another file. Rendering one of those in a single-line box
 *  is what makes a half-pasted PEM impossible to spot before saving. */
export function TextAreaControl({ id, value, example, onChange, invalid }: ControlProps) {
  return (
    <textarea
      id={id}
      className="mono"
      rows={6}
      spellCheck={false}
      value={value}
      placeholder={example}
      aria-invalid={invalid || undefined}
      onChange={(e) => onChange(e.target.value)}
    />
  )
}

/** SecretTextControl is TextAreaControl for a value that is never sent back out. It
 *  starts empty whatever is stored, and the placeholder is the only report of that. */
export function SecretTextControl({
  id,
  value,
  onChange,
  invalid,
  stored,
}: ControlProps & { stored: boolean }) {
  return (
    <textarea
      id={id}
      className="mono"
      rows={6}
      spellCheck={false}
      value={value}
      placeholder={stored ? 'stored — paste to replace' : 'not set'}
      aria-invalid={invalid || undefined}
      onChange={(e) => onChange(e.target.value)}
    />
  )
}

/** NumberControl carries the field's declared bounds as input attributes, so the
 *  browser offers the same limit the agent enforces rather than letting the user
 *  discover it from a rejected save. */
export function NumberControl({ field, id, value, example, onChange, invalid }: ControlProps) {
  return (
    <input
      id={id}
      type="number"
      value={value}
      min={field.constraint?.min}
      max={field.constraint?.max}
      placeholder={example}
      aria-invalid={invalid || undefined}
      onChange={(e) => onChange(e.target.value)}
    />
  )
}

/** SecretControl never shows a stored value, because the agent never sends one. The
 *  box reports only whether a secret is stored, and typing replaces it. */
export function SecretControl({
  id,
  value,
  onChange,
  invalid,
  stored,
}: ControlProps & { stored: boolean }) {
  return (
    <input
      id={id}
      type="password"
      autoComplete="new-password"
      value={value}
      placeholder={stored ? 'stored — type to replace' : 'not set'}
      aria-invalid={invalid || undefined}
      onChange={(e) => onChange(e.target.value)}
    />
  )
}

/** EnumControl offers exactly the choices the schema declares, so a value the agent
 *  would refuse cannot be picked. A schema carrying no options degrades to a text box:
 *  a dashboard older than the agent still reaches the setting rather than rendering an
 *  empty picker with nothing selectable. */
export function EnumControl(props: ControlProps) {
  const { field, id, value, onChange, invalid } = props
  const options = field.options ?? []
  if (options.length === 0) {
    return <TextControl {...props} />
  }
  const selected = options.find((o) => o.value === value)
  return (
    <>
      <select
        id={id}
        value={value}
        aria-invalid={invalid || undefined}
        onChange={(e) => onChange(e.target.value)}
      >
        {/* A value the agent stored but this build has no option for still has to be
            shown, or the picker would silently report a different setting than is in
            force -- and saving would then write the substitute. */}
        {selected === undefined ? <option value={value}>{value === '' ? '—' : value}</option> : null}
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      {selected?.help ? <span className="hint">{selected.help}</span> : null}
    </>
  )
}

/** MultiEnumControl picks a set out of the choices the schema declares, one row per
 *  choice, and carries it as the same comma-separated draft every list kind uses.
 *
 *  A set rather than a text box because the values are ids the agent generated: typing one
 *  by hand is guesswork, and the empty set means something specific here -- every choice --
 *  which a blank box could equally be read as none. A schema carrying no options degrades to
 *  a text box, so a dashboard older than the agent still reaches the setting. */
export function MultiEnumControl(props: ControlProps & { emptyMeans?: string }) {
  const { field, id, value, onChange, invalid, emptyMeans } = props
  const options = field.options ?? []
  if (options.length === 0) {
    return <TextControl {...props} />
  }
  const chosen = splitList(value)
  const toggle = (option: string, on: boolean) => {
    // The stored order is kept: a value already in the set stays where it is, and a new one
    // joins at the end. The order is the value for anything that reads the list as a
    // sequence, so re-sorting it on every click would be an edit nobody asked for.
    onChange(on ? [...chosen, option].join(', ') : chosen.filter((v) => v !== option).join(', '))
  }
  return (
    // A group carries no aria-invalid, so a rejected set says so by pointing at the message
    // the field renders under it, and is named as a whole because the label beside it belongs
    // to no single box.
    <div
      className="choice-set"
      id={id}
      role="group"
      aria-label={field.label}
      aria-describedby={invalid ? `${id}-error` : undefined}
    >
      {options.map((o) => (
        <label className="choice" key={o.value}>
          {/* Named for the choice alone, so the help beside it does not become part of
              what a screen reader announces for the box. */}
          <input
            type="checkbox"
            aria-label={o.label}
            checked={chosen.includes(o.value)}
            onChange={(e) => toggle(o.value, e.target.checked)}
          />
          <span className="choice-text">
            <span className="choice-label">{o.label}</span>
            {o.help ? <span className="hint">{o.help}</span> : null}
          </span>
        </label>
      ))}
      {/* A value the agent stored that this build has no option for is still part of the
          set, and dropping it from the display would have the next save write it away. */}
      {chosen
        .filter((v) => !options.some((o) => o.value === v))
        .map((v) => (
          <label className="choice" key={v}>
            <input type="checkbox" aria-label={v} checked onChange={() => toggle(v, false)} />
            <span className="choice-text">
              <span className="choice-label mono">{v}</span>
              <span className="hint">This connection is no longer on offer.</span>
            </span>
          </label>
        ))}
      {chosen.length === 0 && emptyMeans !== undefined ? (
        <span className="hint">{emptyMeans}</span>
      ) : null}
    </div>
  )
}

/** splitList reads a comma-separated draft as the entries it holds, dropping the blanks a
 *  half-typed list leaves behind. */
function splitList(value: string): string[] {
  return value
    .split(',')
    .map((v) => v.trim())
    .filter((v) => v !== '')
}

/** SwitchControl is the boolean row: the toggle plus the label and help beside it, so
 *  the whole row reads as one statement rather than a checkbox with a caption. */
export function SwitchControl({ field, checked, onChange, disabled }: SwitchProps) {
  return (
    <div className="switch-row">
      <Toggle checked={checked} onChange={onChange} label={field.label} disabled={disabled} />
      <div className="switch-text">
        <span className="switch-label">{field.label}</span>
        <span className="hint">{field.help}</span>
      </div>
    </div>
  )
}

/** FactControl renders a read-only setting as the fact it is. Showing it in a disabled
 *  input would invite the user to try to edit something the agent will never accept. */
export function FactControl({ value }: { value: string }) {
  return <span className="hint mono">{value === '' ? '—' : value}</span>
}
