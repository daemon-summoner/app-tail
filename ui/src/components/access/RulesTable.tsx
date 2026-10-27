// SPDX-License-Identifier: MIT

// One proxy instance's permissions, in the order they are matched.
//
// Order is the meaning: the first rule that fits a destination decides it, and anything no
// rule allows is refused. That is why the rows move with explicit buttons rather than by
// dragging, why they are numbered, and why the whole list is written back at once -- a
// partial write would have to say where each rule goes, and getting that wrong moves a
// refusal below the grant it was written to except.
//
// A row is a sentence rather than five equal boxes, because five equal boxes is what makes
// a permission model unreadable to everybody who did not design it.

import { useState } from 'react'
import {
  api,
  ApiError,
  type AccessAction,
  type AccessProtocol,
  type AccessRule,
  type ProxyInstanceView,
  type TunnelView,
} from '../../api'
import { Notice } from '../primitives'
import {
  classifyDestination,
  describeDestination,
  destinationOf,
  extraDestination,
  portsFrom,
  portsOf,
} from './destination'
import { tunnelChoices } from './instance'

/**
 * One row being edited.
 *
 * `key` is local and survives reordering, which `id` cannot: a rule the agent has not seen
 * yet has no id at all, and two new rows would otherwise share the empty one. `alsoCidr` is
 * the half of a two-part destination this table's one box is not showing -- carried through
 * a save rather than dropped, because dropping it would quietly widen the rule.
 */
interface RuleRow {
  key: string
  id: string
  action: AccessAction
  tunnel: string
  destination: string
  alsoCidr: string
  ports: string
  protocol: AccessProtocol
  note: string
}

let nextKey = 0
function freshKey(): string {
  nextKey += 1
  return `row-${nextKey}`
}

function rowOf(rule: AccessRule): RuleRow {
  return {
    key: freshKey(),
    id: rule.id,
    action: rule.action,
    tunnel: rule.tunnel ?? '',
    destination: destinationOf(rule),
    alsoCidr: extraDestination(rule) ?? '',
    ports: portsOf(rule),
    protocol: rule.protocol ?? '',
    note: rule.note ?? '',
  }
}

function ruleOf(row: RuleRow): AccessRule {
  const where = classifyDestination(row.destination)
  const ports = portsFrom(row.ports)
  // A rule carrying a name may also carry the range that name has to resolve into. The box
  // shows the name, so the range rides along here rather than being lost on the way back.
  const cidr = where.kind === 'host' && row.alsoCidr !== '' ? row.alsoCidr : where.cidr
  return {
    id: row.id,
    action: row.action,
    ...(row.tunnel === '' ? {} : { tunnel: row.tunnel }),
    ...(where.host === undefined ? {} : { host: where.host }),
    ...(cidr === undefined ? {} : { cidr }),
    ...(ports === undefined ? {} : { ports }),
    ...(row.protocol === '' ? {} : { protocol: row.protocol }),
    ...(row.note.trim() === '' ? {} : { note: row.note.trim() }),
  }
}

function blankRow(): RuleRow {
  return {
    key: freshKey(),
    id: '',
    // Allow, because a rule list is read top to bottom and a deny is written to carve an
    // exception out of a grant above it -- so the grant is what somebody adds first.
    action: 'allow',
    tunnel: '',
    destination: '',
    alsoCidr: '',
    ports: '',
    protocol: '',
    note: '',
  }
}

function moved(rows: readonly RuleRow[], from: number, to: number): RuleRow[] {
  const out = [...rows]
  const held = out[from]
  if (held === undefined || to < 0 || to >= out.length) return out
  out.splice(from, 1)
  out.splice(to, 0, held)
  return out
}

export function RulesTable({
  instance,
  tunnels,
  actions,
  protocols,
  onSaved,
}: {
  instance: ProxyInstanceView
  tunnels: readonly TunnelView[]
  /** The verdicts and transports the agent will accept, served rather than listed here so
   *  this table cannot offer one it refuses the moment it is saved. */
  actions: readonly AccessAction[]
  protocols: readonly AccessProtocol[]
  onSaved: () => void
}) {
  const [rows, setRows] = useState<readonly RuleRow[]>(() => instance.rules.map(rowOf))
  // What was on the instance when this table last agreed with it, so Discard has something
  // to go back to and Save knows whether it has anything to do.
  const [base, setBase] = useState<readonly AccessRule[]>(instance.rules)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)

  const edited = JSON.stringify(rows.map(ruleOf)) !== JSON.stringify(base)

  // The instance is polled, so its rules can change under this table -- another window, the
  // command line, the menu bar. Taking the new list is only safe while nothing is being
  // edited here; otherwise the poll would throw away what somebody is in the middle of
  // writing, which is worse than showing them a list that is a few seconds old.
  //
  // Adjusted while rendering rather than in an effect, which is the shape React documents
  // for state that follows a prop, and compared as text because every poll hands back a new
  // array whether or not anything in it moved.
  const served = JSON.stringify(instance.rules)
  const [seen, setSeen] = useState(served)
  if (seen !== served) {
    setSeen(served)
    if (!edited) {
      setRows(instance.rules.map(rowOf))
      setBase(instance.rules)
    }
  }

  const set = (key: string, change: Partial<RuleRow>) => {
    setRows((prev) => prev.map((row) => (row.key === key ? { ...row, ...change } : row)))
  }

  const save = async () => {
    setSaving(true)
    setError(undefined)
    try {
      const updated = await api.setProxyRules(instance.id, rows.map(ruleOf))
      // Read back from the answer rather than from what was sent: the agent mints an id for
      // a rule that had none, and a row that kept its empty id would be minted a second one
      // on the next save.
      setRows(updated.rules.map(rowOf))
      setBase(updated.rules)
      onSaved()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setSaving(false)
    }
  }

  const choices = tunnelChoices(tunnels)

  return (
    <div className="rules">
      {error !== undefined ? <Notice tone="error">{error}</Notice> : null}

      {rows.length === 0 ? (
        <p className="module-off">
          No rules. This proxy reaches nothing: anything a rule does not allow is refused.
        </p>
      ) : (
        <ol className="rule-rows">
          {rows.map((row, at) => (
            <li className="rule-row" key={row.key}>
              <div className="rule-order">
                <span className="rule-number">{at + 1}</span>
                <button
                  className="btn ghost small"
                  aria-label={`Move rule ${at + 1} up`}
                  disabled={at === 0}
                  onClick={() => setRows((prev) => moved(prev, at, at - 1))}
                >
                  Up
                </button>
                <button
                  className="btn ghost small"
                  aria-label={`Move rule ${at + 1} down`}
                  disabled={at === rows.length - 1}
                  onClick={() => setRows((prev) => moved(prev, at, at + 1))}
                >
                  Down
                </button>
              </div>

              <RuleSentence
                row={row}
                at={at}
                actions={actions}
                protocols={protocols}
                choices={choices}
                onChange={(change) => set(row.key, change)}
              />

              <button
                className="btn danger small"
                aria-label={`Remove rule ${at + 1}`}
                onClick={() => setRows((prev) => prev.filter((r) => r.key !== row.key))}
              >
                Remove
              </button>
            </li>
          ))}
        </ol>
      )}

      <div className="rules-foot">
        <button className="btn small" onClick={() => setRows((prev) => [...prev, blankRow()])}>
          Add a rule
        </button>
        <span className="spacer" />
        {edited ? <span className="hint">Unsaved changes</span> : null}
        <button
          className="btn"
          disabled={!edited || saving}
          onClick={() => setRows(base.map(rowOf))}
        >
          Discard
        </button>
        <button
          className="btn primary"
          disabled={!edited || saving}
          onClick={() => void save()}
        >
          {saving ? 'Saving…' : 'Save rules'}
        </button>
      </div>
    </div>
  )
}

function RuleSentence({
  row,
  at,
  actions,
  protocols,
  choices,
  onChange,
}: {
  row: RuleRow
  /** The row's position, which is what every one of its controls is named after: a screen
   *  reader landing on a box needs to know which of eight rules it belongs to. */
  at: number
  actions: readonly AccessAction[]
  protocols: readonly AccessProtocol[]
  choices: readonly { value: string; label: string }[]
  onChange: (change: Partial<RuleRow>) => void
}) {
  const where = classifyDestination(row.destination)
  const id = (part: string) => `rule-${at}-${part}`

  return (
    <div className="rule-sentence">
      <div className="rule-line">
        <label className="sr-only" htmlFor={id('action')}>
          Rule {at + 1}: allow or deny
        </label>
        <select
          id={id('action')}
          value={row.action}
          onChange={(e) => onChange({ action: e.target.value as AccessAction })}
        >
          {actions.map((action) => (
            <option key={action} value={action}>
              {action === 'allow' ? 'Allow' : 'Deny'}
            </option>
          ))}
        </select>

        <span className="rule-word">connections to</span>

        <label className="sr-only" htmlFor={id('destination')}>
          Rule {at + 1}: destination
        </label>
        <input
          id={id('destination')}
          className="mono rule-destination"
          placeholder="anything"
          value={row.destination}
          onChange={(e) => onChange({ destination: e.target.value })}
        />

        <span className="rule-word">on port</span>

        <label className="sr-only" htmlFor={id('ports')}>
          Rule {at + 1}: ports
        </label>
        <input
          id={id('ports')}
          className="mono rule-ports"
          placeholder="any"
          value={row.ports}
          onChange={(e) => onChange({ ports: e.target.value })}
        />

        <span className="rule-word">over</span>

        <label className="sr-only" htmlFor={id('protocol')}>
          Rule {at + 1}: transport
        </label>
        <select
          id={id('protocol')}
          value={row.protocol}
          onChange={(e) => onChange({ protocol: e.target.value as AccessProtocol })}
        >
          {protocols.map((p) => (
            <option key={p} value={p}>
              {p === '' ? 'any transport' : p.toUpperCase()}
            </option>
          ))}
        </select>

        <span className="rule-word">on</span>

        <label className="sr-only" htmlFor={id('tunnel')}>
          Rule {at + 1}: connection
        </label>
        <select
          id={id('tunnel')}
          value={row.tunnel}
          onChange={(e) => onChange({ tunnel: e.target.value })}
        >
          {choices.map((choice) => (
            <option key={choice.value} value={choice.value}>
              {choice.label}
            </option>
          ))}
        </select>
      </div>

      <div className="rule-line rule-explain">
        {/* What the box was read as, so somebody typing 10.0.0.0/8 can see it became a
            range and somebody typing db.* can see it stayed a name. */}
        <span className="chip">{describeDestination(where.kind)}</span>
        {row.alsoCidr !== '' ? (
          <span className="chip">
            and only when that resolves inside {row.alsoCidr}
          </span>
        ) : null}
        <span className="hint">
          Ports as a list or a range: 5432, 8000-8100. Empty is every port.
        </span>
      </div>

      <div className="rule-line">
        <label className="sr-only" htmlFor={id('note')}>
          Rule {at + 1}: note
        </label>
        <input
          id={id('note')}
          className="rule-note"
          placeholder="Why this rule exists"
          value={row.note}
          onChange={(e) => onChange({ note: e.target.value })}
        />
      </div>
    </div>
  )
}
