// SPDX-License-Identifier: MIT

// The exceptions to where internet traffic leaves.
//
// The card sits under the egress card because that is what it excepts: one setting says
// where everything goes, and these say where a named handful goes instead. Order is the
// meaning -- the first rule that fits a destination decides it -- so the rows are numbered,
// they move with explicit buttons, and the whole list is written back at once.
//
// Anything no rule names is not decided here at all. It leaves whichever way the egress
// setting says, which is why an empty list is a normal state rather than a warning.

import { useState } from 'react'
import {
  api,
  ApiError,
  type RoutingAction,
  type RoutingCheckResult,
  type RoutingRule,
  type RoutingTunnel,
  type RoutingView,
} from '../../api'
import { Notice } from '../primitives'
import { Panel } from '../Panel'
import {
  classifyDestination,
  destinationOf,
  extraDestination,
  type DestinationKind,
} from '../access/destination'
import { ArrowDownIcon, ArrowUpIcon } from '../shell/icons'

/** THROUGH mirrors routing.Via: the one action with a connection to name. */
const THROUGH: RoutingAction = 'via'

/**
 * One row being edited.
 *
 * `key` is local and survives reordering, which `id` cannot: a rule the agent has not seen
 * yet has no id at all, and two new rows would otherwise share the empty one. `alsoCidr` is
 * the half of a two-part destination the one box is not showing, carried through a save
 * rather than dropped -- dropping it would quietly widen the rule.
 */
interface RuleRow {
  key: string
  id: string
  action: RoutingAction
  tunnel: string
  destination: string
  alsoCidr: string
  note: string
}

let nextKey = 0
function freshKey(): string {
  nextKey += 1
  return `routing-row-${nextKey}`
}

function rowOf(rule: RoutingRule): RuleRow {
  return {
    key: freshKey(),
    id: rule.id,
    action: rule.action,
    tunnel: rule.tunnel ?? '',
    destination: destinationOf(rule),
    alsoCidr: extraDestination(rule) ?? '',
    note: rule.note ?? '',
  }
}

function ruleOf(row: RuleRow): RoutingRule {
  const where = classifyDestination(row.destination)
  // A rule carrying a name may also carry the range that name has to resolve into. The box
  // shows the name, so the range rides along here rather than being lost on the way back.
  const cidr = where.kind === 'host' && row.alsoCidr !== '' ? row.alsoCidr : where.cidr
  return {
    id: row.id,
    action: row.action,
    // Only the action that sends traffic somewhere carries a connection. Keeping the id on
    // the other two would store a connection nothing reads, and the agent refuses it.
    ...(row.action === THROUGH && row.tunnel !== '' ? { tunnel: row.tunnel } : {}),
    ...(where.host === undefined ? {} : { host: where.host }),
    ...(cidr === undefined ? {} : { cidr }),
    ...(row.note.trim() === '' ? {} : { note: row.note.trim() }),
  }
}

function blankRow(): RuleRow {
  return {
    key: freshKey(),
    id: '',
    // Through a connection, because that is what somebody adding their first rule came here
    // to do: the other two actions are written to carve an exception out of one of these.
    action: THROUGH,
    tunnel: '',
    destination: '',
    alsoCidr: '',
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

/** What the destination box was read as. The routing rules have no "every destination":
 *  a rule with neither a name nor a range would be the egress setting rather than an
 *  exception to it, and the agent refuses one. */
function describeWhere(kind: DestinationKind): string {
  switch (kind) {
    case 'anywhere':
      return 'nothing yet — a rule names a host or a range of addresses'
    case 'range':
      return 'a range of addresses, matched against where the traffic is going'
    default:
      return 'a name, matched against what was asked for'
  }
}

function actionWord(action: RoutingAction): string {
  switch (action) {
    case 'via':
      return 'Send through'
    case 'direct':
      return 'Send out directly'
    default:
      return 'Refuse'
  }
}

export function RoutingCard({
  view,
  error,
  onSaved,
}: {
  view: RoutingView | undefined
  error?: string | undefined
  /** Called after a save, because the rules decide what several other cards are showing:
   *  which connections are carrying, and what the interface is routing. */
  onSaved: () => void
}) {
  const served = view?.rules ?? []
  const [rows, setRows] = useState<readonly RuleRow[]>(() => served.map(rowOf))
  // What was stored when this table last agreed with the agent, so Discard has something to
  // go back to and Save knows whether it has anything to do.
  const [base, setBase] = useState<readonly RoutingRule[]>(served)
  const [saving, setSaving] = useState(false)
  const [failed, setFailed] = useState<string | undefined>(undefined)

  const edited = JSON.stringify(rows.map(ruleOf)) !== JSON.stringify(base)

  // The view is polled, so the rules can change under this table -- another window, the
  // command line. Taking the new list is only safe while nothing is being edited here;
  // otherwise the poll would throw away what somebody is in the middle of writing, which is
  // worse than showing them a list that is a few seconds old.
  //
  // Adjusted while rendering rather than in an effect, which is the shape React documents
  // for state that follows a prop, and compared as text because every poll hands back a new
  // array whether or not anything in it moved.
  const seenNow = JSON.stringify(served)
  const [seen, setSeen] = useState(seenNow)
  if (seen !== seenNow) {
    setSeen(seenNow)
    if (!edited) {
      setRows(served.map(rowOf))
      setBase(served)
    }
  }

  const set = (key: string, change: Partial<RuleRow>) => {
    setRows((prev) => prev.map((row) => (row.key === key ? { ...row, ...change } : row)))
  }

  const save = async () => {
    setSaving(true)
    setFailed(undefined)
    try {
      const updated = await api.setRoutingRules(rows.map(ruleOf))
      // Read back from the answer rather than from what was sent: the agent mints an id for
      // a rule that had none, and a row that kept its empty id would be minted a second one
      // on the next save.
      setRows(updated.rules.map(rowOf))
      setBase(updated.rules)
      onSaved()
    } catch (cause) {
      setFailed(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setSaving(false)
    }
  }

  const tunnels = view?.tunnels ?? []
  const actions = view?.actions ?? []
  const limits = view?.limits ?? []
  const shadowed = view?.shadowed ?? []
  // The agent's own sentence for each stored rule, which is what every other surface shows
  // for it. It lines up with the rows only while nothing is being edited, since a row moved
  // or added here has no stored sentence yet.
  const describe = edited ? [] : (view?.describe ?? [])

  return (
    <Panel
      title="Per-destination rules"
      wide
      status={statusOf(view)}
      info={
        <p>
          Exceptions to where internet traffic leaves. The first rule that fits a destination
          decides it; anything no rule names goes wherever the setting above says.
        </p>
      }
    >
      {error ? <Notice tone="error">{error}</Notice> : null}
      {failed !== undefined ? <Notice tone="error">{failed}</Notice> : null}

      {/* A rule naming a connection that is not running is not an error -- the rule is doing
          what it says, which is refusing those destinations. Said here because an
          unexplained refusal reads as the app being broken. */}
      {view?.capability.degraded === true && view.capability.reason ? (
        <Notice tone="warn">{view.capability.reason}</Notice>
      ) : null}

      {view === undefined && error === undefined ? (
        <p className="module-off">Reading the rules…</p>
      ) : (
        <div className="rules routing-rules">
          {rows.length === 0 ? (
            <p className="module-off">
              No rules. All internet traffic leaves the one way the setting above says.
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
                      <ArrowUpIcon />
                    </button>
                    <button
                      className="btn ghost small"
                      aria-label={`Move rule ${at + 1} down`}
                      disabled={at === rows.length - 1}
                      onClick={() => setRows((prev) => moved(prev, at, at + 1))}
                    >
                      <ArrowDownIcon />
                    </button>
                  </div>

                  <RuleSentence
                    row={row}
                    at={at}
                    actions={actions}
                    tunnels={tunnels}
                    stored={describe[at]}
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

          {/* Rules the network interface will not reach, because an earlier rule already
              carries their range. They still decide on the proxy path, so this is a note
              about one path rather than a fault in the rule. */}
          {shadowed.length > 0 ? (
            <ul className="tunnel-limits">
              {shadowed.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          ) : null}

          <div className="rules-foot">
            <button
              className="btn small"
              onClick={() => setRows((prev) => [...prev, blankRow()])}
            >
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
            <button className="btn primary" disabled={!edited || saving} onClick={() => void save()}>
              {saving ? 'Saving…' : 'Save rules'}
            </button>
          </div>
        </div>
      )}

      <DestinationCheck disabled={view === undefined} />

      {/* What a rule cannot do, which is not obvious from writing one and is invisible from
          anywhere else on the page. */}
      {limits.length > 0 ? (
        <ul className="tunnel-limits">
          {limits.map((limit) => (
            <li key={limit}>{limit}</li>
          ))}
        </ul>
      ) : null}
    </Panel>
  )
}

/**
 * Which way one destination goes, answered by the rules as they are stored.
 *
 * It is a question rather than a test: the agent decides the destination as written and
 * dials nothing, so asking costs no traffic and reveals nothing to the network.
 */
function DestinationCheck({ disabled }: { disabled: boolean }) {
  const [written, setWritten] = useState('')
  const [asking, setAsking] = useState(false)
  const [answer, setAnswer] = useState<RoutingCheckResult | undefined>(undefined)
  const [failed, setFailed] = useState<string | undefined>(undefined)

  const ask = async () => {
    setAsking(true)
    setFailed(undefined)
    try {
      setAnswer(await api.checkRoute(written))
    } catch (cause) {
      setAnswer(undefined)
      setFailed(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setAsking(false)
    }
  }

  return (
    <div className="routing-check">
      <form
        className="rule-line"
        onSubmit={(e) => {
          e.preventDefault()
          void ask()
        }}
      >
        <label htmlFor="routing-check-destination">Where would a destination go?</label>
        <input
          id="routing-check-destination"
          className="mono"
          placeholder="files.corp.example or 10.0.0.5"
          value={written}
          onChange={(e) => setWritten(e.target.value)}
        />
        <button className="btn small" disabled={asking || disabled || written.trim() === ''}>
          {asking ? 'Asking…' : 'Check'}
        </button>
      </form>

      {failed !== undefined ? <Notice tone="error">{failed}</Notice> : null}

      {answer !== undefined ? (
        <p className="rule-line rule-explain">
          {answer.decided ? (
            <span className="chip">rule {answer.ruleIndex}</span>
          ) : (
            <span className="chip">no rule</span>
          )}
          {/* The agent's sentence, which already names the connection as this page does. */}
          <span className="hint">{answer.reason}</span>
        </p>
      ) : null}
    </div>
  )
}

function RuleSentence({
  row,
  at,
  actions,
  tunnels,
  stored,
  onChange,
}: {
  row: RuleRow
  /** The row's position, which is what every one of its controls is named after: a screen
   *  reader landing on a box needs to know which of eight rules it belongs to. */
  at: number
  /** The actions the agent will accept, served rather than listed here so this table cannot
   *  offer one it refuses the moment it is saved. */
  actions: readonly RoutingAction[]
  tunnels: readonly RoutingTunnel[]
  /** The agent's sentence for this rule as it is stored, absent while the list is edited. */
  stored?: string | undefined
  onChange: (change: Partial<RuleRow>) => void
}) {
  const where = classifyDestination(row.destination)
  const id = (part: string) => `routing-rule-${at}-${part}`

  return (
    <div className="rule-sentence">
      <div className="rule-line">
        <label className="sr-only" htmlFor={id('action')}>
          Rule {at + 1}: what happens
        </label>
        <select
          id={id('action')}
          value={row.action}
          onChange={(e) => onChange({ action: e.target.value as RoutingAction })}
        >
          {actions.map((action) => (
            <option key={action} value={action}>
              {actionWord(action)}
            </option>
          ))}
        </select>

        <span className="rule-word">traffic to</span>

        <label className="sr-only" htmlFor={id('destination')}>
          Rule {at + 1}: destination
        </label>
        <input
          id={id('destination')}
          className="mono rule-destination"
          placeholder="*.corp.example"
          value={row.destination}
          onChange={(e) => onChange({ destination: e.target.value })}
        />

        {row.action === THROUGH ? (
          <>
            <span className="rule-word">using</span>
            <label className="sr-only" htmlFor={id('tunnel')}>
              Rule {at + 1}: connection
            </label>
            <select
              id={id('tunnel')}
              value={row.tunnel}
              onChange={(e) => onChange({ tunnel: e.target.value })}
            >
              <option value="">choose a connection</option>
              {tunnels.map((tunnel) => (
                <option key={tunnel.id} value={tunnel.id}>
                  {tunnel.running ? tunnel.name : `${tunnel.name} (not running)`}
                </option>
              ))}
            </select>
          </>
        ) : null}
      </div>

      <div className="rule-line rule-explain">
        {/* What the box was read as, so somebody typing 10.0.0.0/8 can see it became a
            range and somebody typing *.corp can see it stayed a name. */}
        <span className="chip">{describeWhere(where.kind)}</span>
        {row.alsoCidr !== '' ? (
          <span className="chip">and only when that resolves inside {row.alsoCidr}</span>
        ) : null}
        {stored ? <span className="hint">{stored}</span> : null}
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

/** statusOf is the head's dot and word. An empty list is off rather than an error: no
 *  exceptions is a working state, and the traffic leaves the one way the card above says. */
function statusOf(view: RoutingView | undefined) {
  if (view === undefined) return { tone: 'pending', label: 'reading' }
  if (view.rules.length === 0) return { tone: 'off', label: 'no exceptions' }
  const detail = view.rules.length === 1 ? '1 rule' : `${view.rules.length} rules`
  if (view.capability.degraded === true) return { tone: 'error', label: 'refusing', detail }
  return { tone: 'running', label: 'in force', detail }
}
