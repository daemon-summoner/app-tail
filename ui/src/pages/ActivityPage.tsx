// SPDX-License-Identifier: MIT

// What the agent has been doing, as a page someone can read.
//
// The log itself has been recorded since long before anything could show it. This is the
// reader: the whole of the module's state -- whether it is recording, what it holds, and
// the words it will match a filter against -- comes from the agent rather than from a list
// written here, so an event code added in Go appears in the picker with no edit in this
// file.

import { useEffect, useMemo, useRef, useState } from 'react'

import {
  api,
  ApiError,
  type TelemetryEvent,
  type TelemetryPage,
  type TelemetryQuery,
  type TelemetryView,
} from '../api'
import { ModuleOff } from '../components/ModuleOff'
import { Panel } from '../components/Panel'
import { Notice } from '../components/primitives'
import { CardSettings, ModuleSwitch } from '../components/settings/CardSettings'
import type { SettingsForm } from '../components/settings/useSettingsDraft'
import { usePolled } from '../data/StoreProvider'

/** The setting that turns recording on. The agent names it on every answer, and this is
 *  the value it names: the card's switch has to exist before the first read lands. */
const SWITCH = 'telemetry.enabled'

/** How many rows are asked for at a time, and the ceiling the agent will not serve past.
 *  Both are here rather than in the request so the "show more" step and the point it stops
 *  offering cannot disagree. */
const PAGE_ROWS = 100
const MAX_ROWS = 500

/** A moment as a person reads it: the date only when it is not today, because a log of the
 *  last few minutes repeating one date on every row says nothing. */
function stamp(at: string): string {
  const when = new Date(at)
  if (Number.isNaN(when.getTime())) return at
  const clock = when.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  const today = new Date()
  const sameDay =
    when.getFullYear() === today.getFullYear() &&
    when.getMonth() === today.getMonth() &&
    when.getDate() === today.getDate()
  if (sameDay) return clock
  return `${when.toLocaleDateString([], { month: 'short', day: 'numeric' })} ${clock}`
}

/** The card's state chip. How much is held rides with it, because "recording" says the
 *  switch is on and says nothing about whether there is anything to read. */
function moduleStatus(view: TelemetryView | undefined): { tone: string; label: string; detail?: string } {
  if (view === undefined) return { tone: 'pending', label: 'reading' }
  if (!view.enabled) return { tone: 'off', label: 'off' }
  return { tone: 'running', label: 'recording', detail: `${view.stats.events} kept` }
}

/** The small named values behind a sentence, in the order the agent sent them. */
function fieldPairs(fields: Record<string, string> | undefined): [string, string][] {
  return Object.entries(fields ?? {})
}

export function ActivityPage({ form }: { form: SettingsForm }) {
  const view = usePolled('telemetry')

  const [severities, setSeverities] = useState<string[]>([])
  const [categories, setCategories] = useState<string[]>([])
  const [code, setCode] = useState('')
  const [text, setText] = useState('')
  const [typed, setTyped] = useState('')
  const [rows, setRows] = useState(PAGE_ROWS)

  const [page, setPage] = useState<TelemetryPage | undefined>(undefined)
  const [error, setError] = useState<string | undefined>(undefined)
  const asked = useRef(0)

  const enabled = view.data?.enabled === true
  // What the module holds, which is what says there is something new to read. Polling the
  // events on a timer of their own would ask the same question twice; these two figures
  // move for exactly the reasons the list changes -- something was recorded, or something
  // aged out of it.
  const recorded = view.data?.stats.eventsRecorded ?? 0
  const held = view.data?.stats.events ?? 0

  const query = useMemo<TelemetryQuery>(
    () => ({
      ...(severities.length > 0 ? { severities } : {}),
      ...(categories.length > 0 ? { categories } : {}),
      ...(code !== '' ? { codes: [code] } : {}),
      ...(text !== '' ? { text } : {}),
      limit: rows,
    }),
    [severities, categories, code, text, rows],
  )

  useEffect(() => {
    if (!enabled) return
    // Answers can land out of order once a filter is changed twice quickly, and the later
    // request is not always the later answer. Each read takes a ticket and paints only
    // while it is still the newest one asked for.
    const ticket = asked.current + 1
    asked.current = ticket
    api.telemetryEvents(query).then(
      (answer) => {
        if (asked.current !== ticket) return
        setPage(answer)
        setError(undefined)
      },
      (cause) => {
        if (asked.current !== ticket) return
        setError(cause instanceof ApiError ? cause.message : String(cause))
      },
    )
  }, [enabled, query, recorded, held])

  // Read against what the module says it holds, so the page that was on screen when
  // recording was switched off cannot come back when it is switched on again: the log is
  // dropped with the switch, and no filter can match in a store holding nothing.
  const events = held === 0 ? [] : (page?.events ?? [])
  const total = held === 0 ? 0 : (page?.total ?? 0)
  const filtered =
    severities.length > 0 || categories.length > 0 || code !== '' || text !== ''

  const clearFilters = () => {
    setSeverities([])
    setCategories([])
    setCode('')
    setText('')
    setTyped('')
    setRows(PAGE_ROWS)
  }

  return (
    <div className="deck">
      <Panel
        title="Activity"
        wide
        bare
        status={moduleStatus(view.data)}
        info={
          <>
            <p>
              What this app did: connections coming up and going down, forwards starting and
              stopping, the resolver being claimed and put back, and every settings change. It
              is how a fault that has already passed can still be looked at.
            </p>
            <p>
              The log is kept in this app&rsquo;s memory and is sent nowhere. It starts empty
              every time app-tail starts.
            </p>
          </>
        }
        controls={<ModuleSwitch form={form} switchKey={SWITCH} />}
      >
        {view.data === undefined ? (
          // Not known yet is not off: a page that said "off" for the first second would
          // send a reader after a switch that is on.
          <div className="panel-body">
            <p className="hint">Reading the log…</p>
          </div>
        ) : !enabled ? (
          <div className="panel-body">
            <ModuleOff>
              {view.data?.reason ??
                'Off. Nothing is being recorded, so a fault that has already passed leaves nothing behind to look at.'}
            </ModuleOff>
          </div>
        ) : (
          <>
            <div className="activity-filters">
              <Facets
                legend="Severity"
                options={view.data?.severities ?? []}
                chosen={severities}
                onChange={(next) => {
                  setSeverities(next)
                  setRows(PAGE_ROWS)
                }}
              />
              <Facets
                legend="Category"
                options={view.data?.categories ?? []}
                chosen={categories}
                onChange={(next) => {
                  setCategories(next)
                  setRows(PAGE_ROWS)
                }}
              />

              <label className="activity-code">
                <span className="activity-legend">Event</span>
                <select
                  value={code}
                  onChange={(e) => {
                    setCode(e.target.value)
                    setRows(PAGE_ROWS)
                  }}
                >
                  <option value="">Any event</option>
                  {(view.data?.codes ?? []).map((one) => (
                    <option key={one} value={one}>
                      {one}
                    </option>
                  ))}
                </select>
              </label>

              {/* A submit rather than a keystroke: the agent matches the text, so typing
                  straight through would send a request per letter and count each partial
                  word as a search that found nothing. */}
              <form
                className="activity-search"
                onSubmit={(e) => {
                  e.preventDefault()
                  setText(typed.trim())
                  setRows(PAGE_ROWS)
                }}
              >
                <label className="activity-legend" htmlFor="activity-q">
                  Search
                </label>
                <input
                  id="activity-q"
                  type="search"
                  value={typed}
                  placeholder="a word in the message"
                  onChange={(e) => setTyped(e.target.value)}
                />
                <button className="btn small" type="submit">
                  Search
                </button>
              </form>

              {filtered ? (
                <button className="btn ghost small" onClick={clearFilters}>
                  Clear filters
                </button>
              ) : null}
            </div>

            {error ? (
              <div className="table-notice">
                <Notice tone="error">{error}</Notice>
              </div>
            ) : null}

            {events.length === 0 ? (
              <div className="empty">
                <strong>{filtered ? 'Nothing matched' : 'Nothing recorded yet'}</strong>
                <p>
                  {filtered
                    ? `No entry matches these filters. The log holds ${held} ` +
                      `${held === 1 ? 'entry' : 'entries'}; clear the filters above to see ` +
                      'them.'
                    : 'Recording is on. Entries appear here as this app does things: a connection ' +
                      'coming up, a forward starting, a setting changing.'}
                </p>
              </div>
            ) : (
              <>
                <table className="activity">
                  <thead>
                    <tr>
                      <th scope="col">Time</th>
                      <th scope="col">Severity</th>
                      <th scope="col" className="optional">
                        Category
                      </th>
                      <th scope="col" className="optional">
                        Event
                      </th>
                      <th scope="col">What happened</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((event) => (
                      <Row key={event.seq} event={event} />
                    ))}
                  </tbody>
                </table>

                {/* A page that stopped at its limit looks exactly like a log that ends
                    there, so it says how much it left out either way. */}
                <div className="activity-more">
                  <span className="hint">
                    {total > events.length
                      ? `Showing the newest ${events.length} of ${total} matching.`
                      : `${events.length} ${events.length === 1 ? 'entry' : 'entries'}.`}
                  </span>
                  {total > events.length && rows < MAX_ROWS ? (
                    <button
                      className="btn small"
                      onClick={() => setRows(Math.min(rows + PAGE_ROWS, MAX_ROWS))}
                    >
                      Show more
                    </button>
                  ) : null}
                </div>
              </>
            )}
          </>
        )}

        <div className="panel-body">
          <CardSettings
            form={form}
            groups={['telemetry']}
            omit={[SWITCH]}
            collapseLabel="Log settings"
          />
        </div>
      </Panel>
    </div>
  )
}

/** One entry. The sentence is what a person reads; the named values behind it are what
 *  they need once the sentence is not enough. */
function Row({ event }: { event: TelemetryEvent }) {
  const pairs = fieldPairs(event.fields)
  return (
    <tr>
      <td className="activity-at">{stamp(event.at)}</td>
      <td>
        <span className={`badge severity-${event.severity}`}>{event.severity}</span>
      </td>
      <td className="optional">{event.category}</td>
      <td className="optional activity-code-cell">{event.code}</td>
      <td>
        {event.message}
        {pairs.length > 0 ? (
          <div className="activity-fields">
            {pairs.map(([name, value]) => (
              <span key={name} className="activity-field">
                <span className="activity-field-name">{name}</span>
                {value}
              </span>
            ))}
          </div>
        ) : null}
      </td>
    </tr>
  )
}

/** One row of filter chips. Every option is a toggle and none of them chosen means all of
 *  them, which is what an empty filter means to the agent as well. */
function Facets({
  legend,
  options,
  chosen,
  onChange,
}: {
  legend: string
  options: readonly string[]
  chosen: readonly string[]
  onChange: (next: string[]) => void
}) {
  if (options.length === 0) return null
  return (
    <fieldset className="activity-facet">
      <legend className="activity-legend">{legend}</legend>
      {options.map((option) => {
        const on = chosen.includes(option)
        return (
          <button
            key={option}
            type="button"
            className={on ? 'activity-chip on' : 'activity-chip'}
            aria-pressed={on}
            onClick={() =>
              onChange(on ? chosen.filter((c) => c !== option) : [...chosen, option])
            }
          >
            {option}
          </button>
        )
      })}
    </fieldset>
  )
}
