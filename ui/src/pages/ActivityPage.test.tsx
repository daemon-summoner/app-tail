// SPDX-License-Identifier: MIT

import { act, fireEvent } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from '../App'
import type { Settings, TelemetryEvent, TelemetryView } from '../api'
import { href } from '../lib/router'
import {
  deferred,
  failWith,
  makeSettings,
  makeSettingsResponse,
  makeTelemetry,
  makeTelemetryEvent,
  makeTelemetryPage,
  renderAgent,
  settingsRoutes,
  settle,
  type Routes,
} from '../test/agent'

/** recording is the module on and holding what it has been given. */
function recording(events: readonly TelemetryEvent[], overrides: Partial<TelemetryView> = {}) {
  return makeTelemetry({
    enabled: true,
    stats: {
      events: events.length,
      eventsRecorded: events.length,
      eventCapacity: 5000,
      dropped: 0,
      retentionSec: 30 * 24 * 60 * 60,
    },
    ...overrides,
  })
}

/** at opens the activity page over an agent recording these events. Passing none is the
 *  module switched off, which is what a fresh install answers with. */
async function at(
  events: readonly TelemetryEvent[] | undefined,
  routes: Routes = {},
  settings: Partial<Settings> = {},
) {
  window.history.replaceState(null, '', `/${href('activity')}`)
  const on = events !== undefined
  return renderAgent(<App />, {
    ...settingsRoutes(makeSettings({ 'telemetry.enabled': on, ...settings })),
    'PUT /api/settings': makeSettingsResponse({ 'telemetry.enabled': on, ...settings }),
    'GET /api/telemetry': on ? recording(events) : makeTelemetry(),
    'GET /api/telemetry/events': makeTelemetryPage(events ?? []),
    ...routes,
  })
}

/** The query string of the nth read of the log. */
function eventQuery(view: Awaited<ReturnType<typeof at>>, index: number): URLSearchParams {
  const url = view.agent.urlOf('GET /api/telemetry/events', index)
  const at = url.indexOf('?')
  return new URLSearchParams(at < 0 ? '' : url.slice(at + 1))
}

/** The last read of the log, which is the one the screen is showing. */
function lastQuery(view: Awaited<ReturnType<typeof at>>): URLSearchParams {
  return eventQuery(view, view.agent.countOf('GET /api/telemetry/events') - 1)
}

const CONNECTION_UP = makeTelemetryEvent({
  seq: 1,
  message: 'A connection was started.',
  fields: { connection: 'office' },
})

const CONNECTION_DOWN = makeTelemetryEvent({
  seq: 2,
  at: new Date(Date.UTC(2026, 7, 30, 9, 16, 0)).toISOString(),
  code: 'connection.down',
  severity: 'notice',
  message: 'A connection was stopped.',
})

afterEach(() => {
  window.history.replaceState(null, '', '/')
})

describe('the activity page', () => {
  // Before the first answer the page knows nothing, and "off" is the wrong thing to say
  // about a switch that is on: a reader would go looking for it. The log itself is not
  // read until the module says there is one.
  it('says it is reading before the first answer lands, and only then shows the log', async () => {
    const first = deferred<TelemetryView>()
    const view = await at([CONNECTION_UP], { 'GET /api/telemetry': () => first.promise })

    const panel = view.getByRole('region', { name: 'Activity' })
    expect(panel.querySelector('.status')).toHaveClass('pending')
    expect(panel).toHaveTextContent('Reading the log…')
    expect(panel).not.toHaveTextContent(/Off|switched off|Nothing recorded/)
    expect(view.agent.countOf('GET /api/telemetry/events')).toBe(0)

    first.resolve(recording([CONNECTION_UP]))
    await settle()

    expect(panel.querySelector('.status')).toHaveClass('running')
    expect(panel).toHaveTextContent('A connection was started.')
    expect(panel).not.toHaveTextContent('Reading the log…')
  })

  // An empty screen means two opposite things: a machine that has done nothing, and a
  // switch nobody turned on. A reader told the first when the second is true concludes the
  // app is broken and goes looking for a fault that does not exist.
  it('says when nothing is being recorded, and does not read a log that is off', async () => {
    const view = await at(undefined)

    expect(view.getByText(/Recording is switched off/)).toBeInTheDocument()
    expect(view.queryByText(/Nothing recorded yet/)).not.toBeInTheDocument()
    expect(view.agent.countOf('GET /api/telemetry/events')).toBe(0)
  })

  // The switch is the whole point of the page existing: two settings have governed this
  // store since before anything could read it, and nowhere in the dashboard turned it on.
  it('turns recording on from the page that shows it', async () => {
    const view = await at(undefined, {
      'PUT /api/settings': makeSettingsResponse({ 'telemetry.enabled': true }),
    })

    fireEvent.click(view.getByLabelText('Keep a log of what this app does'))
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({ 'telemetry.enabled': true })
    // The log's own settings are gated on the switch beside them, so they are unavailable
    // in the answer the agent served while it was off. Turning it on has to bring them
    // within reach on the card that owns them, not on the next page load.
    expect(view.getByText(/Log settings/)).toBeInTheDocument()
  })

  // The agent answers newest first, which is the order a screen scrolled from the top is
  // read in. Reversing it here would put the entry someone opened the page to see at the
  // bottom of a list of everything that happened before it.
  it('shows what happened, newest first, with the values behind each sentence', async () => {
    const view = await at([CONNECTION_DOWN, CONNECTION_UP])

    const rows = view.container.querySelectorAll('table.activity tbody tr')
    expect(rows).toHaveLength(2)
    expect(rows[0]?.textContent).toContain('A connection was stopped.')
    expect(rows[1]?.textContent).toContain('A connection was started.')
    expect(rows[1]?.textContent).toContain('office')
  })

  // A filter accepted on screen and never sent is the worst outcome available here: the
  // reader gets the whole log and believes it is the narrow one they asked for.
  it('sends every filter it offers to the agent', async () => {
    const view = await at([CONNECTION_UP])

    fireEvent.click(view.getByRole('button', { name: 'warning' }))
    await settle()
    fireEvent.click(view.getByRole('button', { name: 'network' }))
    await settle()
    fireEvent.change(view.getByLabelText('Event'), { target: { value: 'connection.error' } })
    await settle()
    fireEvent.change(view.getByLabelText('Search'), { target: { value: 'office' } })
    fireEvent.click(view.getByRole('button', { name: 'Search' }))
    await settle()

    const query = lastQuery(view)
    expect(query.getAll('severity')).toEqual(['warning'])
    expect(query.getAll('category')).toEqual(['network'])
    expect(query.getAll('code')).toEqual(['connection.error'])
    expect(query.get('q')).toBe('office')
  })

  // The words a filter may use are served rather than written here, so a code added in Go
  // is offered without a second edit. A page holding its own list would quietly stop
  // offering half the log.
  it('offers exactly the filter words the agent serves', async () => {
    const served = makeTelemetry({ enabled: true, codes: ['app.start', 'thing.happened'] })
    const view = await at([], { 'GET /api/telemetry': served })

    for (const code of served.codes) {
      expect(view.getByRole('option', { name: code })).toBeInTheDocument()
    }
    for (const severity of served.severities) {
      expect(view.getByRole('button', { name: severity })).toBeInTheDocument()
    }
  })

  // A filter that matched nothing and a log that holds nothing look identical on screen,
  // and the way out of them is not the same: one is cleared, the other is waited for.
  it('tells a filter that matched nothing from a log with nothing in it', async () => {
    const view = await at([CONNECTION_UP], {
      'GET /api/telemetry/events': ({ url }: { url: string }) =>
        url.includes('severity=error') ? makeTelemetryPage([]) : makeTelemetryPage([CONNECTION_UP]),
    })

    fireEvent.click(view.getByRole('button', { name: 'error' }))
    await settle()

    expect(view.getByText('Nothing matched')).toBeInTheDocument()
    expect(view.queryByText('Nothing recorded yet')).not.toBeInTheDocument()

    fireEvent.click(view.getByRole('button', { name: 'Clear filters' }))
    await settle()

    expect(view.getByText('A connection was started.')).toBeInTheDocument()
  })

  // A read the agent refused and a log with nothing in it are the same blank screen, and
  // the reader draws the wrong conclusion from it: that the app has done nothing worth
  // recording. The refusal is the agent's own sentence, so it is shown as given.
  it('says so when the agent refuses to hand over the log', async () => {
    const view = await at([CONNECTION_UP], {
      'GET /api/telemetry/events': failWith(500, 'the log could not be read'),
    })

    expect(view.getByText('the log could not be read')).toBeInTheDocument()
    expect(view.container.querySelector('.notice.error')).not.toBeNull()
  })

  // A page that stopped at its limit looks exactly like a log that ends there. Saying
  // nothing leaves the reader concluding the agent did nothing before that point.
  it('says how much a page left out, and asks for more of it', async () => {
    const view = await at([CONNECTION_DOWN], {
      'GET /api/telemetry/events': makeTelemetryPage([CONNECTION_DOWN], 431),
    })

    expect(view.getByText(/431 matching/)).toBeInTheDocument()
    expect(lastQuery(view).get('limit')).toBe('100')

    fireEvent.click(view.getByRole('button', { name: 'Show more' }))
    await settle()

    expect(lastQuery(view).get('limit')).toBe('200')
  })

  // The page reads the events off the counters the module already publishes rather than
  // running a timer of its own. If that link breaks the screen silently freezes at
  // whatever it first loaded, which reads as an app that stopped doing anything.
  it('brings the list up to date when something new is recorded', async () => {
    vi.useFakeTimers()
    try {
      const view = await at([CONNECTION_UP])
      expect(view.queryByText('A connection was stopped.')).not.toBeInTheDocument()

      view.agent.set('GET /api/telemetry', recording([CONNECTION_UP, CONNECTION_DOWN]))
      view.agent.set(
        'GET /api/telemetry/events',
        makeTelemetryPage([CONNECTION_DOWN, CONNECTION_UP]),
      )
      await act(async () => {
        await vi.advanceTimersByTimeAsync(4000)
      })
      await settle()

      expect(view.getByText('A connection was stopped.')).toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })
})
