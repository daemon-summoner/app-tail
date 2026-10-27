// SPDX-License-Identifier: MIT

import { act, fireEvent, render } from '@testing-library/react'
import { type ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { type Status, type TrafficView } from '../api'
import { makeStatus, makeTraffic, stubAgent } from '../test/agent'
import { resources, type ResourceTable } from './resources'
import { PollStore } from './store'
import { StoreProvider, usePolled } from './StoreProvider'

/** StatusProbe renders one polled key and reports every value it produced, so a test can
 *  assert on the store without reaching into React internals. */
function StatusProbe() {
  const { data, error, loading, failures, refresh } = usePolled('status')
  return (
    <div>
      <span data-testid="version">{data?.version ?? ''}</span>
      <span data-testid="error">{error ?? ''}</span>
      <span data-testid="loading">{String(loading)}</span>
      <span data-testid="failures">{String(failures)}</span>
      <button onClick={refresh}>refresh</button>
    </div>
  )
}

/** TrafficProbe reads a second key, so a test can prove the two are polled independently. */
function TrafficProbe() {
  const traffic = usePolled('traffic')
  return <span data-testid="traffic">{String(traffic.loading)}</span>
}

/** registry builds a table where the keys under test answer from a fetcher the test owns,
 *  leaving every other key at its real definition. */
function registry(overrides: Partial<ResourceTable>): ResourceTable {
  return { ...resources, ...overrides }
}

/** deferred is a promise a test resolves by hand, which is the only way to observe the
 *  store while a request is still on its way. */
function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((settle) => {
    resolve = settle
  })
  return { promise, resolve }
}

/** advance runs the clock forward and lets the resulting promises settle. */
async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms)
  })
}

/** show mounts a tree against one store, the way the dashboard's provider does. */
function show(store: PollStore, children: ReactNode) {
  return render(<StoreProvider store={store}>{children}</StoreProvider>)
}

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('PollStore', () => {
  it('reports the first result and leaves loading behind', async () => {
    const fetch = () => Promise.resolve(makeStatus({ version: 'first' }))
    const store = new PollStore(registry({ status: { fetch, intervalMs: 1000 } }))
    const view = show(store, <StatusProbe />)

    await advance(0)

    expect(view.getByTestId('version').textContent).toBe('first')
    expect(view.getByTestId('loading').textContent).toBe('false')
  })

  // Two screens wanting the same thing at the same moment is the case a poll per component
  // could not handle: the dashboard and the devices page both read traffic, and each
  // additional reader used to cost another timer and another request.
  it('answers two readers of one key with a single request and a single timer', async () => {
    const held = deferred<Status>()
    const fetch = vi.fn(() => held.promise)
    const store = new PollStore(registry({ status: { fetch, intervalMs: 1000 } }))

    const view = show(
      store,
      <>
        <StatusProbe />
        <StatusProbe />
      </>,
    )
    await advance(0)
    expect(fetch).toHaveBeenCalledTimes(1)

    await act(async () => {
      held.resolve(makeStatus({ version: 'shared' }))
      await Promise.resolve()
    })
    expect(view.getAllByTestId('version').map((node) => node.textContent)).toEqual([
      'shared',
      'shared',
    ])

    await advance(1000)
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  // Two cards saved at once, or a save landing while a tick is already out, would otherwise
  // put two requests for the same thing on the wire and let the slower one win.
  it('answers a refresh that arrives mid-request with the request already on its way', async () => {
    const held = deferred<Status>()
    const fetch = vi.fn(() => held.promise)
    const store = new PollStore(registry({ status: { fetch, intervalMs: 60_000 } }))
    show(store, <StatusProbe />)
    await advance(0)
    expect(fetch).toHaveBeenCalledTimes(1)

    store.refresh('status')
    store.refresh('status')

    expect(fetch).toHaveBeenCalledTimes(1)
    await act(async () => {
      held.resolve(makeStatus())
      await Promise.resolve()
    })
  })

  it('surfaces a failure and recovers on the next tick', async () => {
    const fetch = vi
      .fn<() => Promise<Status>>()
      .mockRejectedValueOnce(new Error('agent is down'))
      .mockResolvedValue(makeStatus({ version: 'back' }))
    const store = new PollStore(registry({ status: { fetch, intervalMs: 1000 } }))

    const view = show(store, <StatusProbe />)
    await advance(0)
    expect(view.getByTestId('error').textContent).toBe('agent is down')

    await advance(1000)
    expect(view.getByTestId('version').textContent).toBe('back')
    expect(view.getByTestId('error').textContent).toBe('')
  })

  // A card that emptied itself every time one poll failed would flicker through a restart
  // that changed nothing, so the last good value stays on screen beside the complaint.
  it('keeps the last value on screen while a poll is failing', async () => {
    const fetch = vi
      .fn<() => Promise<Status>>()
      .mockResolvedValueOnce(makeStatus({ version: 'good' }))
      .mockRejectedValue(new Error('agent is down'))
    const store = new PollStore(registry({ status: { fetch, intervalMs: 1000 } }))

    const view = show(store, <StatusProbe />)
    await advance(0)
    await advance(1000)

    expect(view.getByTestId('version').textContent).toBe('good')
    expect(view.getByTestId('error').textContent).toBe('agent is down')
  })

  // Keeping the last value is what makes a screen unable to tell a restart from an agent
  // that died an hour ago. The count of failures in a row is the only difference between
  // the two, so it is published rather than kept for the backoff alone.
  it('counts the failures in a row and starts again at the first answer', async () => {
    const fetch = vi
      .fn<() => Promise<Status>>()
      .mockResolvedValueOnce(makeStatus({ version: 'good' }))
      .mockRejectedValueOnce(new Error('agent is down'))
      .mockRejectedValueOnce(new Error('agent is down'))
      .mockResolvedValue(makeStatus({ version: 'back' }))
    const store = new PollStore(registry({ status: { fetch, intervalMs: 1000 } }))

    const view = show(store, <StatusProbe />)
    await advance(0)
    expect(view.getByTestId('failures').textContent).toBe('0')

    await advance(1000)
    expect(view.getByTestId('failures').textContent).toBe('1')
    await advance(1000)
    expect(view.getByTestId('failures').textContent).toBe('2')

    await advance(1000)
    expect(view.getByTestId('version').textContent).toBe('back')
    expect(view.getByTestId('failures').textContent).toBe('0')
  })

  // A dashboard left open in a background tab must not keep asking the agent for status
  // every two seconds for the rest of the day.
  it('skips the tick while the tab is hidden', async () => {
    const fetch = vi.fn(() => Promise.resolve(makeStatus()))
    const store = new PollStore(registry({ status: { fetch, intervalMs: 1000 } }))
    show(store, <StatusProbe />)
    await advance(0)
    const afterFirst = fetch.mock.calls.length

    vi.spyOn(document, 'hidden', 'get').mockReturnValue(true)
    await advance(3000)

    expect(fetch.mock.calls.length).toBe(afterFirst)
  })

  // The subscription is what pays for the poll: a key nobody renders any more is a key the
  // agent stops being asked about, which is the whole point of counting subscribers.
  it('stops polling a key once nothing is reading it', async () => {
    const fetch = vi.fn(() => Promise.resolve(makeStatus()))
    const store = new PollStore(registry({ status: { fetch, intervalMs: 1000 } }))
    const view = show(store, <StatusProbe />)
    await advance(0)
    const afterFirst = fetch.mock.calls.length

    view.unmount()
    await advance(5000)

    expect(fetch.mock.calls.length).toBe(afterFirst)
  })

  // Every mutation the dashboard makes ends in a refresh, so this runs on each toggle,
  // save and delete rather than only on a timer.
  it('fetches again on demand without waiting for the next tick', async () => {
    const fetch = vi
      .fn<() => Promise<Status>>()
      .mockResolvedValueOnce(makeStatus({ version: 'before' }))
      .mockResolvedValue(makeStatus({ version: 'after' }))
    const store = new PollStore(registry({ status: { fetch, intervalMs: 60_000 } }))

    const view = show(store, <StatusProbe />)
    await advance(0)
    expect(view.getByTestId('version').textContent).toBe('before')

    fireEvent.click(view.getByText('refresh'))
    await advance(0)

    expect(view.getByTestId('version').textContent).toBe('after')
  })

  // loading is the first-paint flag. Flipping it on every refresh would put the dashboard
  // back into its skeleton state each time the user toggles a forward.
  it('leaves loading alone once the first result has landed', async () => {
    const fetch = vi.fn(() => Promise.resolve(makeStatus()))
    const store = new PollStore(registry({ status: { fetch, intervalMs: 60_000 } }))
    const view = show(store, <StatusProbe />)
    await advance(0)
    expect(view.getByTestId('loading').textContent).toBe('false')

    fireEvent.click(view.getByText('refresh'))

    // Checked before the refresh settles, which is the only window in which a reset would
    // be observable.
    expect(view.getByTestId('loading').textContent).toBe('false')
    await advance(0)
    expect(view.getByTestId('loading').textContent).toBe('false')
  })

  // The tick is skipped while hidden, so coming back to the tab is the only thing that can
  // close the gap. Without it the dashboard shows whatever was true when the user last
  // looked -- possibly a connected node that has since dropped.
  it('refetches the moment a hidden tab is looked at again', async () => {
    const hidden = vi.spyOn(document, 'hidden', 'get').mockReturnValue(true)
    const fetch = vi.fn(() => Promise.resolve(makeStatus()))
    const store = new PollStore(registry({ status: { fetch, intervalMs: 1000 } }))
    show(store, <StatusProbe />)
    await advance(0)
    const afterMount = fetch.mock.calls.length

    // Still hidden: becoming visible is the event, not the event firing at all.
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await Promise.resolve()
    })
    expect(fetch.mock.calls.length).toBe(afterMount)

    hidden.mockReturnValue(false)
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await Promise.resolve()
    })

    expect(fetch.mock.calls.length).toBe(afterMount + 1)
  })

  // The listener is attached on the first subscriber and removed with the last, rather than
  // in the constructor: a store whose document listener outlived its readers would keep
  // waking polls for screens that are no longer mounted.
  it('stops listening for the tab coming back once its last reader is gone', async () => {
    const attach = vi.spyOn(document, 'addEventListener')
    const detach = vi.spyOn(document, 'removeEventListener')
    const fetch = vi.fn(() => Promise.resolve(makeStatus()))
    const store = new PollStore(registry({ status: { fetch, intervalMs: 1000 } }))

    const view = show(store, <StatusProbe />)
    await advance(0)
    const attached = attach.mock.calls.filter(([type]) => type === 'visibilitychange')
    expect(attached).toHaveLength(1)

    view.unmount()

    const detached = detach.mock.calls.filter(([type]) => type === 'visibilitychange')
    expect(detached).toHaveLength(1)
    expect(detached[0]?.[1]).toBe(attached[0]?.[1])
  })

  // The cadence belongs to the key, not to the caller. A single timer for the whole store
  // would poll a four-second key every two seconds, or the reverse.
  it('polls each key at its own cadence', async () => {
    const status = vi.fn<() => Promise<Status>>().mockResolvedValue(makeStatus())
    const traffic = vi.fn<() => Promise<TrafficView>>().mockResolvedValue(makeTraffic())
    const store = new PollStore(
      registry({
        status: { fetch: status, intervalMs: 1000 },
        traffic: { fetch: traffic, intervalMs: 5000 },
      }),
    )

    show(
      store,
      <>
        <StatusProbe />
        <TrafficProbe />
      </>,
    )
    await advance(0)
    expect(status).toHaveBeenCalledTimes(1)
    expect(traffic).toHaveBeenCalledTimes(1)

    await advance(1000)
    expect(status).toHaveBeenCalledTimes(2)
    expect(traffic).toHaveBeenCalledTimes(1)

    await advance(4000)
    expect(traffic).toHaveBeenCalledTimes(2)
  })

  // fetch rejects with a plain string or a DOMException often enough that assuming an
  // Error would render "undefined" where the reason belongs.
  it('reports a rejection that is not an Error', async () => {
    const fetch = vi.fn<() => Promise<Status>>().mockRejectedValue('the socket closed')
    const store = new PollStore(registry({ status: { fetch, intervalMs: 1000 } }))

    const view = show(store, <StatusProbe />)
    await advance(0)

    expect(view.getByTestId('error').textContent).toBe('the socket closed')
    expect(view.getByTestId('loading').textContent).toBe('false')
  })

  // One failed request is usually a restart. Backing off immediately would make a
  // two-second outage look like a thirty-second one, and never backing off would hammer an
  // agent that is down for the afternoon.
  it('keeps its cadence through two failures and slows down after the third', async () => {
    const fetch = vi.fn<() => Promise<Status>>().mockRejectedValue(new Error('down'))
    const store = new PollStore(registry({ status: { fetch, intervalMs: 1000 } }))
    show(store, <StatusProbe />)

    await advance(0)
    await advance(2000)
    expect(fetch).toHaveBeenCalledTimes(3)

    // The fourth attempt is two seconds out rather than one, so the old cadence must pass
    // without a request.
    await advance(1000)
    expect(fetch).toHaveBeenCalledTimes(3)
    await advance(1000)
    expect(fetch).toHaveBeenCalledTimes(4)
  })

  // An agent that comes back has to be noticed without the user reloading the page, so the
  // wait between attempts stops growing well short of the doubling it starts with.
  it('never waits longer than thirty seconds between attempts however long it is down', async () => {
    const attempts: number[] = []
    const fetch = vi.fn<() => Promise<Status>>(() => {
      attempts.push(Date.now())
      return Promise.reject(new Error('down'))
    })
    const store = new PollStore(registry({ status: { fetch, intervalMs: 1000 } }))
    show(store, <StatusProbe />)

    await advance(0)
    await advance(300_000)

    const gaps = attempts.slice(1).map((at, index) => at - (attempts[index] ?? 0))
    expect(gaps.length).toBeGreaterThan(8)
    expect(Math.max(...gaps)).toBe(30_000)
  })

  // The top bar's refresh means "everything on this screen", not "every key this store has
  // ever been asked for": fetching a key nobody is rendering is work for a screen that is
  // not on.
  it('refreshes only the keys something is watching', async () => {
    const status = vi.fn<() => Promise<Status>>().mockResolvedValue(makeStatus())
    const traffic = vi.fn<() => Promise<TrafficView>>().mockResolvedValue(makeTraffic())
    const store = new PollStore(
      registry({
        status: { fetch: status, intervalMs: 60_000 },
        traffic: { fetch: traffic, intervalMs: 60_000 },
      }),
    )
    // Traffic is read once and then navigated away from, so the store knows the key and
    // holds its value: the question is whether a refresh reaches it anyway.
    const closed = show(store, <TrafficProbe />)
    await advance(0)
    closed.unmount()
    expect(traffic).toHaveBeenCalledTimes(1)

    show(store, <StatusProbe />)
    await advance(0)

    await act(async () => {
      store.refreshAll()
      await Promise.resolve()
    })

    expect(status).toHaveBeenCalledTimes(2)
    expect(traffic).toHaveBeenCalledTimes(1)
  })

  // A watched key is re-read at once because something is showing it, and the write that
  // invalidated it is the reason its old value is now wrong.
  it('re-reads a watched key the moment it is invalidated', async () => {
    const fetch = vi
      .fn<() => Promise<Status>>()
      .mockResolvedValueOnce(makeStatus({ version: 'stale' }))
      .mockResolvedValue(makeStatus({ version: 'fresh' }))
    const store = new PollStore(registry({ status: { fetch, intervalMs: 60_000 } }))
    const view = show(store, <StatusProbe />)
    await advance(0)
    expect(view.getByTestId('version').textContent).toBe('stale')

    await act(async () => {
      store.invalidate('status')
      await Promise.resolve()
    })

    expect(view.getByTestId('version').textContent).toBe('fresh')
  })

  // The screen that reads an invalidated key next has to start from the agent. Keeping the
  // cached value would show what was true before the write that invalidated it.
  it('drops the cached value of a key nothing is watching when it is invalidated', async () => {
    const fetch = vi.fn(() => Promise.resolve(makeStatus({ version: 'cached' })))
    const store = new PollStore(registry({ status: { fetch, intervalMs: 60_000 } }))
    const view = show(store, <StatusProbe />)
    await advance(0)
    view.unmount()
    expect(store.snapshot('status').data).not.toBeUndefined()

    store.invalidate('status')

    expect(store.snapshot('status').data).toBeUndefined()
    expect(store.snapshot('status').loading).toBe(true)
  })

  // A response that was already on its way when its key was invalidated describes the state
  // before the write. Publishing it would put the value back that the invalidation just
  // removed, and nothing would correct it until the next tick.
  it('discards a response that stopped being wanted while it was in flight', async () => {
    const held = deferred<Status>()
    const fetch = () => held.promise
    const store = new PollStore(registry({ status: { fetch, intervalMs: 60_000 } }))

    store.refresh('status')
    store.invalidate('status')

    await act(async () => {
      held.resolve(makeStatus({ version: 'overtaken' }))
      await Promise.resolve()
    })

    expect(store.snapshot('status').data).toBeUndefined()
    expect(store.snapshot('status').loading).toBe(true)
  })

  // The alternative -- a lazily created module-level store -- would hide the wiring mistake
  // and leak one screen's cached responses into the next.
  it('fails loudly when a component polls with no provider above it', () => {
    const quiet = vi.spyOn(console, 'error').mockImplementation(() => {})

    expect(() => render(<StatusProbe />)).toThrow(/no StoreProvider/)

    quiet.mockRestore()
  })

  // The registry is the wiring between a key and the agent's route. A store that polled
  // correctly but asked for the wrong thing would pass every test above.
  it('reads a key from the agent route its resource names', async () => {
    const agent = stubAgent({ 'GET /api/status': makeStatus({ version: '9.9.9' }) })
    const view = show(new PollStore(), <StatusProbe />)

    await advance(0)

    expect(agent.countOf('GET /api/status')).toBe(1)
    expect(view.getByTestId('version').textContent).toBe('9.9.9')
  })
})
