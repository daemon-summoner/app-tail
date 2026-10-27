// SPDX-License-Identifier: MIT

import { act, fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import {
  deferred,
  emptySettingsForm,
  failWith,
  makeProxy,
  makeTraffic,
  makeTrafficBreakdown,
  makeTrafficPeer,
  makeTrafficSeries,
  openInfo,
  renderAgent,
  renderScoped,
  settle,
  type AgentView,
  type Routes,
} from '../test/agent'
import { TrafficCard } from './TrafficCard'
import type {
  ProxyView,
  SettingFieldSchema,
  TrafficBreakdown,
  TrafficPoint,
  TrafficView,
} from '../api'
import { settingsSchema } from '../generated/settingsSchema'
import type { SettingsForm } from './settings/useSettingsDraft'

/** A window with something moving in it. Rates are per second, as the agent serves them. */
function moving(overrides: Partial<TrafficView> = {}): TrafficView {
  const at = (n: number) => new Date(Date.UTC(2026, 6, 29, 10, 0, n)).toISOString()
  const point = (n: number, up: number, down: number, conns: number): TrafficPoint => ({
    at: at(n),
    proxyUp: up,
    proxyDown: down,
    forwardUp: 0,
    forwardDown: 0,
    routeIn: 0,
    routeOut: 0,
    tunnelUp: 0,
    tunnelDown: 0,
    connections: conns,
  })
  const points = [point(0, 1024, 2048, 2), point(1, 2048, 4096, 3), point(2, 1024, 8192, 3)]
  return makeTraffic({ points, current: points[2]!, ...overrides })
}

/**
 * The card's form, carrying the one setting the card renders itself.
 *
 * The field is taken from the generated schema rather than written out here, so a key
 * renamed in the registry fails these tests rather than quietly dropping the control.
 */
function formWithSmooth(
  smooth: boolean,
  onChange: (next: unknown) => void = () => {},
): SettingsForm {
  const field = settingsSchema.find((f) => f.key === 'traffic.smooth')
  if (field === undefined) throw new Error('the registry no longer declares traffic.smooth')
  const bind = (f: SettingFieldSchema) => ({
    value: f.key === 'traffic.smooth' ? smooth : '',
    example: '',
    onChange,
    stored: false,
    error: undefined,
    disabled: false,
  })
  return emptySettingsForm({
    available: [{ ...field, available: true, availableReason: '' }],
    bind,
    bindImmediate: bind,
  })
}

function cardWithProxy(
  view: TrafficView | undefined,
  proxy: ProxyView | undefined,
  form: SettingsForm = formWithSmooth(true),
) {
  return <TrafficCard view={view} proxy={proxy} form={form} />
}

/** The card on a machine running the proxy, which is what the destination table is about.
 *  A machine that is not running it is its own case, below. */
function card(view: TrafficView | undefined) {
  return cardWithProxy(view, makeProxy({ enabled: true }))
}

describe('what the card says is happening', () => {
  it('leads with the current rate in both directions', () => {
    const view = renderScoped(card(moving()))

    const chip = view.container.querySelector('.panel-head .status')
    expect(chip).toHaveTextContent('1.0 KB/s up')
    expect(chip).toHaveTextContent('8.0 KB/s down')
  })

  // A machine carrying nothing must read as carrying nothing rather than as a fault, and
  // the colour must not claim otherwise either.
  it('reads as idle rather than as a problem when nothing is moving', () => {
    const view = renderScoped(card(makeTraffic()))

    expect(view.container.querySelector('.panel-head .status')).toHaveTextContent('idle')
    expect(view.container.querySelector('.status.error')).toBeNull()
  })

  // Interface mode moves traffic without it passing the proxy, a forward or the subnet
  // router, so every lane but the tunnel reads zero. Leaving the tunnel out of the headline
  // is what made a saturated machine report "idle".
  it('reports what the tunnel carried when nothing else is running', () => {
    const view = renderScoped(
      card(
        moving({
          points: [],
          current: {
            at: new Date(Date.UTC(2026, 6, 29, 10, 0, 3)).toISOString(),
            proxyUp: 0,
            proxyDown: 0,
            forwardUp: 0,
            forwardDown: 0,
            routeIn: 0,
            routeOut: 0,
            tunnelUp: 3072,
            tunnelDown: 6144,
            connections: 0,
          },
        }),
      ),
    )

    const chip = view.container.querySelector('.panel-head .status')
    expect(chip).toHaveTextContent('3.0 KB/s up')
    expect(chip).toHaveTextContent('6.0 KB/s down')
    expect(chip).not.toHaveTextContent('idle')
  })

  // The tunnel counts every byte it carried and app-tail's own paths count the bytes they
  // were asked to carry -- through the proxy to a tunnel destination, those are the same
  // bytes seen twice. Adding them reports double the traffic the machine actually moved.
  it('does not double-count a transfer both measures saw', () => {
    const view = renderScoped(
      card(
        moving({
          points: [],
          current: {
            at: new Date(Date.UTC(2026, 6, 29, 10, 0, 3)).toISOString(),
            proxyUp: 1024,
            proxyDown: 2048,
            forwardUp: 0,
            forwardDown: 0,
            routeIn: 0,
            routeOut: 0,
            tunnelUp: 1024,
            tunnelDown: 2048,
            connections: 1,
          },
        }),
      ),
    )

    const chip = view.container.querySelector('.panel-head .status')
    expect(chip).toHaveTextContent('1.0 KB/s up')
    expect(chip).toHaveTextContent('2.0 KB/s down')
  })

  it('plots a line per direction, and one for connections', () => {
    const view = renderScoped(card(moving()))

    expect(view.container.querySelector('.chart-series.up')).toBeInTheDocument()
    expect(view.container.querySelector('.chart-series.down')).toBeInTheDocument()
    expect(view.container.querySelector('.chart-series.conns')).toBeInTheDocument()
  })

  // Both charts are the same window at the same cadence, and reading a spike against the
  // connection count that caused it is the whole reason they are shown together. Two
  // charts each keeping their own pointer would report two different moments at once.
  it('reports the same moment on both charts when one column is pointed at', () => {
    const view = renderScoped(card(moving()))

    const columns = view.container.querySelectorAll('.chart-hover rect')
    fireEvent.mouseEnter(columns[1]!)

    const tips = view.container.querySelectorAll('.chart-tooltip')
    expect(tips).toHaveLength(2)
    expect(tips[0]).toHaveTextContent('1.1 KB/s')
    expect(tips[1]).toHaveTextContent('Connections3')
    for (const tip of tips) expect(tip).toHaveTextContent('1s ago')
  })

  // Two points is the least a rate can be drawn from. Rendering a chart from one draws a
  // dot that reads as a measurement.
  it('says so rather than drawing a chart before anything has been measured', () => {
    const view = renderScoped(card(makeTraffic({ points: [], current: undefined as never })))

    expect(view.container.querySelector('.module-off')).toBeInTheDocument()
    expect(view.container.querySelector('polyline')).toBeNull()
  })

  // The card is on the page before the first poll lands: it says nothing has been measured
  // rather than drawing a chart from nothing or a rate of zero that reads as a quiet machine.
  it('says nothing is measured yet before the first poll lands', () => {
    const view = renderScoped(card(undefined))

    expect(view.getByRole('region', { name: 'Live traffic' })).toBeInTheDocument()
    expect(view.container.querySelector('.module-off')).toHaveTextContent('Nothing measured yet')
    expect(view.container.querySelector('polyline')).toBeNull()
    expect(view.container.querySelector('.traffic-rate')).toBeNull()
  })
})

describe('the devices table', () => {
  it('names each device with what crossed to and from it', () => {
    const view = renderScoped(
      card(moving({ peers: [makeTrafficPeer({ label: 'nas', rxBytes: 1024, txBytes: 2048 })] })),
    )

    const row = view.container.querySelector('.traffic-table tbody tr')
    expect(row).toHaveTextContent('nas')
    expect(row).toHaveTextContent('1.0 KB')
    expect(row).toHaveTextContent('2.0 KB')
  })

  // "Direct" and "relayed" is the usual explanation for a device that works and feels
  // slow, and it is not something the byte counts show.
  it('says how the device is reached, not only how much crossed', () => {
    const view = renderScoped(
      card(
        moving({
          peers: [
            makeTrafficPeer({ id: 'a', label: 'near', direct: true }),
            makeTrafficPeer({ id: 'b', label: 'far', direct: false, relay: 'fra' }),
          ],
        }),
      ),
    )

    expect(view.container).toHaveTextContent('direct')
    expect(view.container).toHaveTextContent('relay fra')
  })

  // Absent latency means nobody measured it. Rendering it as a number, or as zero, would
  // report an unprobed device as instantaneous.
  it('leaves the round trip blank when it was never measured', () => {
    const view = renderScoped(card(moving({ peers: [makeTrafficPeer()] })))

    expect(view.container.querySelector('.traffic-table tbody tr')).toHaveTextContent('—')
  })

  it('shows the round trip once it has been measured', () => {
    const view = renderScoped(card(moving({ peers: [makeTrafficPeer({ latencyMs: 12.34 })] })))

    expect(view.container.querySelector('.traffic-table tbody tr')).toHaveTextContent('12.3 ms')
  })

  it('says the table is empty rather than showing an empty table', () => {
    const view = renderScoped(card(moving({ peers: [] })))

    expect(view.container).toHaveTextContent('No device has exchanged traffic yet')
  })
})

describe('the destinations table', () => {
  it('names where the proxy sent traffic', () => {
    const view = renderScoped(
      card(
        moving({
          destinations: [
            {
              address: 'nas:445',
              bytesUp: 1024,
              bytesDown: 4096,
              opened: 2,
              active: 1,
              refused: 0,
              failed: 0,
            },
          ],
        }),
      ),
    )

    expect(view.container).toHaveTextContent('nas:445')
  })

  // The destination table is capped, and a list cut short reads as a complete one unless
  // it says so. This is the whole reason the agent reports what it folded away.
  it('says how much it is not naming when the cap was reached', () => {
    const view = renderScoped(
      card(
        moving({
          destinations: [
            {
              address: 'nas:445',
              bytesUp: 1,
              bytesDown: 1,
              opened: 1,
              active: 0,
              refused: 0,
              failed: 0,
            },
          ],
          folded: 7,
          other: {
            address: '',
            bytesUp: 1024,
            bytesDown: 1024,
            opened: 9,
            active: 0,
            refused: 0,
            failed: 0,
          },
        }),
      ),
    )

    expect(view.container).toHaveTextContent('7 more destinations are summed together')
  })

  it('says nothing about a cap that was never reached', () => {
    const view = renderScoped(card(moving()))

    expect(view.container.textContent).not.toContain('summed together')
  })

  // On a machine that does not run the proxy the table is a heading over a sentence saying
  // nothing has happened, for a feature nobody turned on. It takes half the width of the
  // card and reports nothing in either state.
  it('is absent entirely while the proxy is off', () => {
    const view = renderScoped(cardWithProxy(moving(), makeProxy({ enabled: false })))

    expect(view.container.textContent).not.toContain('Through the proxy')
    expect(view.container.textContent).not.toContain('Nothing has been asked of the proxy')
  })

  // Figures that exist are never hidden: the proxy was switched off with traffic still
  // reported against it, and dropping the table would drop the only record of it.
  it('stays while the proxy is off but has carried something', () => {
    const view = renderScoped(
      cardWithProxy(
        moving({
          destinations: [
            {
              address: 'nas:445',
              bytesUp: 1024,
              bytesDown: 4096,
              opened: 2,
              active: 1,
              refused: 0,
              failed: 0,
            },
          ],
        }),
        makeProxy({ enabled: false }),
      ),
    )

    expect(view.container).toHaveTextContent('Through the proxy')
    expect(view.container).toHaveTextContent('nas:445')
  })

  // The proxy has not answered yet. Drawing the table on a guess would put it on screen and
  // take it away a second later on a machine that does not run the proxy at all.
  it('waits rather than guessing before the proxy has answered', () => {
    const view = renderScoped(cardWithProxy(moving(), undefined))

    expect(view.container.textContent).not.toContain('Through the proxy')
  })
})

// The count is what the proxy and the forwards hold open. With neither of them carrying
// anything the chart is a flat zero taking half the card, beside the one measurement on the
// card that is actually moving.
describe('the connections chart', () => {
  const quiet = (proxy: ProxyView | undefined) =>
    cardWithProxy(
      moving({
        points: [
          { ...moving().points[0]!, connections: 0 },
          { ...moving().points[1]!, connections: 0 },
          { ...moving().points[2]!, connections: 0 },
        ],
      }),
      proxy,
    )

  it('is absent while nothing that opens connections is running', () => {
    const view = renderScoped(quiet(makeProxy({ enabled: false })))

    expect(view.container.querySelector('.chart-series.conns')).toBeNull()
    // Its heading rather than the whole card: the dimension picker names a Connections
    // breakdown too, and that one is a different thing entirely.
    const headings = [...view.container.querySelectorAll('.traffic-chart-head')]
    expect(headings.map((h) => h.textContent)).not.toContain('Connections')
    // The bandwidth chart is still there, and now has the row to itself.
    expect(view.container.querySelectorAll('.traffic-chart')).toHaveLength(1)
  })

  // The proxy is on and simply idle at this moment. Taking the chart away every time the
  // last connection closes would make it flicker on a machine that is using it.
  it('stays at zero while the proxy is on', () => {
    const view = renderScoped(quiet(makeProxy({ enabled: true })))

    expect(view.container.querySelector('.chart-series.conns')).toBeInTheDocument()
  })

  // Forwards open connections too, and they are counted here without the proxy running.
  it('stays for a count the proxy did not open', () => {
    const view = renderScoped(cardWithProxy(moving(), makeProxy({ enabled: false })))

    expect(view.container.querySelector('.chart-series.conns')).toBeInTheDocument()
  })

  // Connections are whole things that were either open or not. A running average over them
  // draws a count nobody had: four connections opening after a quiet stretch averages to one,
  // and the legend states that one as the number open right now.
  it('counts the connections that were open rather than averaging them', () => {
    const opening = moving({
      points: [
        { ...moving().points[0]!, connections: 0 },
        { ...moving().points[1]!, connections: 0 },
        { ...moving().points[2]!, connections: 4 },
      ],
    })
    const view = renderScoped(cardWithProxy(opening, makeProxy({ enabled: true })))

    const legend = view.container.querySelector('.chart-legend-item.conns')
    expect(legend).toHaveTextContent('4')
  })
})

// The card draws one dimension at a time. That is not only a layout decision: a breakdown
// is most of this page's payload, and the store polls exactly what is subscribed to.
describe('breaking the window down', () => {
  async function choose(view: AgentView, name: string): Promise<void> {
    fireEvent.click(view.getByRole('radio', { name }))
    await settle()
  }

  /** Every series the charts name, which is the one place the numbers are readable without
   *  pointing at anything. Both directions carry the same names, so this repeats them. */
  function legend(container: HTMLElement): string[] {
    return [...container.querySelectorAll('.chart-legend-label')].map((el) => el.textContent ?? '')
  }

  it('draws a line per key once a dimension is chosen', async () => {
    const view = await renderAgent(card(moving()))

    await choose(view, 'Devices')

    expect(legend(view.container)).toContain('nas')
    expect(legend(view.container)).toContain('laptop')
  })

  it('draws each lane the agent serves', async () => {
    for (const dimension of ['Devices', 'Connections', 'Destinations', 'Ports']) {
      const view = await renderAgent(card(moving()))
      await choose(view, dimension)

      expect(legend(view.container)).toContain('nas')
      view.unmount()
    }
  })

  // The machine-wide pair and a breakdown of it are the same bytes drawn twice. Leaving both
  // on screen would put the total beside a chart that claims to be it.
  it('replaces the machine-wide pair rather than adding to it', async () => {
    const view = await renderAgent(card(moving()))

    await choose(view, 'Devices')

    expect(view.container.querySelector('.chart-series.up')).toBeNull()
    expect(view.container.querySelector('.chart-series.conns')).toBeNull()
  })

  it('asks the agent only for the dimension on screen', async () => {
    const view = await renderAgent(card(moving()))
    expect(view.agent.countOf('GET /api/traffic/devices')).toBe(0)

    await choose(view, 'Devices')

    expect(view.agent.countOf('GET /api/traffic/devices')).toBe(1)
    expect(view.agent.countOf('GET /api/traffic/ports')).toBe(0)
  })

  // Rendering only the chosen dimension is the whole of the gating: the store starts a poll
  // on a key's first subscriber and stops it on the last. Children kept mounted and merely
  // hidden would leave every dimension costing a request every two seconds forever.
  it('stops polling a dimension the moment it leaves the screen', async () => {
    vi.useFakeTimers()
    try {
      const view = await renderAgent(card(moving()))
      await choose(view, 'Devices')

      // It is polling while it is shown, which is what makes the count below meaningful.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(6000)
      })
      const polled = view.agent.countOf('GET /api/traffic/devices')
      expect(polled).toBeGreaterThan(1)

      fireEvent.click(view.getByRole('radio', { name: 'Total' }))
      await act(async () => {
        await vi.advanceTimersByTimeAsync(6000)
      })

      expect(view.agent.countOf('GET /api/traffic/devices')).toBe(polled)
    } finally {
      vi.useRealTimers()
    }
  })

  // The lane has its own states, apart from the card's: it is read on its own poll, so it
  // can be waiting, refused or empty while the machine-wide pair above is drawing fine.
  it('says it is reading the lane until the first answer lands', async () => {
    const pending = deferred<TrafficBreakdown>()
    const view = await renderAgent(card(moving()), {
      'GET /api/traffic/devices': () => pending.promise,
    })

    await choose(view, 'Devices')

    expect(view.container).toHaveTextContent('Reading the per device breakdown…')
    expect(legend(view.container)).toEqual([])

    pending.resolve(makeTrafficBreakdown({ lane: 'devices' }))
    await settle()
    await settle()

    expect(legend(view.container)).toContain('nas')
  })

  it('says why the lane could not be read rather than waiting forever', async () => {
    const view = await renderAgent(card(moving()), {
      'GET /api/traffic/devices': failWith(503, 'the traffic meter is not running'),
    })

    await choose(view, 'Devices')

    expect(view.container.querySelector('.hint.error')).toHaveTextContent(
      'The per device breakdown could not be read: the traffic meter is not running',
    )
    expect(legend(view.container)).toEqual([])
  })

  // Two readings is the least a line can be drawn from. A key with one sample, or with
  // gaps where the samples should be, is a chart of one dot that reads as a measurement.
  it('says the lane is empty rather than drawing a line from fewer than two readings', async () => {
    const view = await renderAgent(card(moving()), {
      'GET /api/traffic/connections': makeTrafficBreakdown({
        lane: 'connections',
        series: [
          makeTrafficSeries({ key: 'tn_primary', label: 'Tailnet', up: [12], down: [40] }),
          makeTrafficSeries({ key: 'tn_lab', label: 'Lab', up: [null, 7], down: [null, null] }),
        ],
      }),
    })

    await choose(view, 'Connections')

    expect(view.container).toHaveTextContent('No connection has carried anything yet.')
    expect(legend(view.container)).toEqual([])
  })

  // A chart cut short by the cap reads as a complete one unless it says otherwise, and the
  // count has to agree in number with its sentence.
  it.each([
    [1, '1 quieter key is summed into the muted line'],
    [3, '3 quieter keys are summed into the muted line'],
  ])('says %i of the keys were folded into the muted line', async (folded, sentence) => {
    const view = await renderAgent(card(moving()), {
      'GET /api/traffic/devices': makeTrafficBreakdown({ lane: 'devices', folded }),
    })

    await choose(view, 'Devices')

    expect(view.container).toHaveTextContent(sentence)
  })

  it('says nothing about folding when every key is drawn by name', async () => {
    const view = await renderAgent(card(moving()))

    await choose(view, 'Devices')

    expect(view.container).not.toHaveTextContent('summed into the muted line')
  })
})

// Ports come from three seams that share nothing but a number -- the network interface, the
// subnet router and the forwards -- so the filters are how a reader asks about one of them.
describe('the ports lane', () => {
  const routes: Routes = {
    'GET /api/traffic/ports': makeTrafficBreakdown({
      lane: 'ports',
      series: [
        makeTrafficSeries({
          key: 'interface',
          label: 'tcp/443',
          detail: 'interface',
          via: 'wg1',
          up: [10, 20],
          down: [1, 2],
        }),
        makeTrafficSeries({
          key: 'routed',
          label: 'tcp/445',
          detail: 'nas',
          via: 'tn_primary',
          peer: 'n1',
          up: [5, 6],
          down: [7, 8],
        }),
      ],
    }),
  }

  async function ports(extra: Routes = {}): Promise<AgentView> {
    const view = await renderAgent(card(moving({ peers: [makeTrafficPeer()] })), {
      ...routes,
      ...extra,
    })
    fireEvent.click(view.getByRole('radio', { name: 'Ports' }))
    await settle()
    return view
  }

  function labels(container: HTMLElement): string[] {
    return [...container.querySelectorAll('.chart-legend-label')].map((el) => el.textContent ?? '')
  }

  it('narrows to the ports one connection carried', async () => {
    const view = await ports()

    fireEvent.change(view.getByLabelText('Connection'), { target: { value: 'wg1' } })

    expect(labels(view.container)).toContain('tcp/443')
    expect(labels(view.container)).not.toContain('tcp/445')
  })

  it('narrows to the ports one device reached', async () => {
    const view = await ports()

    fireEvent.change(view.getByLabelText('Device'), { target: { value: 'n1' } })

    expect(labels(view.container)).toContain('tcp/445')
    expect(labels(view.container)).not.toContain('tcp/443')
  })

  // The filter is applied here rather than by asking the agent again: the window is already
  // on the page, and a request per click would cost the payload the gating just saved.
  it('filters what it already holds rather than asking again', async () => {
    const view = await ports()
    const asked = view.agent.countOf('GET /api/traffic/ports')

    fireEvent.change(view.getByLabelText('Connection'), { target: { value: 'wg1' } })

    expect(view.agent.countOf('GET /api/traffic/ports')).toBe(asked)
  })

  // An empty chart reads as a quiet machine. In TUN mode the operating system carries the
  // packets, so the lane is empty on a machine that may well be saturated.
  it('says why it holds nothing rather than drawing an empty chart', async () => {
    const view = await ports({
      'GET /api/traffic/ports': makeTrafficBreakdown({
        lane: 'ports',
        series: [],
        unmeasured: 'Ports are not broken out in TUN mode.',
      }),
    })

    expect(view.container).toHaveTextContent('Ports are not broken out in TUN mode.')
    expect(view.container.querySelector('.chart-legend-label')).toBeNull()
  })
})

// A rate sampled once a second is spiky enough that the shape of a transfer is hard to read
// through the sampling noise. The line is drawn from a moving average, and the tooltip
// reads the same numbers the line is drawn from, so the two can never disagree.
describe('smoothing the lines', () => {
  /** A window whose middle second is a spike, sampled either side by quiet ones. */
  function spiky(): TrafficView {
    const at = (n: number) => new Date(Date.UTC(2026, 6, 29, 10, 0, n)).toISOString()
    const point = (n: number, up: number, gap = false): TrafficPoint => ({
      at: at(n),
      proxyUp: up,
      proxyDown: 0,
      forwardUp: 0,
      forwardDown: 0,
      routeIn: 0,
      routeOut: 0,
      tunnelUp: 0,
      tunnelDown: 0,
      connections: 0,
      ...(gap ? { gap: true } : {}),
    })
    const points = [point(0, 0), point(1, 3072), point(2, 0), point(3, 0, true), point(4, 1024)]
    return makeTraffic({ points, current: points[4]!, windowSec: 5 })
  }

  /** The bandwidth tooltip at one column, which reads the same numbers the line is drawn
   *  from. Pointing at a column is how a chart states a value in words. */
  function tipAt(container: HTMLElement, column: number): HTMLElement {
    fireEvent.mouseEnter(container.querySelectorAll('.chart-hover rect')[column]!)
    return container.querySelector<HTMLElement>('.chart-tooltip')!
  }

  it('averages each reading with the ones before it', () => {
    const view = renderScoped(card(spiky()))

    // A 3.0 KB/s spike one second into the window is drawn far below its height: the
    // average weighs it against the quiet second before it and starts spreading it over
    // the seconds to come.
    expect(tipAt(view.container, 1)).toHaveTextContent('384 B/s')
    // The quiet second after it does not drop straight back to nothing. The line is still
    // climbing toward the spike's crest, which the average puts a few seconds later.
    expect(tipAt(view.container, 2)).toHaveTextContent('540 B/s')
  })

  // The average only ever looks backwards, so a spike lands in the second it happened in.
  // Spreading it into the seconds before would draw traffic at a time nothing was moving.
  it('leaves the seconds before a spike where they were measured', () => {
    const view = renderScoped(card(spiky()))

    expect(tipAt(view.container, 0)).toHaveTextContent('0 B/s')
  })

  // An interval nothing was measured in is not a zero. Carrying an average across it would
  // draw a rate from before a stretch of time the agent cannot account for.
  it('starts the average again after an unmeasured interval, which stays a gap', () => {
    const view = renderScoped(card(spiky()))

    expect(tipAt(view.container, 3)).toHaveTextContent('not measured')
    // The reading after the gap stands alone, so it is the rate as measured.
    expect(tipAt(view.container, 4)).toHaveTextContent('1.0 KB/s')
  })

  // The headline is what the machine is doing this second, not an average of the last few.
  // Smoothing the figure somebody reads as "right now" would report a saturated link as
  // quieter than it is.
  it('leaves the headline as the reading it was measured at', () => {
    const view = renderScoped(card(spiky()))

    expect(view.container.querySelector('.panel-head .status')).toHaveTextContent('1.0 KB/s up')
  })

  // Smoothing is a choice about the drawing, not about the measurement, so it is a switch
  // rather than a decision made for everybody.
  describe('the switch that governs it', () => {
    const smooth = (container: HTMLElement) =>
      container.querySelector<HTMLInputElement>('.traffic-smooth input')!

    it('draws the readings as measured while it is off', () => {
      const view = renderScoped(
        cardWithProxy(spiky(), makeProxy({ enabled: true }), formWithSmooth(false)),
      )

      expect(smooth(view.container).checked).toBe(false)
      // The spike stands at its full height, and the quiet second after it is quiet again.
      expect(tipAt(view.container, 1)).toHaveTextContent('3.0 KB/s')
      expect(tipAt(view.container, 2)).toHaveTextContent('0 B/s')
    })

    it('is on, and averaging, while the setting is on', () => {
      const view = renderScoped(card(spiky()))

      expect(smooth(view.container).checked).toBe(true)
      expect(tipAt(view.container, 1)).toHaveTextContent('384 B/s')
      expect(tipAt(view.container, 2)).toHaveTextContent('540 B/s')
    })

    // Nothing to save afterwards: the switch is the decision, and it is written on the click.
    it('writes the setting the moment it is flipped', () => {
      const wrote = vi.fn()
      const view = renderScoped(
        cardWithProxy(spiky(), makeProxy({ enabled: true }), formWithSmooth(true, wrote)),
      )

      fireEvent.click(smooth(view.container))

      expect(wrote).toHaveBeenCalledWith(false)
    })

    // The control is on the charts it governs. Rendered again in the settings drawer below,
    // it would be two switches for one setting, disagreeing for as long as a write is in
    // flight.
    it('is not repeated in the card settings', () => {
      const view = renderScoped(card(spiky()))

      expect(view.container.querySelectorAll('.traffic-smooth input')).toHaveLength(1)
      expect(view.container.textContent).not.toContain('Traffic settings')
    })
  })
})

// The two sets of figures disagree by design -- the tailnet counts every byte it carried,
// the proxy only its own -- and a reader who does not know that reads it as a bug.
describe('what the card explains about itself', () => {
  it('says why the per-device and proxy figures differ', () => {
    const view = renderScoped(card(moving()))

    const info = openInfo(view.container, 'Live traffic')
    expect(info).toHaveTextContent('counting different things')
  })

  // The headline is the larger of two overlapping measures rather than their sum. A reader
  // who does not know that reads the figure against the per-lane tables below it and finds
  // arithmetic that does not add up.
  it('says the two measures overlap rather than add', () => {
    const view = renderScoped(card(moving()))

    const info = openInfo(view.container, 'Live traffic')
    expect(info).toHaveTextContent('larger of them rather than their sum')
  })

  it('keeps that explanation off the card until it is asked for', () => {
    const view = renderScoped(card(moving()))

    expect(view.container.textContent).not.toContain('counting different things')
  })
})
