// SPDX-License-Identifier: MIT

// One dimension of the live traffic window, drawn as a line per key.
//
// The whole card holds one of these at a time. That is deliberate: the store starts a poll
// on a key's first subscriber and stops it on the last, so a dimension nobody is looking at
// costs no requests at all -- and a breakdown is most of the payload on this page.

import { useId, useMemo, useState } from 'react'

import type { TrafficBreakdown, TrafficLane, TrafficPeer } from '../../api'
import { usePolled } from '../../data/StoreProvider'
import { peak } from '../charts/geometry'
import { niceMax } from '../charts/scale'
import { TimeSeriesChart } from '../charts/TimeSeriesChart'
import { formatRate } from '../primitives'
import {
  linesFor,
  hasReadings,
  optionsFor,
  total,
  visible,
  type BreakdownFilter,
} from './breakdown'

/** What a lane calls itself, and what its emptiness means. Written per lane because "no
 *  device has carried anything" and "nothing has been asked of the proxy" send a reader
 *  somewhere different. */
const LANES: Record<TrafficLane, { title: string; empty: string }> = {
  devices: {
    title: 'Per device',
    empty:
      'No device has exchanged traffic yet. This fills in once the tailnet node is ' +
      'connected and something crosses it.',
  },
  connections: {
    title: 'Per connection',
    empty: 'No connection has carried anything yet.',
  },
  destinations: {
    title: 'Per destination',
    empty: 'Nothing has been asked of the proxy yet.',
  },
  ports: {
    title: 'Per port',
    empty:
      'Nothing has crossed a port app-tail carries yet. This covers the network interface, ' +
      'the subnet router and the forwards.',
  },
}

/** The two directions, drawn side by side on one shared scale so a line on the left can be
 *  read against the line that answered it on the right. */
const DIRECTIONS = [
  { key: 'up' as const, title: 'Up' },
  { key: 'down' as const, title: 'Down' },
]

/** Filters is the pair of pickers the ports lane offers: which connection carried a port,
 *  and which device reached it. Both are offered only where the rows actually name one, so
 *  a picker never appears with nothing behind it. */
function Filters({
  breakdown,
  filter,
  onChange,
  labels,
}: {
  breakdown: TrafficBreakdown
  filter: BreakdownFilter
  onChange: (next: BreakdownFilter) => void
  labels: ReadonlyMap<string, string>
}) {
  const viaId = useId()
  const peerId = useId()
  const vias = optionsFor(breakdown.series, 'via', labels)
  const peers = optionsFor(breakdown.series, 'peer', labels)

  if (vias.length === 0 && peers.length === 0) return null
  return (
    <div className="traffic-filters">
      {vias.length > 0 ? (
        <span className="traffic-filter">
          <label htmlFor={viaId}>Connection</label>
          <select
            id={viaId}
            value={filter.via ?? ''}
            onChange={(e) => onChange({ ...filter, via: e.target.value || undefined })}
          >
            <option value="">Every connection</option>
            {vias.map((o) => (
              <option key={o.id} value={o.id}>
                {o.label}
              </option>
            ))}
          </select>
        </span>
      ) : null}

      {peers.length > 0 ? (
        <span className="traffic-filter">
          <label htmlFor={peerId}>Device</label>
          <select
            id={peerId}
            value={filter.peer ?? ''}
            onChange={(e) => onChange({ ...filter, peer: e.target.value || undefined })}
          >
            <option value="">Every device</option>
            {peers.map((o) => (
              <option key={o.id} value={o.id}>
                {o.label}
              </option>
            ))}
          </select>
        </span>
      ) : null}
    </div>
  )
}

/**
 * PortsCharts is the ports lane with the names its filters need.
 *
 * Port rows carry a connection id and a device id, because those are what a filter has to
 * match on -- but neither is a name anybody would recognise. The connection list supplies
 * one half and the peer list already on this card the other. It is a separate component so
 * the connection poll is subscribed to only while the ports lane is on screen.
 */
export function PortsCharts({
  peers,
  ...rest
}: {
  smoothed: boolean
  hover: number | undefined
  onHover: (at: number | undefined) => void
  minutes: number
  peers: readonly TrafficPeer[]
}) {
  const tunnels = usePolled('tunnels')
  const known = tunnels.data
  const labels = useMemo(() => {
    const out = new Map<string, string>()
    for (const t of known ?? []) out.set(t.id, t.name)
    for (const p of peers) out.set(p.id, p.label)
    return out
  }, [known, peers])

  return <BreakdownCharts lane="ports" labels={labels} {...rest} />
}

/**
 * BreakdownCharts polls one lane and draws it.
 *
 * `lane` is a prop rather than four components because the subscription follows the key:
 * changing it here unsubscribes the old lane, which is what stops its poll, without the
 * card having to arrange anything.
 */
export function BreakdownCharts({
  lane,
  smoothed,
  hover,
  onHover,
  minutes,
  labels,
}: {
  lane: TrafficLane
  smoothed: boolean
  hover: number | undefined
  onHover: (at: number | undefined) => void
  minutes: number
  /** labels names the connections and devices the rows carry as ids. A id with no name
   *  here is still offered as a filter under its own id rather than dropped. */
  labels: ReadonlyMap<string, string>
}) {
  const [filter, setFilter] = useState<BreakdownFilter>({})
  const poll = usePolled(`traffic.${lane}` as const)
  const breakdown = poll.data
  const lanes = LANES[lane]

  if (breakdown === undefined) {
    if (poll.error !== undefined) {
      return (
        <p className="hint error">
          The {lanes.title.toLowerCase()} breakdown could not be read: {poll.error}
        </p>
      )
    }
    return <p className="hint">Reading the {lanes.title.toLowerCase()} breakdown…</p>
  }

  // Stated before the emptiness check, because in TUN mode the lane is empty *and* the
  // reason is the whole answer: an empty chart there says the machine is quiet, which is
  // exactly what it is not.
  if (breakdown.unmeasured) {
    return <p className="hint">{breakdown.unmeasured}</p>
  }

  const series = visible(breakdown, filter)
  if (!hasReadings(breakdown.series)) {
    return <p className="hint">{lanes.empty}</p>
  }

  const upLines = linesFor(series, 'up', smoothed)
  const downLines = linesFor(series, 'down', smoothed)
  // One scale across both charts: a download drawn against its own peak looks like an
  // upload of the same size, and comparing the two is the reason they sit side by side.
  const top = niceMax(Math.max(peak(upLines), peak(downLines)))
  const lines = { up: upLines, down: downLines }

  return (
    <>
      {lane === 'ports' ? (
        <Filters breakdown={breakdown} filter={filter} onChange={setFilter} labels={labels} />
      ) : null}

      {series.length === 0 ? (
        <p className="hint">Nothing matched that filter in the last {minutes} minutes.</p>
      ) : (
        <div className="traffic-charts">
          {DIRECTIONS.map((direction) => (
            <div className="traffic-chart" key={direction.key}>
              <div className="traffic-chart-head">
                <h3>{direction.title}</h3>
                <span className="traffic-chart-total">
                  {formatRate(total(series, direction.key))}
                </span>
              </div>
              <TimeSeriesChart
                summary={`${lanes.title}, ${direction.title.toLowerCase()}: ${formatRate(
                  total(series, direction.key),
                )} across ${series.length} of them, over the last ${minutes} minutes.`}
                format={formatRate}
                intervalSec={breakdown.intervalSec}
                max={top}
                hoverIndex={hover}
                onHover={onHover}
                series={lines[direction.key]}
              />
            </div>
          ))}
        </div>
      )}

      {/* A chart cut short by the cap reads as a complete one unless it says otherwise. */}
      {breakdown.folded ? (
        <p className="hint">
          {breakdown.folded} quieter {breakdown.folded === 1 ? 'key is' : 'keys are'} summed into
          the muted line rather than drawn by name.
        </p>
      ) : null}
    </>
  )
}
