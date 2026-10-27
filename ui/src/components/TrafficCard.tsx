// SPDX-License-Identifier: MIT

// What this machine is carrying, right now and for the last few minutes.
//
// Everything else on this page reports configuration; this reports activity. The series
// is the agent's own rather than one accumulated here, because the dashboard stops
// polling whenever its tab is hidden -- a history kept in the browser would go blank
// exactly when someone leaves the page open, and start empty on every reload.

import { useState } from 'react'

import type {
  ProxyView,
  TrafficDestination,
  TrafficLane,
  TrafficPeer,
  TrafficPoint,
  TrafficView,
} from '../api'
import type { Reading } from './charts/geometry'
import { smooth } from './charts/smooth'
import { TimeSeriesChart } from './charts/TimeSeriesChart'
import { ModuleOff } from './ModuleOff'
import { Panel } from './Panel'
import { formatBytes, formatRate, Toggle } from './primitives'
import { CardSettings } from './settings/CardSettings'
import type { SettingsForm } from './settings/useSettingsDraft'
import { BreakdownCharts, PortsCharts } from './traffic/BreakdownCharts'

/** The setting that governs whether the lines are drawn smoothed. */
const SMOOTH_KEY = 'traffic.smooth'

/** What the charts are broken down by. `total` is the machine-wide pair this card has
 *  always drawn; the rest each split one window by what that lane names. */
type Dimension = 'total' | TrafficLane

/** The dimensions in the order they widen: the whole machine, then who, then through what,
 *  then to where, then over which port. Someone reading a spike walks down this list. */
const DIMENSIONS: readonly { id: Dimension; label: string }[] = [
  { id: 'total', label: 'Total' },
  { id: 'devices', label: 'Devices' },
  { id: 'connections', label: 'Connections' },
  { id: 'destinations', label: 'Destinations' },
  { id: 'ports', label: 'Ports' },
]

/** No names to resolve: every lane but ports labels its own rows, so only ports needs a
 *  lookup at all. Shared rather than built per render so the memo below it stays stable. */
const NO_LABELS: ReadonlyMap<string, string> = new Map()

/** lane pulls one measure out of the series, turning an unmeasured interval into the gap
 *  the chart breaks its line at rather than into a zero it would draw as quiet. */
function lane(
  points: readonly TrafficPoint[],
  pick: (p: TrafficPoint) => number,
  smoothed: boolean,
): Reading[] {
  const readings = points.map((p) => (p.gap ? null : pick(p)))
  return smoothed ? smooth(readings) : readings
}

/** Whether the window holds anything worth drawing. Two points is the minimum a rate can
 *  be derived from, and one lone point draws as a dot nobody can read. */
function hasSeries(points: readonly TrafficPoint[]): boolean {
  return points.filter((p) => !p.gap).length >= 2
}

/** Bytes a second in one direction, which is the figure the headline states and the scale
 *  both charts share.
 *
 *  The larger of the two measures rather than their sum, because they overlap by an amount
 *  nothing here can know: the tunnel counts every byte it carried, and app-tail's own paths
 *  count the bytes they were asked to carry -- mostly the same bytes, seen twice. Whichever
 *  is larger is the one that saw the whole transfer. In interface mode the tunnel is the
 *  only lane that moves; through the proxy alone to a destination off the tunnel, it is the
 *  only lane that does not. */
function totalUp(p: TrafficPoint): number {
  return Math.max(p.tunnelUp, p.proxyUp + p.forwardUp + p.routeOut)
}

function totalDown(p: TrafficPoint): number {
  return Math.max(p.tunnelDown, p.proxyDown + p.forwardDown + p.routeIn)
}

/** Connections are whole things, so the axis and the tooltip count them rather than
 *  writing a rate. */
function formatCount(value: number): string {
  return `${Math.round(value)}`
}

/** How a peer is reached, as a word. "Direct" and "relayed" is the usual explanation for
 *  a device that works and feels slow, and it is not something the byte counts show. */
function pathOf(peer: TrafficPeer): string {
  if (peer.direct) return 'direct'
  if (peer.relay) return `relay ${peer.relay}`
  return peer.online ? 'connecting' : 'offline'
}

function Peers({ peers }: { peers: readonly TrafficPeer[] }) {
  if (peers.length === 0) {
    return (
      <p className="hint">
        No device has exchanged traffic yet. This fills in once the tailnet node is
        connected and something crosses it.
      </p>
    )
  }
  return (
    <table className="traffic-table">
      <thead>
        <tr>
          <th scope="col">Device</th>
          <th scope="col" className="numeric">
            In
          </th>
          <th scope="col" className="numeric">
            Out
          </th>
          <th scope="col">Path</th>
          <th scope="col" className="numeric optional">
            Round trip
          </th>
        </tr>
      </thead>
      <tbody>
        {peers.map((peer) => (
          <tr key={peer.id}>
            <td>
              <span className="traffic-name">{peer.label}</span>
              {peer.exitNode ? <span className="badge">exit node</span> : null}
            </td>
            <td className="numeric">{formatBytes(peer.rxBytes)}</td>
            <td className="numeric">{formatBytes(peer.txBytes)}</td>
            <td>{pathOf(peer)}</td>
            {/* Absent is "not measured", not "unreachable" -- the two lead somewhere
                different, so an unprobed device is never reported as slow. */}
            <td className="numeric optional">
              {peer.latencyMs === undefined ? '—' : `${peer.latencyMs.toFixed(1)} ms`}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function Destinations({
  destinations,
  other,
  folded,
}: {
  destinations: readonly TrafficDestination[]
  other: TrafficDestination | undefined
  folded: number
}) {
  if (destinations.length === 0) {
    return <p className="hint">Nothing has been asked of the proxy yet.</p>
  }
  return (
    <>
      <table className="traffic-table">
        <thead>
          <tr>
            <th scope="col">Destination</th>
            <th scope="col" className="numeric">
              Up
            </th>
            <th scope="col" className="numeric">
              Down
            </th>
            <th scope="col" className="numeric">
              Open
            </th>
            <th scope="col" className="numeric optional">
              Refused
            </th>
          </tr>
        </thead>
        <tbody>
          {destinations.map((d) => (
            <tr key={d.address}>
              <td>
                <span className="mono">{d.address}</span>
              </td>
              <td className="numeric">{formatBytes(d.bytesUp)}</td>
              <td className="numeric">{formatBytes(d.bytesDown)}</td>
              <td className="numeric">{d.active}</td>
              <td className="numeric optional">{d.refused + d.failed}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* A list cut short by the cap reads as a complete one unless it says otherwise. */}
      {folded > 0 && other ? (
        <p className="hint">
          {folded} more {folded === 1 ? 'destination is' : 'destinations are'} summed
          together, carrying {formatBytes(other.bytesUp + other.bytesDown)} in total.
        </p>
      ) : null}
    </>
  )
}

export function TrafficCard({
  view,
  proxy,
  form,
}: {
  view: TrafficView | undefined
  /** The proxy, for the one question this card asks of it: is anything going through it.
   *  Absent while the agent has not answered yet. */
  proxy: ProxyView | undefined
  form: SettingsForm
}) {
  // One hovered column for both charts: bandwidth and connections are the same window
  // sampled at the same cadence, and reading a spike against the connection count that
  // caused it is the whole point of showing them together.
  const [hover, setHover] = useState<number | undefined>(undefined)
  const [dimension, setDimension] = useState<Dimension>('total')

  const points = view?.points ?? []
  const current = view?.current
  const up = current ? totalUp(current) : 0
  const down = current ? totalDown(current) : 0
  const connections = current?.connections ?? 0

  const intervalSec = view?.intervalSec ?? 1
  const minutes = Math.round((view?.windowSec ?? 300) / 60)
  const moving = up >= 1 || down >= 1

  // The proxy's own table, on a machine that does not run the proxy, is a heading over a
  // sentence saying nothing has happened -- for a feature the reader has not turned on. It
  // is shown while the proxy is on, and while it has carried something whatever the module
  // now says: figures that exist are never hidden.
  const destinations = view?.destinations ?? []
  const throughProxy = proxy?.enabled === true || destinations.length > 0

  // The connection count is what the proxy and the forwards are holding open, so on a
  // machine running neither it is a flat zero drawn beside the chart that means something.
  // It is kept while the proxy is on, and whenever the window holds a count at all, so
  // forwards on their own still get their graph.
  const counting = throughProxy || points.some((p) => !p.gap && p.connections > 0)

  // Read from the draft rather than from the stored document, so the lines redraw on the
  // click rather than a poll later. The control sits with the charts it governs, so it is
  // kept out of the settings drawer below.
  const smoothField = form.available.find((f) => f.key === SMOOTH_KEY)
  const smoothBinding = smoothField === undefined ? undefined : form.bindImmediate(smoothField)
  const smoothed = smoothBinding?.value === true

  return (
    <Panel
      title="Live traffic"
      wide
      status={
        moving
          ? { tone: 'running', label: `${formatRate(up)} up`, detail: `${formatRate(down)} down` }
          : { tone: 'off', label: 'idle' }
      }
      info={
        <>
          <p>
            What this machine is carrying, sampled once a second and kept for {minutes}{' '}
            minutes. The agent samples it, so the history survives a reload and keeps
            filling while this page is in a background tab.
          </p>
          <p>
            Two things are counted here: what the tunnel carried, and what app-tail&rsquo;s
            own proxy, forwards and subnet routes carried. Mostly those are the same bytes
            seen twice, so the headline is the larger of them rather than their sum. In
            interface mode the tunnel is the only one that moves, because traffic leaves
            through the network interface without passing app-tail at all.
          </p>
          <p>
            Per-device figures come from the tailnet itself and count everything it
            carried, so they will not match the proxy&rsquo;s own totals. Neither is
            wrong; they are counting different things.
          </p>
        </>
      }
    >
      {!hasSeries(points) ? (
        <ModuleOff>
          Nothing measured yet. The first readings appear a couple of seconds after the
          agent starts.
        </ModuleOff>
      ) : (
        <>
          {/* The headline figures, large enough to read from across the room. They are
              the same numbers the chip in the head carries, set where the charts can be
              read against them. */}
          <dl className="traffic-metrics">
            <div className="traffic-metric">
              <dt className="metric-label">Up</dt>
              <dd className="metric">{formatRate(up)}</dd>
            </div>
            <div className="traffic-metric">
              <dt className="metric-label">Down</dt>
              <dd className="metric">{formatRate(down)}</dd>
            </div>
            {counting ? (
              <div className="traffic-metric">
                <dt className="metric-label">Connections</dt>
                <dd className="metric">{formatCount(connections)}</dd>
              </div>
            ) : null}
          </dl>

          <div className="traffic-controls">
            <div
              className="traffic-dimensions"
              role="radiogroup"
              aria-label="Break the traffic down by"
            >
              {DIMENSIONS.map((d) => (
                // A radio rather than a button: these are one choice with five positions,
                // and that is what somebody driving this from the keyboard expects.
                <label
                  key={d.id}
                  className={d.id === dimension ? 'traffic-dimension chosen' : 'traffic-dimension'}
                >
                  <input
                    type="radio"
                    name="traffic-dimension"
                    value={d.id}
                    checked={d.id === dimension}
                    onChange={() => setDimension(d.id)}
                  />
                  <span>{d.label}</span>
                </label>
              ))}
            </div>

            {smoothField !== undefined && smoothBinding !== undefined ? (
              <span className="traffic-smooth">
                <Toggle
                  checked={smoothed}
                  onChange={smoothBinding.onChange}
                  label={smoothField.label}
                  disabled={smoothBinding.disabled}
                />
                <span>Smooth</span>
              </span>
            ) : null}
          </div>

          {/* Only the chosen dimension is rendered, which is the whole of the gating: the
              store stops polling a breakdown the moment nothing is subscribed to it. */}
          {dimension === 'total' ? (
            <div className="traffic-charts">
              <div className="traffic-chart">
                <div className="traffic-chart-head">
                  <h3>Bandwidth</h3>
                </div>
                <TimeSeriesChart
                  summary={`Carrying ${formatRate(up)} up and ${formatRate(down)} down, over the last ${minutes} minutes.`}
                  format={formatRate}
                  intervalSec={intervalSec}
                  hoverIndex={hover}
                  onHover={setHover}
                  series={[
                    {
                      id: 'up',
                      label: 'Up',
                      values: lane(points, totalUp, smoothed),
                      fill: true,
                    },
                    {
                      id: 'down',
                      label: 'Down',
                      values: lane(points, totalDown, smoothed),
                      dashed: true,
                    },
                  ]}
                />
              </div>

              {counting ? (
                <div className="traffic-chart">
                  <div className="traffic-chart-head">
                    <h3>Connections</h3>
                  </div>
                  <TimeSeriesChart
                    summary={`${connections} connections open, over the last ${minutes} minutes.`}
                    format={formatCount}
                    intervalSec={intervalSec}
                    hoverIndex={hover}
                    onHover={setHover}
                    series={[
                      {
                        id: 'conns',
                        label: 'Connections',
                        // Never smoothed, whatever the switch says: an average of a count of
                        // whole things is a number nobody ever had open, and the legend states
                        // it as what is open now.
                        values: lane(points, (p) => p.connections, false),
                        fill: true,
                      },
                    ]}
                  />
                </div>
              ) : null}
            </div>
          ) : dimension === 'ports' ? (
            <PortsCharts
              smoothed={smoothed}
              hover={hover}
              onHover={setHover}
              minutes={minutes}
              peers={view?.peers ?? []}
            />
          ) : (
            // Keyed by lane so the chart is rebuilt rather than reused: a filter chosen on
            // one dimension means nothing on the next.
            <BreakdownCharts
              key={dimension}
              lane={dimension}
              smoothed={smoothed}
              hover={hover}
              onHover={setHover}
              minutes={minutes}
              labels={NO_LABELS}
            />
          )}

          <div className="traffic-lists">
            <div className="traffic-list">
              <h3>Devices</h3>
              <Peers peers={view?.peers ?? []} />
            </div>
            {throughProxy ? (
              <div className="traffic-list">
                <h3>Through the proxy</h3>
                <Destinations
                  destinations={destinations}
                  other={view?.other}
                  folded={view?.folded ?? 0}
                />
              </div>
            ) : null}
          </div>
        </>
      )}

      <CardSettings
        form={form}
        groups={['traffic']}
        omit={[SMOOTH_KEY]}
        collapseLabel="Traffic settings"
      />
    </Panel>
  )
}
