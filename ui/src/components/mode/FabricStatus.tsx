// SPDX-License-Identifier: MIT

// What the one interface is actually carrying, on the page where it was chosen.
//
// The mode card above says which arrangement was asked for. This says what is happening,
// and the two are different questions: the interface is claimed once, at the moment the
// node starts, so a machine can sit in this mode with nothing carried and every address
// on every connection quietly unreachable. Reporting the mode alone would show that as
// healthy.

import { formatBytes, Notice } from '../primitives'
import { Panel } from '../Panel'
import type { FabricCarried, FabricView } from '../../api'

/** nameOf is what one carried connection is called. The last arm is the entry with no
 *  connection at all: an address no connection carried, refused at the interface. */
function nameOf(carried: FabricCarried): string {
  return carried.name ?? carried.tunnelId ?? 'No connection'
}

export function FabricStatus({
  view,
  chosen,
  error,
}: {
  view: FabricView | undefined
  /** Whether this machine is in the mode. The panel is about the mode, so it is absent
   *  under every other arrangement rather than reporting an interface nobody asked for. */
  chosen: boolean
  error?: string | undefined
}) {
  if (!chosen) return null

  if (view === undefined) {
    return (
      <Panel title="What the interface carries" wide>
        <p className="module-off">{error ?? 'Reading what the interface is carrying…'}</p>
      </Panel>
    )
  }

  const routes = view.routes ?? []
  const carried = view.carried ?? []

  return (
    <Panel
      title="What the interface carries"
      wide
      status={
        view.running
          ? { tone: 'running', label: 'carrying', detail: view.interface }
          : { tone: view.error ? 'error' : 'pending', label: 'not carrying' }
      }
      info={
        <p>
          Every program on this machine reaches these networks by address. app-tail ends
          each connection at the interface and opens it again inside the network the
          address belonged to, so only TCP and UDP cross.
        </p>
      }
    >
      {/* Said before the numbers: with nothing carried every counter below is zero, and a
      row of zeroes reads as an idle machine rather than an unreachable one. */}
      {view.running ? null : (
        <p className="module-off">
          {view.error ??
            'The mode is set and nothing is on the interface yet. Restart the connections to move onto it.'}
        </p>
      )}

      <dl className="proxy-counters">
        <div>
          <dt>Interface</dt>
          <dd>{view.interface ?? '—'}</dd>
        </div>
        <div>
          <dt title="The largest packet the interface carries: the smallest of the connected networks' own">
            Packet size
          </dt>
          <dd>{view.mtu ? `${view.mtu} bytes` : '—'}</dd>
        </div>
        <div>
          <dt>Ranges</dt>
          <dd>{routes.length}</dd>
        </div>
      </dl>

      {routes.length > 0 ? (
        <div className="routes-list">
          <ul>
            {routes.map((prefix) => (
              <li key={prefix} className="mono">
                {prefix}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {carried.length > 0 ? (
        <table className="forwards">
          <thead>
            <tr>
              <th>Connection</th>
              <th>Flows</th>
              <th title="Flows turned away because no connection carried the address">
                Refused
              </th>
              <th>Open now</th>
              <th>In</th>
              <th>Out</th>
            </tr>
          </thead>
          <tbody>
            {carried.map((row) => (
              <tr key={row.tunnelId ?? 'unrouted'}>
                <td>{nameOf(row)}</td>
                <td>{row.flows}</td>
                <td>{row.refused}</td>
                <td>{row.holding}</td>
                <td>{formatBytes(row.received)}</td>
                <td>{formatBytes(row.sent)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {error ? <Notice tone="error">{error}</Notice> : null}
    </Panel>
  )
}
