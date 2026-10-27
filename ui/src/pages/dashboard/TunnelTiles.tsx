// SPDX-License-Identifier: MIT

// Which networks this machine is on, one tile each.
//
// It answers the first question the dashboard exists to answer, above the strip that says
// how programs here reach them. Like that strip it carries no controls: a connection is
// brought up and configured on its own page, and two places to do it is how the two end
// up disagreeing.

import type { TunnelView } from '../../api'
import { connectionHref, toneOf } from '../../components/connections/tunnel'

export function TunnelTiles({ tunnels }: { tunnels: readonly TunnelView[] }) {
  return (
    <section className="reach" aria-label="Which networks this machine is on">
      <div className="band-head">
        <h2>Which networks this machine is on</h2>
      </div>

      <div className="reach-modes">
        {tunnels.map((tunnel) => (
          <a className="reach-mode" key={tunnel.id} href={connectionHref(tunnel)}>
            <span className="reach-mode-name">{tunnel.name}</span>
            <span className={`status ${toneOf(tunnel.state)}`}>
              <span className="dot" aria-hidden="true" />
              {tunnel.stateLabel}
            </span>
          </a>
        ))}
      </div>
    </section>
  )
}
