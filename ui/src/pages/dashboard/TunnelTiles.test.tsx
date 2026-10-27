// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { TunnelTiles } from './TunnelTiles'
import { makeTunnel, renderScoped } from '../../test/agent'

describe('which networks this machine is on', () => {
  it('shows a tile for every connection, each leading to its own page', () => {
    const view = renderScoped(
      <TunnelTiles
        tunnels={[
          makeTunnel(),
          makeTunnel({ id: 'tn_office', type: 'wireguard', name: 'Office', slug: 'office' }),
        ]}
      />,
    )

    expect(view.getByRole('link', { name: /Tailnet/ })).toHaveAttribute(
      'href',
      '#/connections/tailscale/tn_primary',
    )
    expect(view.getByRole('link', { name: /Office/ })).toHaveAttribute(
      'href',
      '#/connections/wireguard/tn_office',
    )
  })

  // A tile is orientation, not a control. A switch that also lived here would be a second
  // place to flip one thing, which is how the two end up disagreeing.
  it('offers nothing to press', () => {
    const view = renderScoped(<TunnelTiles tunnels={[makeTunnel()]} />)

    expect(view.queryAllByRole('button')).toHaveLength(0)
    expect(view.queryAllByRole('switch')).toHaveLength(0)
  })

  // The colour is decoration and the word is the state, so a tile that carried only the
  // dot would say nothing at all to a reader who cannot see it.
  it('names each connection state in words', () => {
    const view = renderScoped(
      <TunnelTiles
        tunnels={[makeTunnel({ state: 'needs-login', stateLabel: 'Waiting for sign-in' })]}
      />,
    )

    const status = view.container.querySelector('.status')
    expect(status).toHaveClass('status', 'pending')
    expect(status).toHaveTextContent('Waiting for sign-in')
  })
})
