// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { makeSettings, makeTunnel, renderAgent, settingsRoutes } from '../test/agent'
import { SecurityCard } from './SecurityCard'
import { useSettingsDraft } from './settings/useSettingsDraft'
import type { TunnelView } from '../api'

function Card({ tunnels }: { tunnels: readonly TunnelView[] }) {
  const form = useSettingsDraft()
  return <SecurityCard form={form} tunnels={tunnels} />
}

const securityOn = () => settingsRoutes(makeSettings({ 'security.enabled': true }))

/** A connection holding these settings, set the way the test needs them. A connection that
 *  carries neither key is a kind of network with no node preferences at all. */
function guarded(overrides: Partial<TunnelView>, shields: boolean, posture = false): TunnelView {
  const held = makeTunnel(overrides)
  return {
    ...held,
    settings: {
      ...held.settings,
      'security.shieldsUp': shields,
      'security.postureChecking': posture,
    },
  }
}

// A card with a heading and nothing under it reads as one that failed to load. Whichever
// way the switch is set, it has something to say.
describe('what the card says whichever way the switch is set', () => {
  // The count is the question people open Security with: not what one connection is set
  // to, but whether anything on this machine is reachable from a network it is on.
  it('counts the connections refusing incoming traffic', async () => {
    const { container } = await renderAgent(
      <Card
        tunnels={[
          guarded({}, true),
          guarded({ id: 'tn_lab', name: 'Lab', slug: 'lab' }, false),
        ]}
      />,
      securityOn(),
    )

    expect(container.textContent).toContain('refused on 1 of 2 connections')
  })

  // The setting is the connection's, so the reader has to be able to get to the page that
  // changes it -- this card is a summary and owns no control of its own.
  it('names each connection and links to the page that changes it', async () => {
    const { getByRole, container } = await renderAgent(
      <Card tunnels={[guarded({}, true, true)]} />,
      securityOn(),
    )

    expect(getByRole('link', { name: 'Tailnet' })).toHaveAttribute(
      'href',
      '#/connections/tailscale/tn_primary',
    )
    expect(container.textContent).toContain('Refuses incoming connections')
    expect(container.textContent).toContain('reports its posture')
  })

  // A connection whose kind keeps no node preferences holds neither setting. Counting it
  // would report a connection as accepting traffic nobody ever asked it about.
  it('leaves out a connection that holds neither setting', async () => {
    const { container } = await renderAgent(
      <Card
        tunnels={[
          guarded({}, true),
          makeTunnel({ id: 'tn_office', type: 'wireguard', name: 'Office', slug: 'office' }),
        ]}
      />,
      securityOn(),
    )

    expect(container.textContent).toContain('refused on 1 of 1 connection')
    expect(container.textContent).not.toContain('Office')
  })

  it('says so when nothing here holds these settings at all', async () => {
    const { container } = await renderAgent(
      <Card tunnels={[makeTunnel({ id: 'tn_office', type: 'wireguard', name: 'Office' })]} />,
      securityOn(),
    )

    expect(container.textContent).toContain('No connection here holds these settings')
  })

  it('says what off means rather than showing an empty card', async () => {
    const { container } = await renderAgent(
      <Card tunnels={[guarded({}, true)]} />,
      settingsRoutes(makeSettings()),
    )

    expect(container.querySelector('.module-off')).toBeInTheDocument()
    expect(container.textContent).toContain('accepts incoming tailnet connections')
  })
})
