// SPDX-License-Identifier: MIT

import { fireEvent, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { PathsHero } from './PathsHero'
import { href } from '../../lib/router'
import type { AutoMapView, FabricView, Forward, InterfaceView, ProxyView, Settings } from '../../api'
import {
  failWith,
  makeFabric,
  makeForward,
  makeInterface,
  makeProxy,
  makeSettings,
  makeSettingsResponse,
  netFail,
  renderAgent,
  settingsRoutes,
  settle,
  type AgentView,
} from '../../test/agent'
import { useSettingsDraft } from '../../components/settings/useSettingsDraft'

/** The card driven by the real settings form, so what these tests exercise is the write
 *  the agent would receive rather than a stub standing in for it. */
function Hero({
  forwards = [],
  automap,
  proxy,
  tun = makeInterface(),
  fabric = makeFabric(),
  onChanged = () => {},
}: {
  forwards?: readonly Forward[]
  automap?: AutoMapView
  proxy?: ProxyView
  /** `null` is the view not having arrived, which `undefined` cannot say here: the
   *  default fills it in. */
  tun?: InterfaceView | null
  fabric?: FabricView
  onChanged?: () => void
}) {
  const form = useSettingsDraft()
  return (
    <PathsHero
      form={form}
      forwards={forwards}
      automap={automap}
      proxy={proxy}
      tun={tun ?? undefined}
      fabric={fabric}
      onChanged={onChanged}
    />
  )
}

function writable(settings: Partial<Settings> = {}) {
  return {
    ...settingsRoutes(makeSettings(settings)),
    'PUT /api/settings': makeSettingsResponse(settings),
  }
}

/** One path's tile: its name, its state, and its switch if it has one. */
function tile(view: AgentView, id: string): HTMLElement {
  const node = view.container.querySelector(`[data-path="${id}"]`)
  if (!(node instanceof HTMLElement)) throw new Error(`no path is called ${id}`)
  return node
}

describe('what the card names', () => {
  it('names all three paths, each linked to its own page', async () => {
    const view = await renderAgent(<Hero />, writable())

    const region = view.getByRole('region', { name: 'How this machine reaches the tailnet' })
    expect(within(region).getByRole('link', { name: 'Port forwards' })).toHaveAttribute(
      'href',
      href('connections', 'forwards'),
    )
    expect(within(region).getByRole('link', { name: 'Proxies' })).toHaveAttribute(
      'href',
      href('connections', 'proxies'),
    )
    expect(within(region).getByRole('link', { name: 'Network interface' })).toHaveAttribute(
      'href',
      href('connections', 'paths'),
    )
  })

  it('carries the gear to the paths page', async () => {
    const view = await renderAgent(<Hero />, writable())

    expect(
      view.getByRole('link', { name: 'How this machine reaches the tailnet settings' }),
    ).toHaveAttribute('href', href('connections', 'paths'))
  })

  // The state beside each name is the agent's answer, not the switch's: a proxy that is on
  // and could not bind its port is the failure a reader needs, and the switch alone
  // reports that as working.
  it('reports what each path is doing from the views, not from its switch', async () => {
    const view = await renderAgent(
      <Hero
        forwards={[makeForward(), makeForward({ id: 'fwd-web', name: 'web', state: 'error' })]}
        proxy={makeProxy({
          enabled: true,
          capability: { available: false, degraded: false, reason: 'the port is already in use' },
        })}
        tun={makeInterface({ enabled: true, configured: 'tun', inForce: true, interface: 'utun9' })}
      />,
      writable({ 'proxy.enabled': true, 'interface.enabled': true, 'interface.mode': 'tun' }),
    )

    expect(tile(view, 'forwards').querySelector('.status')).toHaveTextContent('1 of 2 running')
    expect(tile(view, 'proxy').querySelector('.status')).toHaveClass('error')
    expect(tile(view, 'proxy').querySelector('.status')).toHaveTextContent('not listening')
    expect(tile(view, 'interface').querySelector('.status')).toHaveTextContent('on utun9')
  })
})

describe('the switches', () => {
  // The forwards run whenever one is configured; there is nothing to switch.
  it('give the forwards no switch and say they are always on', async () => {
    const view = await renderAgent(<Hero />, writable())

    expect(within(tile(view, 'forwards')).queryByRole('checkbox')).toBeNull()
    expect(tile(view, 'forwards')).toHaveTextContent('always on')
  })

  it('show the stored setting for the proxy and the interface', async () => {
    const view = await renderAgent(
      <Hero />,
      writable({ 'proxy.enabled': true, 'interface.enabled': false }),
    )

    expect(within(tile(view, 'proxy')).getByRole('checkbox', { name: 'Proxies' })).toBeChecked()
    expect(
      within(tile(view, 'interface')).getByRole('checkbox', { name: 'Network interface' }),
    ).not.toBeChecked()
  })

  it('write the proxy switch the moment it is flipped, and re-read the views', async () => {
    const onChanged = vi.fn()
    const view = await renderAgent(<Hero onChanged={onChanged} />, writable())

    fireEvent.click(within(tile(view, 'proxy')).getByRole('checkbox'))
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({ 'proxy.enabled': true })
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  // A refusal is the form's notice already; re-reading the views after one would confirm
  // that nothing changed.
  it('do not re-read the views when the agent refuses the flip', async () => {
    const onChanged = vi.fn()
    const view = await renderAgent(<Hero onChanged={onChanged} />, {
      ...writable(),
      'PUT /api/settings': failWith(409, 'the proxy address is taken'),
    })

    fireEvent.click(within(tile(view, 'proxy')).getByRole('checkbox'))
    await settle()

    expect(onChanged).not.toHaveBeenCalled()
    expect(within(tile(view, 'proxy')).getByRole('checkbox')).not.toBeChecked()
  })

  // A switch shows the stored setting, and before the settings have loaded there is none:
  // a switch drawn off beside a status saying "listening" would be a position nobody set.
  it('show no switch until the settings have loaded', async () => {
    const view = await renderAgent(<Hero proxy={makeProxy({ enabled: true })} />, {
      ...writable(),
      'GET /api/settings/schema': netFail(),
    })

    expect(within(tile(view, 'proxy')).queryByRole('checkbox')).toBeNull()
    expect(tile(view, 'proxy').querySelector('.skeleton')).not.toBeNull()
    expect(tile(view, 'proxy')).toHaveTextContent('listening')
  })

  // The interface's on-patch names the mode the view reports, and the view comes on its own
  // request, after the settings as often as not. A switch offered before it arrived would
  // write `tun` over a machine arranged for one interface.
  it('show no interface switch until its view has arrived, even with the settings loaded', async () => {
    const view = await renderAgent(<Hero tun={null} />, writable())

    expect(within(tile(view, 'proxy')).getByRole('checkbox')).toBeInTheDocument()
    expect(within(tile(view, 'interface')).queryByRole('checkbox')).toBeNull()
    expect(tile(view, 'interface').querySelector('.skeleton')).not.toBeNull()
    expect(tile(view, 'interface')).toHaveTextContent('reading')
  })

  // The module switch alone puts the node on no interface at all, so turning the interface
  // on names the mode with it.
  it('name the interface mode when the interface is switched on', async () => {
    const view = await renderAgent(<Hero />, writable())

    fireEvent.click(within(tile(view, 'interface')).getByRole('checkbox'))
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({
      'interface.enabled': true,
      'interface.mode': 'tun',
    })
  })

  it('switch the interface off without touching its mode', async () => {
    const view = await renderAgent(
      <Hero tun={makeInterface({ enabled: true, configured: 'tun' })} />,
      writable({ 'interface.enabled': true, 'interface.mode': 'tun' }),
    )

    fireEvent.click(within(tile(view, 'interface')).getByRole('checkbox'))
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({ 'interface.enabled': false })
  })

  // The interface's switch reconnects the node, which interrupts every forward. Said on
  // the tile, before the flip, rather than in a notice after it.
  it('warn that the interface switch reconnects the node, and the proxy switch does not', async () => {
    const view = await renderAgent(<Hero />, writable())

    expect(tile(view, 'interface')).toHaveTextContent('reconnects the node')
    expect(tile(view, 'proxy')).not.toHaveTextContent('reconnects the node')
  })
})
