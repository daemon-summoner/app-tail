// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import App from '../../App'
import { href } from '../../lib/router'
import { settingsSchema } from '../../api'
import {
  makeFabric,
  makeSettings,
  makeSettingsResponse,
  renderAgent,
  settingsRoutes,
  settle,
  type Routes,
} from '../../test/agent'
import type { Settings } from '../../api'

/** The switches that put this machine on one interface for every network. */
const ON_THE_FABRIC: Partial<Settings> = { 'interface.enabled': true, 'interface.mode': 'fabric' }

/** The field the page is about. Read from the generated registry rather than restated,
 *  so a mode added in Go is offered here without this file naming it. */
const MODE_FIELD = settingsSchema.find((f) => f.key === 'mode.primary')!

/** at opens the paths page over a machine arranged the given way. */
async function at(settings: Partial<Settings> = {}, routes: Routes = {}) {
  window.history.replaceState(null, '', `/${href('connections', 'paths')}`)
  return renderAgent(<App />, {
    ...settingsRoutes(makeSettings(settings)),
    'PUT /api/settings': makeSettingsResponse(settings),
    ...routes,
  })
}

afterEach(() => {
  window.history.replaceState(null, '', '/')
})

describe('choosing how app-tail runs here', () => {
  // Standalone is a mode with a body, not the absence of one. A page that offered two
  // arrangements and a blank would make "changes nothing" look like a broken card.
  it('offers every mode the agent knows, each with what it does to the machine', async () => {
    const view = await at()

    for (const option of MODE_FIELD.options ?? []) {
      expect(view.getByRole('radio', { name: new RegExp(option.label) })).toBeInTheDocument()
      expect(view.getByText(option.help!)).toBeInTheDocument()
    }
  })

  it.each([
    ['a machine touching nothing', {}, 'Standalone'],
    ['a machine running the proxy', { 'proxy.enabled': true }, 'Proxy'],
    [
      'a machine on the interface',
      { 'interface.enabled': true, 'interface.mode': 'tun' },
      'Network interface',
    ],
  ])('shows %s as %s', async (_case, settings, chosen) => {
    const view = await at(settings)

    expect(view.getByRole('radio', { name: new RegExp(chosen) })).toBeChecked()
  })

  // The switches a mode stands for are served with the mode, so choosing one writes the
  // agent's own answer. A page that held its own idea of what a mode meant would leave
  // the picker somewhere other than where it was put.
  it.each(MODE_FIELD.options ?? [])('writes what $label stands for', async (option) => {
    // Started from another mode, because choosing the mode the machine is already in is
    // a no-op and would prove nothing about what the card writes.
    const from = (MODE_FIELD.options ?? []).find((o) => o.value !== option.value)!
    const view = await at(from.applies)

    fireEvent.click(view.getByRole('radio', { name: new RegExp(option.label) }))
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual(option.applies)
  })

  // The modes are a shortcut for the switches, not a replacement: a machine on the
  // interface may still want a proxy for a program that is pointed at one, and a picker
  // that hid the switches it wrote would be one nobody could get out of.
  it('leaves the switches the modes write reachable on their own', async () => {
    const view = await at()

    const written = new Set(
      (MODE_FIELD.options ?? []).flatMap((o) => Object.keys(o.applies ?? {})),
    )
    const switches = settingsSchema.filter(
      (f) => f.moduleSwitch !== undefined && written.has(f.key),
    )

    expect(switches.length).toBeGreaterThan(0)
    for (const field of switches) {
      expect(view.getByLabelText(field.label)).toBeInTheDocument()
    }
  })

  // The one switch a mode writes that is not a module switch is the interface's own mode,
  // which is meaningless on its own: it is the module switch that decides whether the
  // interface is in play at all.
  it('writes the interface mode only alongside the switch that offers it', async () => {
    const view = await at()

    fireEvent.click(view.getByRole('radio', { name: /Network interface/ }))
    await settle()

    const written = view.agent.bodyOf<Record<string, unknown>>('PUT /api/settings')
    expect(written['interface.mode']).toBe('tun')
    expect(written['interface.enabled']).toBe(true)
  })
})

// What the interface is carrying is a different question from which mode was asked for.
// The interface is claimed once, when the connections start, so a machine can sit in this
// mode carrying nothing at all -- and the picker alone would show that as healthy.
describe('what the one interface is carrying', () => {
  const carrying = makeFabric({
    running: true,
    interface: 'utun7',
    mtu: 1280,
    routes: ['10.0.0.0/24', '198.18.0.0/24'],
    carried: [
      { tunnelId: 'tn_office', name: 'Office', flows: 12, refused: 1, sent: 2048, received: 4096, holding: 3 },
    ],
  })

  it('names the interface, the packet size and every range it is sending there', async () => {
    const view = await at(ON_THE_FABRIC, { 'GET /api/fabric': carrying })

    const panel = view.getByRole('region', { name: 'What the interface carries' })
    expect(panel).toHaveTextContent('utun7')
    expect(panel).toHaveTextContent('1280 bytes')
    for (const prefix of carrying.routes ?? []) {
      expect(panel).toHaveTextContent(prefix)
    }
  })

  // Per connection, and the two directions kept apart: a page that reported this machine's
  // uploads as what came back would be read as a network problem on the other side.
  it('reports what each connection carried', async () => {
    const view = await at(ON_THE_FABRIC, { 'GET /api/fabric': carrying })

    const row = view.getByRole('row', { name: /Office/ })
    expect(row).toHaveTextContent('12')
    expect(row).toHaveTextContent('3')
    const cells = [...row.querySelectorAll('td')].map((cell) => cell.textContent)
    expect(cells).toEqual(['Office', '12', '1', '3', '4.0 KB', '2.0 KB'])
  })

  // The state with no symptom: the mode is set, nothing is on the interface, and every
  // address on every connection is unreachable while the counters all read zero.
  it('says the mode is set and nothing is carried, with the reason', async () => {
    const view = await at(ON_THE_FABRIC, {
      'GET /api/fabric': makeFabric({ error: 'the privileged helper is not installed' }),
    })

    const panel = view.getByRole('region', { name: 'What the interface carries' })
    expect(panel).toHaveTextContent('not carrying')
    expect(panel).toHaveTextContent('the privileged helper is not installed')
  })

  // Nothing wrong and nothing carried: the mode was chosen and the connections have not been
  // restarted onto it yet. Left to the counters alone this reads as an idle machine rather
  // than an unreachable one, so the page has to say which it is.
  it('says what to do when the mode is set and nothing has moved onto it yet', async () => {
    const view = await at(ON_THE_FABRIC, { 'GET /api/fabric': makeFabric() })

    const panel = view.getByRole('region', { name: 'What the interface carries' })
    expect(panel).toHaveTextContent('not carrying')
    expect(panel).toHaveTextContent(/Restart the connections/)
  })

  // Under every other arrangement there is no such interface, and a panel describing one
  // would have a reader looking for traffic on something that was never claimed.
  it.each([
    ['a machine touching nothing', {}],
    ['a machine on the tailnet interface', { 'interface.enabled': true, 'interface.mode': 'tun' }],
  ])('is absent for %s', async (_case, settings) => {
    const view = await at(settings, { 'GET /api/fabric': carrying })

    expect(view.queryByRole('region', { name: 'What the interface carries' })).toBeNull()
  })
})
