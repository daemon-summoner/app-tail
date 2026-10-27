// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { settingsSchema } from '../api'
import { emptySettingsForm, makeTunnel, openInfo, renderAgent } from '../test/agent'
import { ConnectionNamesCard } from './ConnectionNamesCard'

/** The card as the page renders it, with no settings served: the rows are what a reader
 *  came for, and they do not depend on the form. */
function card(tunnels: readonly Parameters<typeof ConnectionNamesCard>[0]['tunnels'][number][]) {
  return <ConnectionNamesCard tunnels={tunnels} form={emptySettingsForm()} />
}

/** A form serving the one global field this card owns, the way the agent serves it. */
function formWithZone() {
  const available = settingsSchema
    .filter((f) => f.key === 'dns.zone')
    .map((f) => ({ ...f, available: true, availableReason: '' }))
  return emptySettingsForm({
    available,
    bind: () => ({
      value: '',
      example: 'internal',
      onChange: () => {},
      stored: false,
      error: undefined,
      disabled: false,
    }),
  })
}

const office = makeTunnel({
  id: 'tn_office',
  type: 'wireguard',
  typeLabel: 'WireGuard',
  name: 'Office',
  slug: 'office',
  settings: { 'dns.suffix': 'office.internal' },
})

const lab = makeTunnel({
  id: 'tn_lab',
  type: 'wireguard',
  typeLabel: 'WireGuard',
  name: 'Lab',
  slug: 'lab',
  enabled: false,
  settings: { 'dns.suffix': 'lab.internal' },
})

/** The rows as a reader sees them. */
function rows(container: HTMLElement): string[] {
  return [...container.querySelectorAll('.dns-list li')].map((li) => li.textContent ?? '')
}

// Two networks with the same addresses reachable at once is the whole reason the suffix
// exists, and a user only gets it if they can see which name belongs to which connection.
describe('which connection answers for which names', () => {
  it('names every connection beside the suffix its hosts answer under', async () => {
    const { container } = await renderAgent(card([office, lab]))

    expect(rows(container)).toEqual([
      expect.stringContaining('*.office.internal'),
      expect.stringContaining('*.lab.internal'),
    ])
    expect(rows(container)[0]).toContain('Office')
    expect(rows(container)[1]).toContain('Lab')
  })

  it('links each row to the connection that holds the name', async () => {
    const { container } = await renderAgent(card([office]))

    const link = container.querySelector<HTMLAnchorElement>('.dns-list a')
    expect(link?.getAttribute('href')).toBe('#/connections/wireguard/tn_office')
  })

  // A connection that is off keeps its names: the suffix is what says which network a name
  // is on, and a name that quietly meant a different network while one connection was down
  // is the failure the whole convention exists to prevent.
  it('keeps a switched-off connection listed, and says it is off', async () => {
    const { container } = await renderAgent(card([lab]))

    expect(rows(container)[0]).toContain('*.lab.internal')
    expect(rows(container)[0]).toContain('switched off')
  })

  // The card would otherwise read as "this machine resolves these", which is the thing a
  // user files as a bug the first time a browser outside app-tail cannot reach one.
  it('says these names resolve through app-tail and not through this machine', async () => {
    const { container } = await renderAgent(card([office]))

    expect(container.textContent).toContain('through app-tail')
    expect(container.textContent).toContain('no such name')
  })

  it('states where the suffix comes from', async () => {
    const { container } = await renderAgent(card([office]))

    expect(openInfo(container, 'Names on your connections')).toHaveTextContent('short name')
  })

  // The zone is the one part of a name that is not the connection's own, and this is the
  // only card that shows what it produces. Served but drawn nowhere, it would be a setting
  // reachable from the command line and invisible here.
  it('carries the zone every suffix hangs under', async () => {
    const { container } = await renderAgent(
      <ConnectionNamesCard tunnels={[office]} form={formWithZone()} />,
    )

    expect(container.textContent).toContain('Name every connection under')
  })

  it('shows nothing at all when no connection answers for a name', async () => {
    const { container } = await renderAgent(card([makeTunnel({ settings: { 'dns.suffix': '' } })]))

    expect(container.querySelector('.panel')).toBeNull()
  })
})
