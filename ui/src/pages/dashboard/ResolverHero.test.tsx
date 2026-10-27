// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { ResolverHero } from './ResolverHero'
import { href } from '../../lib/router'
import type { DNSSystemView, Settings } from '../../api'
import {
  makeDNSSystem,
  makeSettings,
  makeSettingsResponse,
  pickerChosen,
  pickRow,
  renderAgent,
  settingsRoutes,
  settle,
  type AgentView,
} from '../../test/agent'
import { useSettingsDraft } from '../../components/settings/useSettingsDraft'

/** The card driven by the real settings form, so what these tests exercise is the write
 *  the agent would actually receive rather than a stub standing in for it. */
function Hero({ dns }: { dns?: DNSSystemView }) {
  const form = useSettingsDraft()
  return <ResolverHero form={form} view={dns} />
}

function routes(stored: Partial<Settings> = {}) {
  return {
    ...settingsRoutes(makeSettings(stored)),
    'PUT /api/settings': makeSettingsResponse(stored),
  }
}

const IN_FORCE = { 'systemDns.enabled': true, 'systemDns.profile': 'cloudflare' } as const

// The same picker the resolver card carries, at the top of the dashboard. It writes the
// switch with the profile because the profile is refused while the switch is off.
describe('choosing the resolver', () => {
  it('marks the profile in force and writes the switch with a new one', async () => {
    const view = await renderAgent(
      <Hero dns={makeDNSSystem({ enabled: true, applied: true, profile: 'cloudflare' })} />,
      routes(IN_FORCE),
    )

    expect(pickerChosen(view.container, 'Resolver')).toBe('cloudflare')

    pickRow(view.container, 'Resolver', 'quad9')
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({
      'systemDns.enabled': true,
      'systemDns.profile': 'quad9',
    })
  })

  // System default means "change nothing about this machine", which is the module off.
  // Naming a profile in that write would name a setting the same write makes unavailable.
  it('turns the override off when System default is chosen', async () => {
    const view = await renderAgent(
      <Hero dns={makeDNSSystem({ enabled: true, applied: true, profile: 'cloudflare' })} />,
      routes(IN_FORCE),
    )

    pickRow(view.container, 'Resolver', 'system')
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({ 'systemDns.enabled': false })
  })

  // An agent too old to carry the machine-wide resolver says so rather than showing a
  // picker whose every choice would be refused.
  it('says so when the agent does not carry the machine-wide resolver', async () => {
    const view = await renderAgent(<Hero />, routes())

    expect(view.getByRole('region', { name: 'System resolver' })).toHaveTextContent(
      'does not carry the machine-wide resolver',
    )
    expect(view.container.querySelector('.choice-picker')).toBeNull()
  })

  it('carries the gear to the DNS page', async () => {
    const view = await renderAgent(<Hero />, routes())

    expect(view.getByRole('link', { name: 'System resolver settings' })).toHaveAttribute(
      'href',
      href('dns'),
    )
  })
})

// The head says what is in force rather than what was chosen: the override is installed by
// the machine, and the machine can refuse. A card that echoed the setting would show "in
// force" over a resolver that is not.
describe('what the card says at its head', () => {
  function head(view: AgentView) {
    const chip = view.getByRole('region', { name: 'System resolver' }).querySelector('.status')
    if (!(chip instanceof HTMLElement)) throw new Error('the card has no status chip')
    return chip
  }

  it('reads as pending before the first answer lands', async () => {
    const view = await renderAgent(<Hero />, routes())

    expect(head(view)).toHaveClass('pending')
    expect(head(view)).toHaveTextContent('reading')
  })

  it('reads as unchanged while the override is off', async () => {
    const view = await renderAgent(<Hero dns={makeDNSSystem({ enabled: false, applied: false })} />, routes())

    expect(head(view)).toHaveClass('off')
    expect(head(view)).toHaveTextContent('unchanged')
  })

  it('says the override is not in force when the machine refused it', async () => {
    const view = await renderAgent(
      <Hero dns={makeDNSSystem({ enabled: true, applied: false })} />,
      routes({ 'systemDns.enabled': true }),
    )

    expect(head(view)).toHaveClass('error')
    expect(head(view)).toHaveTextContent('not in force')
  })

  it('names the profile in force by its label, or by its id when it has none', async () => {
    const stored = { 'systemDns.enabled': true, 'systemDns.profile': 'quad9' } as const
    const labelled = await renderAgent(
      <Hero dns={makeDNSSystem({ enabled: true, applied: true, profile: 'quad9', profileLabel: 'Quad9' })} />,
      routes(stored),
    )
    expect(head(labelled)).toHaveClass('running')
    expect(head(labelled)).toHaveTextContent('in force Quad9')
    labelled.unmount()

    const bare = makeDNSSystem({ enabled: true, applied: true, profile: 'quad9' })
    delete bare.profileLabel
    const unlabelled = await renderAgent(<Hero dns={bare} />, routes(stored))
    expect(head(unlabelled)).toHaveTextContent('in force quad9')
  })
})
