// SPDX-License-Identifier: MIT

import { fireEvent, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { BlocklistHero } from './BlocklistHero'
import { href } from '../../lib/router'
import type { DNSBlockView, Settings } from '../../api'
import {
  makeDNSBlock,
  makeSettings,
  makeSettingsResponse,
  renderAgent,
  settingsRoutes,
  settle,
  type AgentView,
} from '../../test/agent'
import { useSettingsDraft } from '../../components/settings/useSettingsDraft'

/** The card driven by the real settings form, which is what puts the write path under
 *  test rather than a stub of it. */
function Hero({ view, onChanged = () => {} }: { view?: DNSBlockView; onChanged?: () => void }) {
  const form = useSettingsDraft()
  return <BlocklistHero form={form} view={view} onChanged={onChanged} />
}

/** Blocking on for the whole machine with one list downloaded: the state everything else
 *  on this card is a departure from. */
function blocking(overrides: Partial<DNSBlockView> = {}): DNSBlockView {
  return makeDNSBlock({
    enabled: true,
    own: true,
    system: true,
    rules: 120_000,
    blocked: 42,
    capability: { available: true, degraded: false, limits: [] },
    ...overrides,
  })
}

function writable(settings: Partial<Settings> = {}) {
  return {
    ...settingsRoutes(makeSettings(settings)),
    'PUT /api/settings': makeSettingsResponse(settings),
    'POST /api/dns/block/preset': blocking({ preset: 'ultimate' }),
  }
}

const ON = { 'dnsBlock.enabled': true, 'dnsBlock.own': true, 'dnsBlock.system': true } as const

function card(view: AgentView) {
  return view.getByRole('region', { name: 'Blocking' })
}

describe('what the card says blocking is doing', () => {
  it('reads as pending before the first answer lands, with no control to flip', async () => {
    const view = await renderAgent(<Hero />, writable())

    expect(card(view).querySelector('.status')).toHaveTextContent('reading')
    expect(within(card(view)).queryByRole('radiogroup')).toBeNull()
  })

  it('says it is off, and offers no level, while the switch is off', async () => {
    const view = await renderAgent(<Hero view={makeDNSBlock()} />, writable())

    expect(card(view).querySelector('.status')).toHaveClass('off')
    expect(card(view)).toHaveTextContent('Off. Every name resolves the way it always did.')
    expect(within(card(view)).queryByRole('radiogroup')).toBeNull()
  })

  it('counts the names it blocks and the lookups it refused', async () => {
    const view = await renderAgent(<Hero view={blocking()} />, writable(ON))

    expect(card(view).querySelector('.status')).toHaveTextContent('blocking 120,000 names')
    expect(card(view)).toHaveTextContent('120,000 names in force')
    expect(card(view)).toHaveTextContent('has refused 42 lookups so far')
  })

  it('counts one refused lookup in the singular', async () => {
    const view = await renderAgent(<Hero view={blocking({ rules: 5, blocked: 1 })} />, writable(ON))

    expect(card(view)).toHaveTextContent('has refused 1 lookup so far')
  })

  // Paused is said instead of the counts: a count under a pause reads as a blocker at
  // work, and nothing is being refused until the pause ends.
  it('says blocking is paused instead of counting, even with rules built', async () => {
    const view = await renderAgent(
      <Hero view={blocking({ pausedUntil: '2026-09-11T23:00:00Z' })} />,
      writable(ON),
    )

    expect(card(view).querySelector('.status')).toHaveTextContent('paused')
    expect(card(view).querySelector('[data-block="paused"]')).toHaveTextContent('Every name resolves normally')
    expect(card(view)).not.toHaveTextContent('has refused')
  })

  // Blocking that never reaches the machine-wide resolver refuses names only for what
  // app-tail resolves itself, which is invisible from every other card.
  it('says when blocking does not reach the machine-wide resolver', async () => {
    const view = await renderAgent(<Hero view={blocking({ system: false })} />, writable({ ...ON, 'dnsBlock.system': false }))

    expect(card(view).querySelector('[data-block="own-only"]')).toHaveTextContent('Only what app-tail resolves for itself')
  })

  it('says nothing about reach while blocking covers the whole machine', async () => {
    const view = await renderAgent(<Hero view={blocking()} />, writable(ON))

    expect(card(view).querySelector('[data-block="own-only"]')).toBeNull()
  })

  it('repeats the reason the agent gives for blocking nothing', async () => {
    const view = await renderAgent(
      <Hero
        view={blocking({
          rules: 0,
          capability: { available: true, degraded: true, reason: 'No list has been downloaded yet.', limits: [] },
        })}
      />,
      writable(ON),
    )

    expect(card(view).querySelector('.status')).toHaveTextContent('blocking nothing')
    expect(card(view)).toHaveTextContent('No list has been downloaded yet.')
  })
})

describe('the controls', () => {
  it('carries the module switch, written the moment it is flipped', async () => {
    const view = await renderAgent(<Hero view={makeDNSBlock()} />, writable())

    fireEvent.click(within(card(view)).getByRole('checkbox', { name: 'Block names on a list' }))
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({ 'dnsBlock.enabled': true })
  })

  it('marks the level in force and applies a chosen one, then re-reads the view', async () => {
    const onChanged = vi.fn()
    const view = await renderAgent(<Hero view={blocking()} onChanged={onChanged} />, writable(ON))

    const levels = within(card(view)).getByRole('radiogroup', { name: 'Level' })
    expect(within(levels).getByRole('radio', { name: /Medium/ })).toBeChecked()

    fireEvent.click(within(levels).getByRole('radio', { name: /Ultimate/ }))
    await settle()

    expect(view.agent.bodyOf('POST /api/dns/block/preset')).toEqual({ preset: 'ultimate' })
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  it('carries the gear to the blocking page', async () => {
    const view = await renderAgent(<Hero view={blocking()} />, writable(ON))

    expect(view.getByRole('link', { name: 'Blocking settings' })).toHaveAttribute(
      'href',
      href('dns', 'blocklist'),
    )
  })
})
