// SPDX-License-Identifier: MIT

import { fireEvent, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { InspectionHero } from './InspectionHero'
import { rungPatch } from '../../lib/inspectionLevel'
import { href } from '../../lib/router'
import type { IPSView, Settings } from '../../api'
import {
  makeIPS,
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
function Hero({ view, onChanged = () => {} }: { view?: IPSView; onChanged?: () => void }) {
  const form = useSettingsDraft()
  return <InspectionHero form={form} view={view} onChanged={onChanged} />
}

function writable(settings: Partial<Settings> = {}) {
  return {
    ...settingsRoutes(makeSettings(settings)),
    'PUT /api/settings': makeSettingsResponse(settings),
  }
}

/** Inspection on the Deep rung with entries in force: the state the rest departs from. */
function deep(overrides: Partial<IPSView> = {}): IPSView {
  return makeIPS({
    enabled: true,
    names: true,
    destinations: true,
    handshake: true,
    fingerprints: true,
    payload: true,
    anomaly: true,
    rules: 3_200,
    matched: 17,
    refused: 4,
    capability: { available: true, degraded: false, limits: [] },
    ...overrides,
  })
}

const ON = { 'ips.enabled': true } as const

function card(view: AgentView) {
  return view.getByRole('region', { name: 'Traffic inspection' })
}

describe('what the card says inspection is doing', () => {
  it('reads as pending before the first answer lands, with no ladder to climb', async () => {
    const view = await renderAgent(<Hero />, writable())

    expect(card(view).querySelector('.status')).toHaveTextContent('reading')
    expect(within(card(view)).queryByRole('radiogroup')).toBeNull()
  })

  it('reads as off, with the Off rung marked, while the module is off', async () => {
    const view = await renderAgent(<Hero view={makeIPS()} />, writable())

    expect(card(view).querySelector('.status')).toHaveClass('off')
    expect(within(card(view)).getByRole('radio', { name: /Off/ })).toBeChecked()
  })

  it('counts the entries in force and what they matched', async () => {
    const view = await renderAgent(<Hero view={deep()} />, writable(ON))

    expect(card(view).querySelector('.status')).toHaveTextContent('recording 3,200 entries')
    expect(card(view).querySelector('[data-inspection="matched"]')).toHaveTextContent(
      '17 connections have matched, 4 of them refused.',
    )
  })

  it('says refusing rather than recording once the mode prevents', async () => {
    const view = await renderAgent(<Hero view={deep({ mode: 'prevent' })} />, writable(ON))

    expect(card(view).querySelector('.status')).toHaveTextContent('refusing')
  })

  it('counts nothing while no entry is in force', async () => {
    const view = await renderAgent(<Hero view={deep({ rules: 0 })} />, writable(ON))

    expect(card(view).querySelector('[data-inspection="matched"]')).toBeNull()
  })

  it('repeats the reason the agent gives for needing attention', async () => {
    const view = await renderAgent(
      <Hero
        view={deep({
          capability: { available: true, degraded: true, reason: 'No feed has been downloaded yet.', limits: [] },
        })}
      />,
      writable(ON),
    )

    expect(card(view).querySelector('.status')).toHaveTextContent('needs attention')
    expect(card(view)).toHaveTextContent('No feed has been downloaded yet.')
  })
})

describe('the ladder', () => {
  // The ladder is the one control: its Off rung is the module switch, so a second switch
  // beside the name would be two controls for one setting.
  it('is the only control, with no module switch beside the name', async () => {
    const view = await renderAgent(<Hero view={deep()} />, writable(ON))

    expect(within(card(view)).queryByRole('checkbox')).toBeNull()
    expect(within(card(view)).getByRole('radio', { name: /Deep/ })).toBeChecked()
  })

  it('writes the chosen rung through the settings form, then re-reads the view', async () => {
    const onChanged = vi.fn()
    const view = await renderAgent(<Hero view={deep()} onChanged={onChanged} />, writable(ON))

    fireEvent.click(within(card(view)).getByRole('radio', { name: /Basic/ }))
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual(rungPatch('basic'))
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  // The line under Full sends the reader to the inspection page for the certificate, which
  // is the same page the gear opens.
  it('sends the reader to the inspection page for the certificate, where the gear goes', async () => {
    const view = await renderAgent(
      <Hero view={deep({ intercept: { ...makeIPS().intercept, mode: 'except', agreed: true, installed: false } })} />,
      writable(ON),
    )

    expect(view.getByRole('link', { name: 'Install it' })).toHaveAttribute('href', href('inspection'))
    expect(view.getByRole('link', { name: 'Traffic inspection settings' })).toHaveAttribute(
      'href',
      href('inspection'),
    )
  })
})
