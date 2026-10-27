// SPDX-License-Identifier: MIT

import { fireEvent, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { InspectionLadder } from './InspectionLadder'
import type { IPSView } from '../../api'
import { rungPatch } from '../../lib/inspectionLevel'
import {
  failWith,
  makeIPS,
  makeSettings,
  makeSettingsResponse,
  renderAgent,
  settingsRoutes,
  settle,
  type AgentView,
} from '../../test/agent'
import { useSettingsDraft } from '../settings/useSettingsDraft'

const ADVANCED = '#/inspection'

/** The ladder driven by the real settings form, which is what puts the write path under
 *  test rather than a stub of it. */
function Ladder({ view, onChanged = () => {} }: { view: IPSView; onChanged?: () => void }) {
  const form = useSettingsDraft()
  return <InspectionLadder view={view} form={form} advanced={ADVANCED} onChanged={onChanged} />
}

/** The routes a control that writes needs: the document it reads its state from, and an
 *  answer to the write. */
function writable(settings: Partial<Parameters<typeof makeSettings>[0]> = {}) {
  return {
    ...settingsRoutes(makeSettings(settings)),
    'PUT /api/settings': makeSettingsResponse(settings),
  }
}

/** A machine on one rung, as the agent would serve it after that rung was chosen. */
function on(
  rung: 'off' | 'basic' | 'deep' | 'full',
  over: Partial<Omit<IPSView, 'intercept'>> & { intercept?: Partial<IPSView['intercept']> } = {},
): IPSView {
  const deep = rung === 'deep' || rung === 'full'
  const { intercept, ...rest } = over
  return makeIPS({
    enabled: rung !== 'off',
    names: rung !== 'off',
    destinations: rung !== 'off',
    handshake: deep,
    fingerprints: deep,
    anomaly: deep,
    ...rest,
    intercept: { ...makeIPS().intercept, ...intercept, mode: rung === 'full' ? 'except' : 'off' },
  })
}

function ladder(view: AgentView) {
  return within(view.getByRole('radiogroup', { name: 'Inspection level' }))
}

describe('reading the rung', () => {
  it('marks the rung the machine is on and offers the other three', async () => {
    const view = await renderAgent(<Ladder view={on('deep')} />, writable())

    const rungs = ladder(view)
    expect(rungs.getByRole('radio', { name: /Off/ })).not.toBeChecked()
    expect(rungs.getByRole('radio', { name: /Basic/ })).not.toBeChecked()
    expect(rungs.getByRole('radio', { name: /Deep/ })).toBeChecked()
    expect(rungs.getByRole('radio', { name: /Full/ })).not.toBeChecked()
  })

  it('recommends Deep and nothing else', async () => {
    const view = await renderAgent(<Ladder view={on('off')} />, writable())

    const rungs = ladder(view)
    expect(rungs.getByRole('radio', { name: /Deep/ })).toHaveAccessibleName(/Recommended/)
    expect(rungs.getByRole('radio', { name: /Full/ })).not.toHaveAccessibleName(/Recommended/)
  })

  // A machine set by hand to a combination that is nobody's rung has no rung marked, and
  // says so: a ladder rounding it to the nearest rung would misreport what it inspects.
  it('marks no rung on a machine set to a combination that is none of them', async () => {
    const view = await renderAgent(
      <Ladder view={on('basic', { anomaly: true })} />,
      writable(),
    )

    for (const radio of ladder(view).getAllByRole('radio')) expect(radio).not.toBeChecked()
    expect(view.container.textContent).toContain('none of these levels')
  })
})

describe('choosing a rung', () => {
  it('writes every switch at once, and re-reads the view', async () => {
    const onChanged = vi.fn()
    const view = await renderAgent(<Ladder view={on('basic')} onChanged={onChanged} />, writable())

    fireEvent.click(ladder(view).getByRole('radio', { name: /Deep/ }))
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual(rungPatch('deep'))
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  it('switches only the module off for Off', async () => {
    const view = await renderAgent(<Ladder view={on('deep')} />, writable())

    fireEvent.click(ladder(view).getByRole('radio', { name: /Off/ }))
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({ 'ips.enabled': false })
  })

  // Full asks this machine to trust a certificate app-tail made. The first time, that is a
  // question, and nothing is written until it is answered.
  it('asks before opening connections the first time, and writes nothing until answered', async () => {
    const view = await renderAgent(<Ladder view={on('deep')} />, writable())

    fireEvent.click(ladder(view).getByRole('radio', { name: /Full/ }))
    await settle()

    const dialog = view.getByRole('dialog', { name: 'Open encrypted connections?' })
    expect(dialog).toHaveTextContent(/root certificate/)
    expect(view.agent.countOf('PUT /api/settings')).toBe(0)
    expect(ladder(view).getByRole('radio', { name: /Full/ })).not.toBeChecked()
  })

  it('writes the agreement with the switches once the question is answered', async () => {
    const onChanged = vi.fn()
    const view = await renderAgent(<Ladder view={on('deep')} onChanged={onChanged} />, writable())

    fireEvent.click(ladder(view).getByRole('radio', { name: /Full/ }))
    await settle()
    fireEvent.click(within(view.getByRole('dialog')).getByRole('button', { name: /I understand/ }))
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({
      ...rungPatch('full'),
      'ips.interceptAgreed': true,
    })
    expect(view.queryByRole('dialog')).toBeNull()
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  it('writes nothing when the question is dismissed', async () => {
    const view = await renderAgent(<Ladder view={on('deep')} />, writable())

    fireEvent.click(ladder(view).getByRole('radio', { name: /Full/ }))
    await settle()
    fireEvent.click(within(view.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))

    expect(view.queryByRole('dialog')).toBeNull()
    expect(view.agent.countOf('PUT /api/settings')).toBe(0)
  })

  // Agreed once is agreed: the question is not asked again, and the write carries the
  // switches alone rather than agreeing on the person's behalf a second time.
  it('does not ask again once the agreement is stored', async () => {
    const view = await renderAgent(
      <Ladder view={on('deep', { intercept: { agreed: true } })} />,
      writable(),
    )

    fireEvent.click(ladder(view).getByRole('radio', { name: /Full/ }))
    await settle()

    expect(view.queryByRole('dialog')).toBeNull()
    expect(view.agent.bodyOf('PUT /api/settings')).toEqual(rungPatch('full'))
  })

  // A dialog that closed on a refusal would read as the agreement having been taken. It
  // stays open, with the agent's reason where the person is looking.
  it('keeps the question open with the reason when the agent refuses the agreement', async () => {
    const onChanged = vi.fn()
    const view = await renderAgent(<Ladder view={on('deep')} onChanged={onChanged} />, {
      ...writable(),
      'PUT /api/settings': failWith(400, 'ips.intercept: the exception list is empty'),
    })

    fireEvent.click(ladder(view).getByRole('radio', { name: /Full/ }))
    await settle()
    fireEvent.click(within(view.getByRole('dialog')).getByRole('button', { name: /I understand/ }))
    await settle()

    const dialog = view.getByRole('dialog', { name: 'Open encrypted connections?' })
    expect(dialog).toHaveTextContent('the exception list is empty')
    expect(onChanged).not.toHaveBeenCalled()
  })

  it('shows the reason beneath the rungs when the agent refuses a level', async () => {
    const onChanged = vi.fn()
    const view = await renderAgent(<Ladder view={on('basic')} onChanged={onChanged} />, {
      ...writable(),
      'PUT /api/settings': failWith(409, 'the engine is reloading its feeds'),
    })

    fireEvent.click(ladder(view).getByRole('radio', { name: /Deep/ }))
    await settle()

    const field = view.container.querySelector('.block-levels-field')
    expect(field?.querySelector('.notice.error')).toHaveTextContent('the engine is reloading its feeds')
    expect(onChanged).not.toHaveBeenCalled()
  })
})

describe('what Full reports', () => {
  it.each([
    [
      'connections being opened',
      { agreed: true, installed: true, running: true, opened: 12 },
      'running',
      '12 opened so far',
    ],
    ['no agreement yet', { agreed: false, installed: false, running: false }, 'unagreed', 'until you confirm'],
    [
      'a certificate this machine does not trust',
      { agreed: true, installed: false, running: false },
      'untrusted',
      'does not trust the certificate',
    ],
    ['nothing opened yet', { agreed: true, installed: true, running: false }, 'waiting', 'nothing is being opened yet'],
  ])('reports %s', async (_case, intercept, state, text) => {
    const view = await renderAgent(
      <Ladder view={on('full', { intercept })} />,
      writable(),
    )

    const line = view.container.querySelector(`[data-intercept="${state}"]`)
    expect(line).not.toBeNull()
    expect(line).toHaveTextContent(text)
  })

  // Full is the chosen rung here and a chosen radio takes no click, so the line that says
  // the agreement is missing is where the agreement is given.
  it('offers the question from the line that says it is unanswered', async () => {
    const view = await renderAgent(
      <Ladder view={on('full', { intercept: { agreed: false } })} />,
      writable(),
    )

    fireEvent.click(view.getByRole('button', { name: 'Read and confirm' }))
    await settle()
    fireEvent.click(within(view.getByRole('dialog')).getByRole('button', { name: /I understand/ }))
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({
      ...rungPatch('full'),
      'ips.interceptAgreed': true,
    })
    expect(view.queryByRole('dialog')).toBeNull()
  })

  it('points at the page with the certificate commands', async () => {
    const view = await renderAgent(
      <Ladder
        view={on('full', { intercept: { agreed: true, installed: false } })}
      />,
      writable(),
    )

    expect(view.getByRole('link', { name: 'Install it' })).toHaveAttribute('href', ADVANCED)
  })

  it('says nothing about opening connections below Full', async () => {
    const view = await renderAgent(<Ladder view={on('deep')} />, writable())

    expect(view.container.querySelector('[data-intercept]')).toBeNull()
  })
})
