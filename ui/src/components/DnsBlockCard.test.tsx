// SPDX-License-Identifier: MIT

import { fireEvent, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import {
  failWith,
  makeDNSBlock,
  makeSettings,
  makeSettingsResponse,
  openInfo,
  renderAgent,
  settingsRoutes,
  settle,
} from '../test/agent'
import { DnsBlockCard } from './DnsBlockCard'
import { useSettingsDraft } from './settings/useSettingsDraft'
import type { DNSBlockView } from '../api'

/** The card driven by the real settings form, which is what puts the write path under
 *  test rather than a stub of it. */
function Card({ view, onChanged = () => {} }: { view: DNSBlockView; onChanged?: () => void }) {
  const form = useSettingsDraft()
  return <DnsBlockCard view={view} form={form} onChanged={onChanged} />
}

/** Blocking on, both switches on, one list downloaded: the state everything else on this
 *  card is a departure from. */
function blocking(overrides: Partial<DNSBlockView> = {}): DNSBlockView {
  return makeDNSBlock({
    enabled: true,
    own: true,
    system: true,
    rules: 152_403,
    compiledAt: '2026-08-31T09:00:00Z',
    blocked: 91,
    capability: { available: true, degraded: false, limits: [] },
    lists: [
      {
        id: 'hagezi-pro',
        provider: 'Hagezi',
        name: 'Hagezi Pro',
        url: 'https://example.test/pro.txt',
        format: 'abp',
        builtIn: true,
        enabled: true,
        rules: 152_403,
        skipped: 12,
        updatedAt: '2026-08-31T09:00:00Z',
      },
      {
        id: 'oisd-big',
        provider: 'OISD',
        name: 'OISD Big',
        url: 'https://example.test/oisd.txt',
        format: 'abp',
        builtIn: true,
        enabled: false,
        rules: 0,
        skipped: 0,
      },
    ],
    ...overrides,
  })
}

/** The routes a card that writes needs: the schema and document it reads its controls
 *  from, and the answer to the write it makes. */
function writable(settings: Partial<Parameters<typeof makeSettings>[0]> = {}) {
  const on = {
    'dnsBlock.enabled': true,
    'dnsBlock.own': true,
    'dnsBlock.system': true,
    ...settings,
  }
  return {
    ...settingsRoutes(makeSettings(on)),
    'PUT /api/settings': makeSettingsResponse(on),
    // The three writes that are not settings. They answer with the view, which is what
    // the card's own poll would have re-read.
    'POST /api/dns/block/refresh': blocking(),
    'POST /api/dns/block/pause': blocking({ pausedUntil: '2099-01-01T00:00:00Z' }),
    'POST /api/dns/block/resume': blocking(),
    'POST /api/dns/block/preset': blocking({ preset: 'ultimate' }),
  }
}

// "Blocking is switched on" and "names are actually being refused" are different facts,
// and every gap between them has its own fix. A card that collapsed them would report a
// machine resolving every ad domain as working.
describe('what the card says blocking is doing', () => {
  it.each([
    ['the switch off', makeDNSBlock(), 'off'],
    ['names in force', blocking(), 'blocking'],
    [
      'neither switch on',
      blocking({
        own: false,
        system: false,
        capability: {
          available: true,
          degraded: true,
          reason: 'Blocking is on but neither switch under it is, so nothing is filtered.',
        },
      }),
      'blocking nothing',
    ],
    [
      'paused',
      blocking({
        pausedUntil: '2099-01-01T00:00:00Z',
        capability: { available: true, degraded: true, reason: 'Blocking is paused.' },
      }),
      'paused',
    ],
  ])('shows %s as %s', async (_case, view, label) => {
    const { container } = await renderAgent(<Card view={view} />, writable())

    expect(container.querySelector('.panel-head .status')).toHaveTextContent(label)
  })

  it('says nothing is downloaded rather than showing a count of zero', async () => {
    const { container } = await renderAgent(
      <Card
        view={blocking({
          rules: 0,
          blocked: 0,
          lists: (blocking().lists ?? []).map((list) => ({ ...list, enabled: false })),
        })}
      />,
      writable(),
    )

    expect(container.textContent).toContain('No list has been downloaded yet')
  })

  // Switching blocking on starts the download, so the same count of zero means something
  // else: a reader told only that nothing is downloaded goes looking for the button that
  // starts what is already running.
  it('says the download is under way when blocking is on with nothing compiled yet', async () => {
    const { container } = await renderAgent(
      <Card view={blocking({ rules: 0, blocked: 0 })} />,
      writable(),
    )

    expect(container.textContent).toContain('Downloading the lists')
    expect(container.textContent).not.toContain('No list has been downloaded yet')
  })

  it('reports what the lists hold and what the machine refused', async () => {
    const { container } = await renderAgent(<Card view={blocking()} />, writable())

    expect(container.textContent).toContain('152,403 names in force')
    expect(container.textContent).toContain('refused 91 lookups')
  })
})

// A list that fetched a captive-portal page, or one whose rules a resolver mostly cannot
// express, is still switched on and contributing almost nothing. Both are invisible unless
// the row says so.
describe('what each list contributed', () => {
  it('shows the rules kept and the rules a resolver could not express', async () => {
    const { container } = await renderAgent(<Card view={blocking()} />, writable())

    expect(container.textContent).toContain('152,403 names, 12 skipped')
  })

  it('names the failure on a list that could not be downloaded', async () => {
    const view = blocking()
    const failed = {
      ...view,
      lists: [{ ...(view.lists ?? [])[0]!, error: 'connection refused' }],
    }
    const { container } = await renderAgent(<Card view={failed} />, writable())

    expect(container.textContent).toContain('connection refused')
  })

  it('writes the whole set of enabled lists when one row is switched on', async () => {
    const { agent, container, getByLabelText } = await renderAgent(
      <Card view={blocking()} />,
      writable(),
    )

    const switches = within(container.querySelector('.picker') as HTMLElement)
    fireEvent.click(switches.getByRole('button', { name: /OISD/ }))
    fireEvent.click(getByLabelText('Use OISD Big'))
    await settle()

    expect(agent.bodyOf('PUT /api/settings')).toEqual({
      'dnsBlock.lists': ['hagezi-pro', 'oisd-big'],
    })
  })

  // Forty shipped lists are a wall of rows unless the tiers of one author read as one
  // choice, so the picker is grouped under the name of whoever publishes them.
  it('puts each list under the name of who publishes it', async () => {
    const view = blocking()
    const withMine = {
      ...view,
      lists: [
        ...(view.lists ?? []),
        {
          id: 'work',
          provider: 'Your lists',
          name: 'Work list',
          url: 'https://lists.example.test/work.txt',
          builtIn: false,
          enabled: false,
          rules: 0,
          skipped: 0,
        },
      ],
    }
    const { container } = await renderAgent(<Card view={withMine} />, writable())

    // The first picker is the switches; the catalog editor below repeats the same groups.
    const switches = within(container.querySelector('.picker') as HTMLElement)
    const hagezi = switches.getByRole('group', { name: 'Hagezi' })
    expect(hagezi).toHaveTextContent('Hagezi Pro')
    expect(hagezi).not.toHaveTextContent('OISD Big')

    fireEvent.click(switches.getByRole('button', { name: /OISD/ }))
    fireEvent.click(switches.getByRole('button', { name: /Your lists/ }))
    expect(switches.getByRole('group', { name: 'OISD' })).toHaveTextContent('OISD Big')
    expect(switches.getByRole('group', { name: 'Your lists' })).toHaveTextContent('Work list')
  })

  // A catalog this long only fits on the card because a group nobody is using stays shut.
  // The group holding a list already on is the exception: it is the state somebody came to
  // read, so closing it would hide the answer to "what is blocking right now".
  it('opens the groups holding an enabled list and leaves the rest shut', async () => {
    const { container } = await renderAgent(<Card view={blocking()} />, writable())
    const switches = within(container.querySelector('.picker') as HTMLElement)

    expect(switches.getByRole('button', { name: /Hagezi/ })).toHaveAttribute(
      'aria-expanded',
      'true',
    )
    const oisd = switches.getByRole('button', { name: /OISD/ })
    expect(oisd).toHaveAttribute('aria-expanded', 'false')
    expect(switches.queryByLabelText('Use OISD Big')).toBeNull()

    fireEvent.click(oisd)

    expect(oisd).toHaveAttribute('aria-expanded', 'true')
    expect(switches.getByLabelText('Use OISD Big')).toBeTruthy()
  })

  it('drops a row from the set when it is switched off', async () => {
    const { agent, getByLabelText } = await renderAgent(<Card view={blocking()} />, writable())

    fireEvent.click(getByLabelText('Use Hagezi Pro'))
    await settle()

    expect(agent.bodyOf('PUT /api/settings')).toEqual({ 'dnsBlock.lists': [] })
  })

  // A refused write changed nothing, so re-reading the view would only confirm that; the
  // reason belongs on the card, beside the row that asked for it.
  it('shows why a row could not be switched, and does not re-read the view', async () => {
    let changed = 0
    const { getByLabelText, container } = await renderAgent(
      <Card view={blocking()} onChanged={() => (changed += 1)} />,
      { ...writable(), 'PUT /api/settings': failWith(400, 'that list is not one the agent carries') },
    )

    fireEvent.click(getByLabelText('Use Hagezi Pro'))
    await settle()

    expect(changed).toBe(0)
    expect(container.textContent).toContain('that list is not one the agent carries')
  })
})

// A pause is the control somebody reaches for with a broken site in front of them, so it
// has to apply at once and say when it ends. It is held in memory, so nothing but this
// card reports it.
describe('pausing and downloading', () => {
  it('pauses for the length on the button', async () => {
    const { agent, getByLabelText } = await renderAgent(<Card view={blocking()} />, writable())

    fireEvent.click(getByLabelText('Pause blocking for 15 minutes'))
    await settle()

    expect(agent.bodyOf('POST /api/dns/block/pause')).toEqual({ minutes: 15 })
  })

  it('offers a way back while paused, and says when it ends by itself', async () => {
    const paused = blocking({
      pausedUntil: '2099-01-01T00:00:00Z',
      capability: { available: true, degraded: true, reason: 'Blocking is paused.' },
    })
    const { agent, getByText, container } = await renderAgent(<Card view={paused} />, writable())

    expect(container.textContent).toContain('comes back by itself')

    fireEvent.click(getByText('Resume blocking'))
    await settle()

    expect(agent.countOf('POST /api/dns/block/resume')).toBe(1)
  })

  it('downloads on request without waiting for the schedule', async () => {
    const { agent, getByText } = await renderAgent(<Card view={blocking()} />, writable())

    fireEvent.click(getByText('Download now'))
    await settle()

    expect(agent.countOf('POST /api/dns/block/refresh')).toBe(1)
  })

  it('shows what the agent refused rather than dropping it', async () => {
    const { getByText, container } = await renderAgent(<Card view={blocking()} />, {
      ...writable(),
      'POST /api/dns/block/refresh': failWith(503, 'no network to download over'),
    })

    fireEvent.click(getByText('Download now'))
    await settle()

    expect(container.textContent).toContain('no network to download over')
  })
})

// Somebody arrives at this card with a broken site in front of them, and the question is
// whether blocking is what broke it. Only the agent can answer: it holds the lists, and it
// knows the answers that are not about a list at all.
describe('asking whether one name is blocked', () => {
  const check = (answer: unknown) => ({
    ...writable(),
    'GET /api/dns/block/check': answer,
  })

  it('asks about the name typed in and names the list holding it', async () => {
    const { agent, getByLabelText, getByText, container } = await renderAgent(
      <Card view={blocking()} />,
      check({
        name: 'ads.doubleclick.net',
        blocked: true,
        list: 'Hagezi Pro',
        reason: 'on Hagezi Pro',
      }),
    )

    fireEvent.change(getByLabelText('Is a name blocked?'), {
      target: { value: 'ads.doubleclick.net' },
    })
    fireEvent.click(getByText('Check'))
    await settle()

    expect(agent.urlOf('GET /api/dns/block/check')).toContain('name=ads.doubleclick.net')
    expect(container.textContent).toContain('ads.doubleclick.net is blocked: on Hagezi Pro')
  })

  it('says a name is not blocked rather than only that no list has it', async () => {
    const { getByLabelText, getByText, container } = await renderAgent(
      <Card view={blocking()} />,
      check({
        name: 'example.com',
        blocked: false,
        reason: 'not on any of the 152,403 names the lists you turned on hold',
      }),
    )

    fireEvent.change(getByLabelText('Is a name blocked?'), { target: { value: 'example.com' } })
    fireEvent.click(getByText('Check'))
    await settle()

    expect(container.textContent).toContain('example.com is not blocked: not on any of the')
  })

  it('shows what the agent refused rather than an answer it never gave', async () => {
    const { getByLabelText, getByText, container } = await renderAgent(
      <Card view={blocking()} />,
      check(failWith(503, 'the agent is still starting')),
    )

    fireEvent.change(getByLabelText('Is a name blocked?'), { target: { value: 'example.com' } })
    fireEvent.click(getByText('Check'))
    await settle()

    expect(container.textContent).toContain('the agent is still starting')
    expect(container.textContent).not.toContain('example.com is')
  })
})

// The one claim this card must never let slip: what blocking does not reach. A forward
// carries an address rather than a name and is not filtered, and every list is a file on
// this machine rather than a service being asked per query.
describe('what it never oversells', () => {
  const LIMITS = [
    'Blocking happens where names are resolved, so a port forward -- which carries an ' +
      'address rather than a name -- is not filtered by it.',
    'Lists are downloaded and kept on this machine. A list that cannot be downloaded ' +
      'keeps blocking from the copy already here.',
  ]

  it.each([
    ['off', makeDNSBlock({ capability: { available: true, degraded: false, limits: LIMITS } })],
    ['blocking', blocking({ capability: { available: true, degraded: false, limits: LIMITS } })],
  ])('states them while %s', async (_case, view) => {
    const { container } = await renderAgent(<Card view={view} />, writable())

    const info = openInfo(container, 'Blocking')
    for (const limit of LIMITS) expect(info.textContent).toContain(limit)
  })
})

// Picking a level is the whole decision for most people, so the ladder has to say what each
// rung blocks, mark the one in force, and admit when the lists switched on are nobody's rung
// -- a picker that showed one selected anyway would misreport what the machine is doing.
describe('choosing a level', () => {
  it('offers every rung with what it blocks, and marks the one in force', async () => {
    const { getByRole, container } = await renderAgent(<Card view={blocking()} />, writable())

    const ladder = within(getByRole('radiogroup', { name: 'Level' }))
    expect(ladder.getByRole('radio', { name: /Minimum/ })).not.toBeChecked()
    expect(ladder.getByRole('radio', { name: /Medium/ })).toBeChecked()
    expect(ladder.getByRole('radio', { name: /Ultimate/ })).not.toBeChecked()
    expect(container.textContent).toContain('Everything the catalog can block without breaking a site.')
  })

  // Six rungs is five too many to read before choosing. The badge is what makes it one
  // choice with a default, so a rung marked recommended by the agent has to wear it -- and
  // the rungs beside it must not, or the mark says nothing.
  it('marks the recommended rung and only that one', async () => {
    const { getByRole } = await renderAgent(<Card view={blocking()} />, writable())

    const ladder = within(getByRole('radiogroup', { name: 'Level' }))
    expect(ladder.getByRole('radio', { name: /Medium/ })).toHaveAccessibleName(/Recommended/)
    expect(ladder.getByRole('radio', { name: /Minimum/ })).not.toHaveAccessibleName(/Recommended/)
    expect(ladder.getByRole('radio', { name: /Ultimate/ })).not.toHaveAccessibleName(/Recommended/)
  })

  it('switches to the rung chosen and re-reads what that produced', async () => {
    let reread = 0
    const { agent, getByRole } = await renderAgent(
      <Card view={blocking()} onChanged={() => (reread += 1)} />,
      writable(),
    )

    fireEvent.click(within(getByRole('radiogroup', { name: 'Level' })).getByRole('radio', {
      name: /Ultimate/,
    }))
    await settle()

    expect(agent.bodyOf('POST /api/dns/block/preset')).toEqual({ preset: 'ultimate' })
    expect(reread).toBe(1)
  })

  it('says a set of lists that is no level is exactly that, with nothing chosen', async () => {
    // A set of lists the agent could not name a level for arrives with the field absent.
    const noLevel = blocking()
    delete noLevel.preset
    const { getByRole, container } = await renderAgent(<Card view={noLevel} />, writable())

    const ladder = within(getByRole('radiogroup', { name: 'Level' }))
    for (const name of [/Minimum/, /Medium/, /Ultimate/]) {
      expect(ladder.getByRole('radio', { name })).not.toBeChecked()
    }
    expect(container.textContent).toContain('are not one of these levels')
  })

  it('shows what the agent refused rather than a level it never switched to', async () => {
    const { getByRole, container } = await renderAgent(<Card view={blocking()} />, {
      ...writable(),
      'POST /api/dns/block/preset': failWith(400, 'that level is not one the agent carries'),
    })

    fireEvent.click(within(getByRole('radiogroup', { name: 'Level' })).getByRole('radio', {
      name: /Ultimate/,
    }))
    await settle()

    expect(container.textContent).toContain('that level is not one the agent carries')
  })
})

// Forty-five rows across sixteen groups make "what is actually on right now" a question
// nobody can answer by scrolling. The filter is the answer to it, and it has to be a state
// somebody can leave again.
describe('seeing only the lists that are on', () => {
  const filter = (view: ReturnType<typeof blocking>) =>
    renderAgent(<Card view={view} />, writable())

  it('shows only the lists that are on, with their groups open', async () => {
    const { container, getByRole } = await filter(blocking())

    fireEvent.click(getByRole('button', { name: /Show only what's on/ }))

    const switches = within(container.querySelector('.picker') as HTMLElement)
    expect(switches.getByRole('group', { name: 'Hagezi' })).toHaveTextContent('Hagezi Pro')
    expect(switches.queryByRole('group', { name: 'OISD' })).toBeNull()
    expect(switches.queryByLabelText('Use OISD Big')).toBeNull()
  })

  it('opens a group the reader had shut, rather than showing an empty one', async () => {
    const view = blocking()
    const bothOn = {
      ...view,
      lists: (view.lists ?? []).map((list) => ({ ...list, enabled: true })),
    }
    const { container, getByRole } = await filter(bothOn)

    // OISD starts shut in the normal view only because nothing in it was on; here it is.
    fireEvent.click(getByRole('button', { name: /Show only what's on/ }))

    const switches = within(container.querySelector('.picker') as HTMLElement)
    expect(switches.getByRole('group', { name: 'OISD' })).toHaveTextContent('OISD Big')
  })

  it('goes back to the whole catalog on a second press', async () => {
    const { container, getByRole } = await filter(blocking())

    fireEvent.click(getByRole('button', { name: /Show only what's on/ }))
    fireEvent.click(getByRole('button', { name: 'Show every list' }))

    const switches = within(container.querySelector('.picker') as HTMLElement)
    expect(switches.getByRole('group', { name: 'OISD' })).toBeInTheDocument()
  })

  it('stays leavable when the last list goes off underneath it', async () => {
    const view = blocking()
    const { container, getByRole, rerender } = await filter(view)

    fireEvent.click(getByRole('button', { name: /Show only what's on/ }))
    // What the next poll brings after the last list is switched off.
    rerender(
      <Card
        view={{ ...view, lists: (view.lists ?? []).map((l) => ({ ...l, enabled: false })) }}
      />,
    )

    expect(container.textContent).toContain('No list is switched on')
    expect(getByRole('button', { name: 'Show every list' })).toBeEnabled()
  })
})
