// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { RoutingCard } from './RoutingCard'
import { failWith, makeRouting, renderAgent, settle, type Routes } from '../../test/agent'
import type { RoutingRule, RoutingView } from '../../api'

const OFFICE = 'tn_office'
const LAB = 'tn_lab'

const TUNNELS = [
  { id: OFFICE, name: 'Office', running: true },
  { id: LAB, name: 'Lab', running: true },
]

/** One stored rule and the sentence the agent serves for it, which is what every other
 *  surface shows for the same rule. */
function withRules(rules: readonly RoutingRule[], describe: readonly string[]): RoutingView {
  return makeRouting({ rules: [...rules], describe: [...describe], tunnels: TUNNELS })
}

const CORP: RoutingRule = { id: 'rt_1', action: 'via', tunnel: OFFICE, host: '*.corp.example' }
const STREAM: RoutingRule = { id: 'rt_2', action: 'direct', host: '*.stream.example' }

function mount(view: RoutingView | undefined, routes: Routes = {}, error?: string) {
  return renderAgent(
    <RoutingCard
      view={view}
      {...(error === undefined ? {} : { error })}
      onSaved={() => undefined}
    />,
    routes,
  )
}

describe('the per-destination rules', () => {
  // Order is the meaning -- the first rule that fits decides -- so the number on each row is
  // the rule's precedence rather than decoration, and it has to follow the served order.
  it('draws a numbered row per rule, in the order they are matched', async () => {
    const view = await mount(
      withRules([CORP, STREAM], ['rule 1 sends *.corp.example through Office', 'rule 2 sends *.stream.example out directly']),
    )

    expect(view.getByLabelText('Rule 1: destination')).toHaveValue('*.corp.example')
    expect(view.getByLabelText('Rule 2: destination')).toHaveValue('*.stream.example')
    expect(view.getByText('rule 1 sends *.corp.example through Office')).toBeInTheDocument()
  })

  // An empty list is a working state rather than a failure: nothing is excepted, so the
  // traffic leaves the one way the setting above says. An empty table would read as rules
  // that failed to load.
  it('says an install with no rules sends everything the one way', async () => {
    const view = await mount(makeRouting())

    expect(view.getByText(/All internet traffic leaves the one way/)).toBeInTheDocument()
  })

  // Before the first answer there is nothing to describe. Rendering the empty list instead
  // would say the machine has no exceptions, which is a claim about state rather than about
  // not having read it yet.
  it('says it is still reading rather than reporting no rules', async () => {
    const view = await mount(undefined)

    expect(view.getByText('Reading the rules…')).toBeInTheDocument()
    expect(view.queryByText(/All internet traffic leaves the one way/)).toBeNull()
  })

  it('says why the rules could not be read', async () => {
    const view = await mount(undefined, {}, 'the agent is not answering')

    expect(view.getByText('the agent is not answering')).toBeInTheDocument()
  })

  // The rule is doing exactly what it says: those destinations are refused rather than sent
  // out another way. Somebody not told that reads the refusal as the app being broken.
  it('says when a rule names a connection that is not running', async () => {
    const down = makeRouting({
      rules: [CORP],
      describe: ['rule 1 sends *.corp.example through Office'],
      tunnels: [{ id: OFFICE, name: 'Office', running: false }],
      capability: {
        available: true,
        degraded: true,
        reason: 'rule 1 sends traffic through Office, which is not running',
      },
    })
    const view = await mount(down)

    expect(
      view.getByText('rule 1 sends traffic through Office, which is not running'),
    ).toBeInTheDocument()
    expect(view.getByRole('region', { name: 'Per-destination rules' })).toHaveTextContent(
      'refusing',
    )
  })

  // A rule an earlier one already covers still decides on the proxy path, so it is a note
  // about one path rather than a fault. Dropping it would leave a rule that looks in force
  // and is not.
  it('names the rules the interface will not reach', async () => {
    const view = await mount(
      makeRouting({
        rules: [CORP],
        describe: ['rule 1 sends *.corp.example through Office'],
        shadowed: ['rule 2 covers 10.0.0.0/24, which rule 1 already carries'],
      }),
    )

    expect(
      view.getByText('rule 2 covers 10.0.0.0/24, which rule 1 already carries'),
    ).toBeInTheDocument()
  })
})

describe('writing the rules', () => {
  // Nothing to save is not the same as saving nothing. A live Save on an untouched list
  // invites a write that cannot do anything, and hides whether an edit registered.
  it('offers nothing to save until a rule is edited', async () => {
    const view = await mount(withRules([CORP], ['rule 1 sends *.corp.example through Office']))

    expect(view.getByRole('button', { name: 'Save rules' })).toBeDisabled()

    fireEvent.change(view.getByLabelText('Rule 1: destination'), {
      target: { value: '*.corp.test' },
    })

    expect(view.getByRole('button', { name: 'Save rules' })).toBeEnabled()
  })

  // The order is what the agent decides by, so moving a row has to be what is written. A
  // save that kept the served order would silently undo the move.
  it('saves the new order when a rule is moved', async () => {
    const served = withRules([CORP, STREAM], ['first', 'second'])
    const view = await mount(served, { 'PUT /api/routing/rules': served })

    fireEvent.click(view.getByRole('button', { name: 'Move rule 2 up' }))
    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    const sent: { rules: RoutingRule[] } = view.agent.bodyOf('PUT /api/routing/rules')
    expect(sent.rules.map((r) => r.id)).toEqual(['rt_2', 'rt_1'])
  })

  // A destination written as an address is a range holding only itself, never a name: a name
  // is matched before anything resolves it, so a rule carrying 10.0.0.5 as a host would match
  // nothing at all.
  it('sends an address as a range and a pattern as a name', async () => {
    const served = makeRouting({ tunnels: TUNNELS })
    const view = await mount(served, { 'PUT /api/routing/rules': served })

    fireEvent.click(view.getByRole('button', { name: 'Add a rule' }))
    fireEvent.change(view.getByLabelText('Rule 1: destination'), { target: { value: '10.0.0.5' } })
    fireEvent.change(view.getByLabelText('Rule 1: connection'), { target: { value: LAB } })
    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    const sent: { rules: RoutingRule[] } = view.agent.bodyOf('PUT /api/routing/rules')
    expect(sent.rules).toEqual([{ id: '', action: 'via', tunnel: LAB, cidr: '10.0.0.5/32' }])
  })

  // Only the action that sends traffic somewhere carries a connection. Keeping the id on a
  // rule that refuses the destination would store a connection nothing reads, and the agent
  // refuses the rule outright.
  it('drops the connection from a rule that no longer sends traffic through one', async () => {
    const served = withRules([CORP], ['rule 1 sends *.corp.example through Office'])
    const view = await mount(served, { 'PUT /api/routing/rules': served })

    fireEvent.change(view.getByLabelText('Rule 1: what happens'), { target: { value: 'block' } })
    expect(view.queryByLabelText('Rule 1: connection')).toBeNull()

    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    const sent: { rules: RoutingRule[] } = view.agent.bodyOf('PUT /api/routing/rules')
    expect(sent.rules).toEqual([{ id: 'rt_1', action: 'block', host: '*.corp.example' }])
  })

  // The agent mints an id for a rule that had none. A table that kept its own empty id would
  // have that rule minted a second one on the next save, leaving two rules where one was
  // written.
  it('takes the ids the agent minted rather than saving an empty one twice', async () => {
    const minted = makeRouting({
      rules: [{ id: 'rt_minted', action: 'via', tunnel: LAB, host: 'files.example' }],
      describe: ['rule 1 sends files.example through Lab'],
      tunnels: TUNNELS,
    })
    const view = await mount(makeRouting({ tunnels: TUNNELS }), {
      'PUT /api/routing/rules': minted,
    })

    fireEvent.click(view.getByRole('button', { name: 'Add a rule' }))
    fireEvent.change(view.getByLabelText('Rule 1: destination'), {
      target: { value: 'files.example' },
    })
    fireEvent.change(view.getByLabelText('Rule 1: connection'), { target: { value: LAB } })
    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    fireEvent.change(view.getByLabelText('Rule 1: note'), { target: { value: 'the file server' } })
    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    const sent: { rules: RoutingRule[] } = view.agent.bodyOf('PUT /api/routing/rules', 1)
    expect(sent.rules).toEqual([
      { id: 'rt_minted', action: 'via', tunnel: LAB, host: 'files.example', note: 'the file server' },
    ])
  })

  // The box holds one destination, and a rule may carry two: a name, and the range that name
  // has to resolve into. Dropping the half it is not showing would quietly widen the rule to
  // every address the name answers with.
  it('keeps the range a rule narrows its name to', async () => {
    const both: RoutingRule = {
      id: 'rt_both',
      action: 'via',
      tunnel: OFFICE,
      host: '*.corp.example',
      cidr: '10.0.0.0/24',
    }
    const served = withRules([both], ['rule 1 sends *.corp.example inside 10.0.0.0/24 through Office'])
    const view = await mount(served, { 'PUT /api/routing/rules': served })

    expect(view.getByText('and only when that resolves inside 10.0.0.0/24')).toBeInTheDocument()

    fireEvent.change(view.getByLabelText('Rule 1: note'), { target: { value: 'the file server' } })
    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    const sent: { rules: RoutingRule[] } = view.agent.bodyOf('PUT /api/routing/rules')
    expect(sent.rules).toEqual([{ ...both, note: 'the file server' }])
  })

  // A refused list leaves the stored rules as they were, so the rows stay on screen with the
  // reason. Clearing them would look like a save that emptied the list.
  it('keeps the edited rows on screen with the reason a write was refused', async () => {
    const view = await mount(withRules([CORP], ['rule 1 sends *.corp.example through Office']), {
      'PUT /api/routing/rules': failWith(400, 'rule 1 names no destination'),
    })

    fireEvent.change(view.getByLabelText('Rule 1: destination'), { target: { value: '*.corp.test' } })
    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    expect(view.getByText('rule 1 names no destination')).toBeInTheDocument()
    expect(view.getByLabelText('Rule 1: destination')).toHaveValue('*.corp.test')
  })

  // The other cards on this page report what the rules moved -- what the interface carries,
  // which connections are being used -- so they are stale the moment a rule lands.
  it('tells the page to re-read everything after a save', async () => {
    const served = withRules([CORP], ['rule 1 sends *.corp.example through Office'])
    const saved = vi.fn()
    const view = await renderAgent(<RoutingCard view={served} onSaved={saved} />, {
      'PUT /api/routing/rules': served,
    })

    fireEvent.change(view.getByLabelText('Rule 1: note'), { target: { value: 'work' } })
    fireEvent.click(view.getByRole('button', { name: 'Save rules' }))
    await settle()

    expect(saved).toHaveBeenCalled()
  })

  // The rules are polled, so they move under this table -- another window, the command line.
  // Taking the new list while somebody is editing would throw away what they are writing,
  // which is worse than a list a few seconds old.
  it('takes a list that changed elsewhere, but not over an edit in progress', async () => {
    const first = withRules([CORP], ['rule 1 sends *.corp.example through Office'])
    const view = await mount(first)

    const second = withRules([STREAM], ['rule 1 sends *.stream.example out directly'])
    view.rerender(<RoutingCard view={second} onSaved={() => undefined} />)
    expect(view.getByLabelText('Rule 1: destination')).toHaveValue('*.stream.example')

    fireEvent.change(view.getByLabelText('Rule 1: destination'), { target: { value: 'mine.test' } })
    view.rerender(<RoutingCard view={first} onSaved={() => undefined} />)

    expect(view.getByLabelText('Rule 1: destination')).toHaveValue('mine.test')
  })
})

describe('asking where a destination goes', () => {
  it('names the rule that decided it', async () => {
    const view = await mount(withRules([CORP], ['rule 1 sends *.corp.example through Office']), {
      'POST /api/routing/check': {
        destination: 'files.corp.example',
        decided: true,
        action: 'via',
        tunnel: OFFICE,
        tunnelName: 'Office',
        rule: 'rt_1',
        ruleIndex: 1,
        reason: 'rule 1 *.corp.example goes through Office',
      },
    })

    fireEvent.change(view.getByLabelText('Where would a destination go?'), {
      target: { value: 'files.corp.example' },
    })
    fireEvent.click(view.getByRole('button', { name: 'Check' }))
    await settle()

    expect(view.agent.bodyOf('POST /api/routing/check')).toEqual({
      destination: 'files.corp.example',
    })
    expect(view.getByText('rule 1')).toBeInTheDocument()
    expect(view.getByText('rule 1 *.corp.example goes through Office')).toBeInTheDocument()
  })

  // A destination no rule names is the ordinary answer, not a blank: it leaves whichever way
  // the setting above says, and that is what somebody checking wanted to know.
  it('says so when no rule names the destination', async () => {
    const view = await mount(makeRouting({ tunnels: TUNNELS }), {
      'POST /api/routing/check': {
        destination: 'example.com',
        decided: false,
        reason: 'no rule names this destination, so it leaves whichever way the setting says',
      },
    })

    fireEvent.change(view.getByLabelText('Where would a destination go?'), {
      target: { value: 'example.com' },
    })
    fireEvent.click(view.getByRole('button', { name: 'Check' }))
    await settle()

    expect(view.getByText('no rule')).toBeInTheDocument()
    expect(view.getByText(/no rule names this destination/)).toBeInTheDocument()
  })

  // A question that could not be answered says so. Leaving the last answer on screen would
  // report the previous destination's route as this one's.
  it('says why a destination could not be checked', async () => {
    const view = await mount(withRules([CORP], ['rule 1 sends *.corp.example through Office']), {
      'POST /api/routing/check': failWith(400, 'destination is required'),
    })

    fireEvent.change(view.getByLabelText('Where would a destination go?'), {
      target: { value: '???' },
    })
    fireEvent.click(view.getByRole('button', { name: 'Check' }))
    await settle()

    expect(view.getByText('destination is required')).toBeInTheDocument()
    expect(view.queryByText('rule 1')).toBeNull()
  })

  // Asking about nothing has no answer, and the agent refuses it. Offering the button anyway
  // spends a round trip to be told so.
  it('will not ask about an empty destination', async () => {
    const view = await mount(makeRouting({ tunnels: TUNNELS }))

    expect(view.getByRole('button', { name: 'Check' })).toBeDisabled()
  })
})
