// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { deferred, emptySettingsForm, failWith, makeExitNode, makeExitNodeCandidate, renderAgent, settle } from '../test/agent'
import { ExitNodeCard } from './ExitNodeCard'
import type { ExitNodeSuggestion, ExitNodeView } from '../api'

function card(view: ExitNodeView) {
  return <ExitNodeCard view={view} form={emptySettingsForm()} app={emptySettingsForm()} />
}

/** working is the module on with a device carrying traffic, which is the state every
 *  test below varies one thing away from. */
function working(overrides: Partial<ExitNodeView> = {}): ExitNodeView {
  return makeExitNode({
    enabled: true,
    current: 'nGATEWAY',
    currentLabel: 'gateway',
    liveId: 'nGATEWAY',
    liveOnline: true,
    reason: 'Traffic is leaving through gateway.',
    candidates: [makeExitNodeCandidate({ current: true })],
    capability: { available: true, degraded: false },
    ...overrides,
  })
}

// The device carrying this machine's traffic is the one fact the card exists for.
it('names the device traffic is leaving through', async () => {
  const { getByLabelText } = await renderAgent(card(working()))

  const panel = getByLabelText('Exit node')
  expect(panel).toHaveTextContent('carrying traffic')
  expect(panel).toHaveTextContent('gateway')
  expect(panel).toHaveTextContent('Traffic is leaving through gateway.')
})

// Changing the exit node drops every connection going through the old one, and there is
// no graceful drain at any layer. That has to be on the card rather than in a doc.
it('always warns what changing the device costs', async () => {
  const { getByText } = await renderAgent(card(working()))

  expect(getByText(/drops every connection going through the old one/)).toBeInTheDocument()
})

// The device app-tail asked for and the one the tailnet reports carrying traffic are
// different facts, and the gap between them is the whole diagnosis when an exit node is
// not working.
it('says so when the tailnet is not carrying traffic through the chosen device', async () => {
  const { getByText } = await renderAgent(
    card(working({ liveId: '', liveOnline: false, capability: { available: true, degraded: true } })),
  )

  expect(getByText(/no exit node carrying traffic yet/)).toBeInTheDocument()
})

it('names the other device when the tailnet is routing through one we did not choose', async () => {
  const { getByText } = await renderAgent(card(working({ liveId: 'nOTHER' })))

  expect(getByText(/leaving through nOTHER rather than the device app-tail asked for/)).toBeInTheDocument()
})

// A tailnet offering nothing is the state a new user is in, and reading as broken there
// sends them looking for a fault in app-tail rather than at the admin console.
it('explains an empty tailnet rather than showing a blank list', async () => {
  const { getByText } = await renderAgent(card(working({ candidates: [] })))

  expect(getByText(/has to advertise itself as one and an admin has to approve it/)).toBeInTheDocument()
})

// An offline device stays listed because a chosen one has to remain visible while it is
// away -- but choosing it stops traffic, so it cannot read the same as an online one.
it('marks which offered devices are reachable and which one is in use', async () => {
  const { getByLabelText } = await renderAgent(
    card(
      working({
        candidates: [
          makeExitNodeCandidate({ id: 'nA', label: 'berlin', display: 'berlin (Berlin, Germany)', current: true }),
          makeExitNodeCandidate({ id: 'nB', label: 'away', display: 'away', online: false }),
        ],
      }),
    ),
  )

  const rows = [...getByLabelText('Exit node').querySelectorAll('.exit-node-candidates li')]
  expect(rows.map((row) => row.textContent)).toEqual([
    'berlin (Berlin, Germany)onlinein use',
    'awayoffline',
  ])
})

// A module nobody switched on and a module that could not start both arrive from the
// agent as unavailable. Painting the first one red puts a failure on the card for every
// feature the user has deliberately left alone.
it('reads a module nobody turned on as off rather than as a failure', async () => {
  const { container } = await renderAgent(
    card(
      makeExitNode({
        enabled: false,
        capability: { available: false, degraded: false, reason: 'the module is switched off' },
      }),
    ),
  )

  const status = container.querySelector('.panel-head .status')
  expect(status).toHaveClass('status', 'off')
  expect(status).not.toHaveClass('error')
})

// The agent's capability reason is the one that says what to do about the state, and it
// is a different sentence from the reason describing it. Dropping it because a reason is
// already on screen would lose the actionable half.
it('carries the agent’s explanation beside the state it describes', async () => {
  const { getByText } = await renderAgent(
    card(
      working({
        candidates: [],
        capability: {
          available: true,
          degraded: true,
          reason: 'Your tailnet is offering no approved exit node.',
        },
      }),
    ),
  )

  expect(getByText('Traffic is leaving through gateway.')).toBeInTheDocument()
  expect(getByText('Your tailnet is offering no approved exit node.')).toBeInTheDocument()
})

// Rotation moving the device on a timer is a thing the user has to be able to anticipate;
// a card that only said "rotating" would leave a dropped download unexplained.
it('says when the rotation schedule moves on', async () => {
  const when = new Date(Date.now() + 10 * 60 * 1000)
  const { getByText } = await renderAgent(
    card(working({ rotating: true, nextChange: when.toISOString() })),
  )

  const clock = when.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
  expect(getByText(`Rotation is on; the next change is around ${clock}.`)).toBeInTheDocument()
})

// A schedule with no next change yet still has to read as rotating, and a broken
// timestamp must not render "around Invalid Date".
it('reports rotation without a time rather than an unreadable one', async () => {
  const { getByText } = await renderAgent(
    card(working({ rotating: true, nextChange: 'not-a-time' })),
  )

  expect(getByText('Rotation is on.')).toBeInTheDocument()
})

describe('asking the tailnet for a recommendation', () => {
  // The empty answer is the ordinary one on a tailnet whose exit nodes are all
  // self-hosted. Rendering nothing would read as the button being broken.
  it('reports an empty answer as an answer', async () => {
    const empty: ExitNodeSuggestion = {
      reason: 'Your tailnet has no exit node to suggest. Choose from the list instead.',
    }
    const { agent, getByRole, getByText } = await renderAgent(card(working()), {
      'POST /api/exitnode/suggest': empty,
    })

    fireEvent.click(getByRole('button', { name: 'Ask my tailnet' }))
    await settle()

    expect(agent.countOf('POST /api/exitnode/suggest')).toBe(1)
    expect(
      getByText('Your tailnet has no exit node to suggest. Choose from the list instead.'),
    ).toBeInTheDocument()
  })

  // A picker of hosted exit nodes is unusable without the place, so a recommendation
  // that has one states it.
  it('names the suggested device and where it is', async () => {
    const { getByRole, getByText } = await renderAgent(card(working()), {
      'POST /api/exitnode/suggest': {
        id: 'nXYZ',
        label: 'mullvad-berlin',
        country: 'Germany',
        city: 'Berlin',
      },
    })

    fireEvent.click(getByRole('button', { name: 'Ask my tailnet' }))
    await settle()

    expect(
      getByText('Your tailnet suggests mullvad-berlin (Berlin, Germany). Choose it in the settings below to use it.'),
    ).toBeInTheDocument()
  })

  // A device someone runs themselves has no place to report, and a sentence built for one
  // would trail an empty bracket where the city should be.
  it('names a suggested device that has no place to report', async () => {
    const { getByRole, getByText } = await renderAgent(card(working()), {
      'POST /api/exitnode/suggest': { id: 'nHOME', label: 'home-router' },
    })

    fireEvent.click(getByRole('button', { name: 'Ask my tailnet' }))
    await settle()

    expect(
      getByText('Your tailnet suggests home-router. Choose it in the settings below to use it.'),
    ).toBeInTheDocument()
  })

  // A refusal that vanished would look identical to "your tailnet has no suggestion",
  // which sends the user to the admin console instead of at the node that is down.
  it('shows the agent’s refusal rather than reporting no suggestion', async () => {
    const { getByRole, getByText } = await renderAgent(card(working()), {
      'POST /api/exitnode/suggest': failWith(503, 'the tailnet node is not running'),
    })

    fireEvent.click(getByRole('button', { name: 'Ask my tailnet' }))
    await settle()

    expect(getByText('the tailnet node is not running')).toBeInTheDocument()
  })

  it('cannot be pressed twice while the first request is still open', async () => {
    const pending = deferred<ExitNodeSuggestion>()
    const { agent, getByRole } = await renderAgent(card(working()), {
      'POST /api/exitnode/suggest': () => pending.promise,
    })

    const button = getByRole('button', { name: 'Ask my tailnet' })
    fireEvent.click(button)
    await settle(1)
    expect(button).toBeDisabled()

    pending.resolve({ reason: 'nothing to suggest' })
    await settle()
    expect(agent.countOf('POST /api/exitnode/suggest')).toBe(1)
  })
})

// The agent explains an empty candidate list in almost the same words the card would use
// on its own. Both is two findings about one empty list.
describe('an empty candidate list', () => {
  const served =
    'Your tailnet is offering no approved exit node. A device has to advertise itself as one.'

  it('leaves the explaining to the agent when it has explained', async () => {
    const { container, getByText } = await renderAgent(
      <ExitNodeCard
        view={makeExitNode({
          enabled: true,
          candidates: [],
          capability: { available: true, degraded: true, reason: served },
        })}
        form={emptySettingsForm()}
      app={emptySettingsForm()}
      />,
    )

    expect(getByText(served)).toBeInTheDocument()
    expect(container.textContent).not.toContain('before it can be chosen here')
  })

  // And says it itself when the agent said nothing, because three blank columns with no
  // sentence read as a card that failed to load.
  it('says it itself when the agent said nothing', async () => {
    const { container } = await renderAgent(
      <ExitNodeCard
        view={makeExitNode({
          enabled: true,
          candidates: [],
          capability: { available: true, degraded: false },
        })}
        form={emptySettingsForm()}
      app={emptySettingsForm()}
      />,
    )

    expect(container.textContent).toContain('offering no approved exit node')
  })
})
