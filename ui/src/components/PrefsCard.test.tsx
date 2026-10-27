// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { makePrefField, makePrefs, renderAgent } from '../test/agent'
import { PrefsCard } from './PrefsCard'
import type { PrefsView } from '../api'

function card(view: PrefsView) {
  return <PrefsCard view={view} />
}

/** rows is what the card shows for each setting, which is the whole of its output. */
function rows(container: HTMLElement): string[] {
  return [...container.querySelectorAll('.proxy-counters div')].map((row) => row.textContent ?? '')
}

// A setting the node is holding is the ordinary case, and it has to read as settled
// rather than as one more thing waiting on something.
it('shows a setting the node is holding as in force', async () => {
  const { container } = await renderAgent(
    card(makePrefs({ fields: [makePrefField()] })),
  )

  expect(rows(container)).toEqual([
    'Reach networks other devices advertiseOn — In force',
  ])
})

// The reason this card exists: a save that stored fine and never reached the tailnet
// looks identical to one that worked unless the two values are shown side by side.
it('shows the node’s own value beside the stored one when they disagree', async () => {
  const { container } = await renderAgent(
    card(makePrefs({ fields: [makePrefField({ stored: true, live: false, inForce: false })] })),
  )

  expect(rows(container)).toEqual([
    'Reach networks other devices advertiseOn — The node has it off',
  ])
})

// "Waiting" and "the node disagrees" call for different actions -- one is patience, the
// other is a conflict -- so a value nobody has read yet must not render as a disagreement.
it('says a setting is waiting rather than guessing what the node holds', async () => {
  const { container } = await renderAgent(
    card(makePrefs({ fields: [makePrefField({ live: undefined, inForce: false })] })),
  )

  expect(rows(container)).toEqual([
    'Reach networks other devices advertiseOn — Waiting for the tailnet node',
  ])
})

// Nothing about a preference is known until the node reports its own, so every setting
// waits together rather than each claiming to be in force on a node nobody has heard from.
it('says every setting is waiting while the node has reported nothing', async () => {
  const { container } = await renderAgent(
    card(makePrefs({ known: false, fields: [makePrefField()] })),
  )

  expect(rows(container)).toEqual([
    'Reach networks other devices advertiseOn — Waiting for the tailnet node',
  ])
})

// These settings are not all booleans, and a text one that is empty has to read as unset
// rather than as a blank where a value should be.
it('reads an empty text setting as unset rather than as blank', async () => {
  const { container } = await renderAgent(
    card(
      makePrefs({
        fields: [
          makePrefField({ key: 'exitNode.nodeId', label: 'Device to route through', stored: '', live: '' }),
        ],
      }),
    ),
  )

  expect(rows(container)).toEqual(['Device to route throughNot set — In force'])
})

// One of these settings is a list of networks. Handed to the renderer as it arrives it
// would print as its entries run together, which is unreadable exactly where a typo in a
// prefix matters -- and an empty one has to say so rather than leave the row blank.
it('shows a list setting as its entries, and says so when there are none', async () => {
  const { container } = await renderAgent(
    card(
      makePrefs({
        fields: [
          makePrefField({
            key: 'routes.advertise',
            label: 'Networks to offer the tailnet',
            stored: ['10.0.0.0/24', '192.168.1.0/24'],
            live: ['10.0.0.0/24', '192.168.1.0/24'],
          }),
          makePrefField({
            key: 'routes.advertise.empty',
            label: 'Networks offered by a device with none',
            stored: [],
            live: [],
          }),
        ],
      }),
    ),
  )

  expect(rows(container)).toEqual([
    'Networks to offer the tailnet10.0.0.0/24, 192.168.1.0/24 — In force',
    'Networks offered by a device with noneNone — In force',
  ])
})

// A number reads as itself: "On" for a count would be nonsense, and the label carries
// the subject either way.
it('shows a numeric setting as its own value', async () => {
  const { container } = await renderAgent(
    card(
      makePrefs({
        fields: [makePrefField({ key: 'rotate', label: 'Minutes between changes', stored: 15, live: 15 })],
      }),
    ),
  )

  expect(rows(container)).toEqual(['Minutes between changes15 — In force'])
})

// The agent's reason is what says why a setting is not being applied. Dropping it would
// leave a stale value on screen with nothing explaining it.
it('carries the agent’s explanation of why these settings are not applying', async () => {
  const { getByText } = await renderAgent(
    card(
      makePrefs({
        fields: [makePrefField()],
        capability: {
          available: true,
          degraded: true,
          reason: 'Something outside app-tail keeps changing these back.',
        },
      }),
    ),
  )

  expect(getByText('Something outside app-tail keeps changing these back.')).toBeInTheDocument()
})

// Everything working is the state the card spends most of its life in, and it has to look
// like nothing rather than like an empty box the user reads as a message that failed to
// load.
it('shows no notice at all when the agent has nothing to explain', async () => {
  const { container } = await renderAgent(
    card(
      makePrefs({
        fields: [makePrefField()],
        capability: { available: true, degraded: false, reason: '' },
      }),
    ),
  )

  expect(container.querySelector('.notice')).toBeNull()
})

// A list setting nobody has set arrives as JSON null, because a nil Go slice marshals to
// null rather than to []. Before this was handled, `shown` returned null itself and the
// caller that lowercased it threw during render -- which in React means the whole
// dashboard goes blank, not just this card.
describe('a value the agent sent as null', () => {
  const nullList = () =>
    card(
      makePrefs({
        known: true,
        fields: [
          {
            key: 'routes.advertise',
            label: 'Networks to offer the tailnet',
            stored: null,
            live: null,
            inForce: false,
          },
        ],
      }),
    )

  it('reads as unset rather than taking the whole page down', async () => {
    const { getByText } = await renderAgent(nullList())

    expect(getByText('Networks to offer the tailnet')).toBeInTheDocument()
  })

  // Null and "the node has not reported this yet" are the same thing to a reader, and
  // both are honest. Claiming "the node has it not set" would invent a value.
  it('is described as waiting rather than as a value the node holds', async () => {
    const { container } = await renderAgent(nullList())

    expect(container.textContent).toContain('Waiting for the tailnet node')
    expect(container.textContent).not.toContain('The node has it')
  })
})
