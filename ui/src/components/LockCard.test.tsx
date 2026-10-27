// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { deferred, failWith, makeLock, renderAgent, settle } from '../test/agent'
import { LockCard } from './LockCard'
import type { LockUpdate, LockView } from '../api'

function card(view: Partial<LockView>, onChanged: () => void = () => {}) {
  return <LockCard view={makeLock({ enabled: true, ...view })} onChanged={onChanged} />
}

/** A device lock has cut off, which is the state the whole card exists for. */
const lockedOut: Partial<LockView> = {
  enabled: true,
  signed: false,
  nodeKey: 'nodekey:abc123',
  lockKey: 'tlpub:def456',
  signCommand: 'tailscale lock sign nodekey:abc123 tlpub:def456',
  capability: {
    available: true,
    degraded: true,
    reason: 'This device is not signed for tailnet lock yet, so it can reach no device.',
  },
}

// The command is the entire remedy for a locked-out device: it is what the user takes to
// someone holding a key. A card that describes the problem without it leaves them with
// nothing to do, which is indistinguishable from the app having no answer.
describe('the remedy', () => {
  it('shows the command that unlocks this device while it is cut off', async () => {
    const { getByText } = await renderAgent(card(lockedOut))

    expect(getByText('tailscale lock sign nodekey:abc123 tlpub:def456')).toBeInTheDocument()
  })

  // Left on screen after signing it reads as a device still waiting, which is the exact
  // conclusion the card is meant to prevent anyone reaching.
  it('drops the command once this device is signed', async () => {
    const { queryByText } = await renderAgent(card({ ...lockedOut, signed: true }))

    expect(queryByText('tailscale lock sign nodekey:abc123 tlpub:def456')).toBeNull()
  })

  // The keys come from the agent, which knows this device's own. A card that assembled
  // the command itself would be a second place its shape is written down.
  it('shows no command when the agent could not build one', async () => {
    const withoutCommand = { ...lockedOut }
    delete withoutCommand.signCommand
    const { container } = await renderAgent(card(withoutCommand))

    expect(container.querySelector('.snippet')).toBeNull()
  })
})

// Being unsigned is not a warning: the device reaches nothing at all, which is the same
// outcome as one that never connected. The word and the colour are what a reader scanning
// a page of panels actually takes in.
describe('the state it names', () => {
  const cases: Array<[string, Partial<LockView>, string, string]> = [
    [
      'lock is off for the tailnet',
      { enabled: false },
      'off for this tailnet',
      'running',
    ],
    ['this device is unsigned', lockedOut, 'this device is not signed', 'error'],
    [
      'other devices are held back',
      { signed: true, capability: { available: true, degraded: true } },
      'some devices held back',
      'pending',
    ],
    [
      'everything is signed',
      { signed: true, capability: { available: true, degraded: false } },
      'signed',
      'running',
    ],
    [
      'the node is down so nothing was read',
      { signed: true, capability: { available: false, degraded: false } },
      'unknown',
      'off',
    ],
  ]

  for (const [name, view, label, tone] of cases) {
    it(`says ${label} when ${name}`, async () => {
      const { getByText } = await renderAgent(card(view))

      expect(getByText(label).className).toContain(tone)
    })
  }
})

// Peers lock removed from this device's view are the reason "online but nothing connects"
// is otherwise unexplainable. A count would not do: the user has to go and look at those
// specific devices to get them signed.
describe('the devices held back', () => {
  it('names them rather than counting them', async () => {
    const { getByText } = await renderAgent(
      card({
        signed: true,
        filtered: [
          { id: 'n1', name: 'laptop', nodeKey: 'nodekey:aaa' },
          { id: 'n2', name: 'phone', nodeKey: 'nodekey:bbb' },
        ],
      }),
    )

    expect(getByText('laptop')).toBeInTheDocument()
    expect(getByText('nodekey:aaa')).toBeInTheDocument()
    expect(getByText('phone')).toBeInTheDocument()
  })

  it('leaves the block out when lock is holding nobody back', async () => {
    const { container } = await renderAgent(card({ signed: true }))

    expect(container.querySelector('.lock-filtered')).toBeNull()
  })
})

// The tailnet's own metadata against a key, which is how a reader tells a colleague's
// laptop from a recovery key kept in a safe.
it('labels the keys the tailnet trusts and marks this device among them', async () => {
  const { container, getByText } = await renderAgent(
    card({
      signed: true,
      trusted: [
        { id: 'tlpub:aaa', votes: 1, self: true, label: 'workstation' },
        { id: 'tlpub:bbb', votes: 2, self: false, label: 'recovery' },
      ],
    }),
  )

  expect(getByText('workstation')).toBeInTheDocument()
  expect(getByText('recovery')).toBeInTheDocument()
  const marked = [...container.querySelectorAll('.lock-keys li')]
    .filter((li) => li.querySelector('.badge'))
    .map((li) => li.textContent ?? '')
  expect(marked).toHaveLength(1)
  expect(marked[0]).toContain('tlpub:aaa')
})

describe('authorizing another device', () => {
  const signer: Partial<LockView> = { signed: true, canSign: true }

  // Offered to a device without a trusted key, every submission comes back refused --
  // which reads as a broken feature rather than as one this device cannot perform.
  it('is offered only to a device holding a trusted key', async () => {
    const { queryByText } = await renderAgent(card({ signed: true, canSign: false }))

    expect(queryByText('Authorize another device')).toBeNull()
  })

  it('sends both keys the way the user typed them', async () => {
    const { agent, getByLabelText, getByText } = await renderAgent(card(signer), {
      'POST /api/lock/sign': makeLock({ enabled: true, signed: true }),
    })

    fireEvent.change(getByLabelText(/Device node key/), { target: { value: 'nodekey:xyz' } })
    fireEvent.change(getByLabelText(/Device tailnet lock key/), {
      target: { value: 'tlpub:xyz' },
    })
    fireEvent.click(getByText('Sign this device'))
    await settle()

    expect(agent.bodyOf('POST /api/lock/sign')).toEqual({
      nodeKey: 'nodekey:xyz',
      rotationKey: 'tlpub:xyz',
    })
  })

  // The card's own view is a poll away from being stale, and the whole point of signing is
  // that the held-back list above it changes.
  it('re-reads the card once the tailnet accepted the signature', async () => {
    let refreshed = 0
    const { getByLabelText, getByText } = await renderAgent(
      card(signer, () => {
        refreshed += 1
      }),
      { 'POST /api/lock/sign': makeLock({ enabled: true, signed: true }) },
    )

    fireEvent.change(getByLabelText(/Device node key/), { target: { value: 'nodekey:xyz' } })
    fireEvent.click(getByText('Sign this device'))
    await settle()

    expect(refreshed).toBe(1)
  })

  // A refusal that vanished would leave the user believing an unsigned device is now
  // authorized, and they would go looking for the fault on the other machine.
  it('shows the agent’s refusal instead of reporting success', async () => {
    let refreshed = 0
    const { getByLabelText, getByText, queryByText } = await renderAgent(
      card(signer, () => {
        refreshed += 1
      }),
      { 'POST /api/lock/sign': failWith(400, 'nodeKey is required') },
    )

    fireEvent.change(getByLabelText(/Device node key/), { target: { value: 'nope' } })
    fireEvent.click(getByText('Sign this device'))
    await settle()

    expect(getByText('nodeKey is required')).toBeInTheDocument()
    expect(queryByText('Signed nope.')).toBeNull()
    expect(refreshed).toBe(0)
  })

  it('cannot be submitted with no node key', async () => {
    const { getByRole } = await renderAgent(card(signer))

    expect(getByRole('button', { name: 'Sign this device' })).toBeDisabled()
  })

  it('cannot be submitted twice while the first is still open', async () => {
    const pending = deferred<LockView>()
    const { agent, getByLabelText, getByRole } = await renderAgent(card(signer), {
      'POST /api/lock/sign': () => pending.promise,
    })

    fireEvent.change(getByLabelText(/Device node key/), { target: { value: 'nodekey:xyz' } })
    const button = getByRole('button', { name: 'Sign this device' })
    fireEvent.click(button)
    await settle(1)
    expect(button).toBeDisabled()

    pending.resolve(makeLock({ enabled: true, signed: true }))
    await settle()
    expect(agent.countOf('POST /api/lock/sign')).toBe(1)
  })
})

describe('the history', () => {
  // The log is the tailnet's whole key authority. Read on every poll it would be fetched
  // four times a minute for a panel almost nobody opens.
  it('is read only when asked for', async () => {
    const { agent, container, getByText } = await renderAgent(card({ signed: true }), {
      'GET /api/lock/log': [] as LockUpdate[],
    })

    expect(agent.countOf('GET /api/lock/log')).toBe(0)
    // Nor rendered as an empty history, which would say the tailnet recorded no change
    // when the truth is that nobody has looked.
    expect(container.querySelector('.lock-log')).toBeNull()
    expect(container.textContent).not.toContain('no recorded changes')

    fireEvent.click(getByText('Show history'))
    await settle()

    expect(agent.countOf('GET /api/lock/log')).toBe(1)
  })

  it('lists what changed against the entry that changed it', async () => {
    const { getByText } = await renderAgent(card({ signed: true }), {
      'GET /api/lock/log': [
        { hash: 'abcdef0123456789', change: 'added a signing key' },
      ] as LockUpdate[],
    })

    fireEvent.click(getByText('Show history'))
    await settle()

    expect(getByText('added a signing key')).toBeInTheDocument()
    expect(getByText('abcdef012345')).toBeInTheDocument()
  })

  // An empty log rendering nothing is indistinguishable from a button that did not work.
  it('says so when the tailnet recorded no change', async () => {
    const { getByText } = await renderAgent(card({ signed: true }), {
      'GET /api/lock/log': [] as LockUpdate[],
    })

    fireEvent.click(getByText('Show history'))
    await settle()

    expect(getByText('Your tailnet’s key authority has no recorded changes.')).toBeInTheDocument()
  })

  it('shows the agent’s refusal rather than an empty history', async () => {
    const { getByText, queryByText } = await renderAgent(card({ signed: true }), {
      'GET /api/lock/log': failWith(503, 'the tailnet node is not running'),
    })

    fireEvent.click(getByText('Show history'))
    await settle()

    expect(getByText('the tailnet node is not running')).toBeInTheDocument()
    expect(queryByText('Your tailnet’s key authority has no recorded changes.')).toBeNull()
  })
})

describe('a failed read', () => {
  const failed = 'reading tailnet lock status failed: context deadline exceeded'

  // The agent reports the failure as the module's reason as well, because it is why the
  // module is degraded. Rendering both slots verbatim puts the same sentence on screen
  // twice, which reads as two separate faults.
  it('is stated once when it is also the reason the module is degraded', async () => {
    const { getAllByText } = await renderAgent(
      card({ error: failed, capability: { available: true, degraded: true, reason: failed } }),
    )

    expect(getAllByText(failed, { selector: '.notice' })).toHaveLength(1)
  })

  // Left out whenever a reason is present, a failure the agent did not promote would
  // vanish -- and a card with an unexplained state is the thing to avoid.
  it('is stated alongside a reason that says something else', async () => {
    const { getByText } = await renderAgent(
      card({
        error: failed,
        capability: {
          available: true,
          degraded: true,
          reason: 'Tailnet lock is holding back some devices this one can otherwise see.',
        },
      }),
    )

    expect(getByText(failed, { selector: '.notice' })).toBeInTheDocument()
    expect(
      getByText('Tailnet lock is holding back some devices this one can otherwise see.'),
    ).toBeInTheDocument()
  })
})
