// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import {
  deferred,
  emptySettingsForm,
  failWith,
  makeInterface,
  openInfo,
  renderAgent,
  renderScoped,
  settle,
} from '../../test/agent'
import { InterfaceModeCard } from './InterfaceModeCard'

describe('what the card says the mode is doing', () => {
  // The state the card exists for: the node is up, reports an address, and is not the
  // thing that carries the machine's tailnet addresses. Every other signal reads healthy.
  it('separates the mode in force from the one that was asked for', () => {
    const { container, getByText } = renderScoped(
      <InterfaceModeCard
        tun={makeInterface({
          enabled: true,
          configured: 'tun',
          fallback: 'the privileged helper is not running',
        })} form={emptySettingsForm()} />,
    )

    expect(container.querySelector('.status.error')).toHaveTextContent('fell back')
    expect(getByText(/not on a network interface/)).toHaveTextContent(
      'the privileged helper is not running',
    )
  })

  it('names the interface once the node is really on one', () => {
    const { container } = renderScoped(
      <InterfaceModeCard
        tun={makeInterface({ enabled: true, mode: 'tun', configured: 'tun', inForce: true })} form={emptySettingsForm()} />,
    )

    expect(container.querySelector('.status.running')).toHaveTextContent('in force')
    expect(container.querySelector('.status.running')).toHaveTextContent('utun9')
  })

  // A mode stored but not yet moved onto is neither working nor broken, and saying so is
  // what tells the user the remaining step is a restart rather than a reinstall.
  it('says a stored mode is waiting for a restart', () => {
    const { container } = renderScoped(
      <InterfaceModeCard tun={makeInterface({ enabled: true, configured: 'tun' })} form={emptySettingsForm()} />,
    )

    expect(container.querySelector('.status.pending')).toHaveTextContent('waiting for a restart')
  })

  // A working machine has nothing to explain. A card that kept a notice standing once the
  // mode was in force would read as a warning about the state it just reached.
  it('shows no notice at all once the mode is working', () => {
    const { container } = renderScoped(
      <InterfaceModeCard
        tun={makeInterface({
          enabled: true,
          mode: 'tun',
          configured: 'tun',
          inForce: true,
          capability: { available: true, degraded: false },
        })} form={emptySettingsForm()} />,
    )

    expect(container.querySelector('.notice')).toBeNull()
  })

  it('says the tailnet is inside app-tail while the mode is unchosen', () => {
    const { container } = renderScoped(<InterfaceModeCard tun={makeInterface({ enabled: true })} form={emptySettingsForm()} />)

    expect(container.querySelector('.status.off')).toHaveTextContent('inside app-tail only')
  })
})

// The helper is what creates the interface, and every way it can be missing has a
// different remedy -- so the row says which one this machine is in rather than "not ready".
describe('what the card says about the privileged helper', () => {
  it.each([
    [
      'running',
      { design: true, installable: true, installed: true, running: true, version: '1.2.3' },
      'Running, version 1.2.3.',
    ],
    [
      'answering without naming a version',
      { design: true, installable: true, installed: true, running: true },
      'Running.',
    ],
    [
      'installed and silent',
      { design: true, installable: true, installed: true, running: false },
      'Installed, but it has not answered.',
    ],
    [
      'absent',
      { design: true, installable: true, installed: false, running: false },
      'Not installed.',
    ],
    [
      'unnecessary on this platform',
      { design: false, installable: false, installed: false, running: false },
      'This platform needs no separate helper.',
    ],
  ])('describes a helper that is %s', (_state, helper, expected) => {
    const { getByText } = renderScoped(
      <InterfaceModeCard tun={makeInterface({ enabled: true, helper })} form={emptySettingsForm()} />,
    )

    expect(getByText(expected)).toBeInTheDocument()
  })

  // The helper's own sentence already carries the next step, so repeating a generic one
  // beside it would send someone to a remedy that does not fit their machine.
  it('leads with the helper own words when it could not be reached', () => {
    const { getByText } = renderScoped(
      <InterfaceModeCard
        tun={makeInterface({
          enabled: true,
          helper: {
            design: true,
            installable: false,
            installed: true,
            running: false,
            problem: 'set it up for this account with `sudo app-tail tun helper`',
            socket: '/var/run/app-tail/helper.sock',
          },
        })} form={emptySettingsForm()} />,
    )

    expect(getByText(/sudo app-tail tun helper/)).toBeInTheDocument()
    expect(getByText('/var/run/app-tail/helper.sock')).toBeInTheDocument()
  })
})

describe('what the card says about the machine', () => {
  // Another tailnet client owning the addresses is not a fault in app-tail and no amount
  // of reinstalling fixes it, so it is stated rather than folded into the helper row.
  it('names a conflict and a missing component separately', () => {
    const { getByText } = renderScoped(
      <InterfaceModeCard
        tun={makeInterface({
          enabled: true,
          conflict: 'the official Tailscale client is running',
          missing: 'the system extension is not installed',
        })} form={emptySettingsForm()} />,
    )

    expect(getByText('the official Tailscale client is running')).toBeInTheDocument()
    expect(getByText('the system extension is not installed')).toBeInTheDocument()
  })

  // The case this exists for is the one where app-tail is not the thing that will do the
  // cleaning, so the commands have to be here to run by hand.
  it('lists what an earlier run left behind, with the commands that remove it', () => {
    const { getByText } = renderScoped(
      <InterfaceModeCard
        tun={makeInterface({
          enabled: true,
          leftovers: ['/etc/resolver/tail1a2b3c.ts.net'],
          undo: ['sudo rm /etc/resolver/tail1a2b3c.ts.net'],
        })} form={emptySettingsForm()} />,
    )

    expect(getByText('/etc/resolver/tail1a2b3c.ts.net')).toBeInTheDocument()
    expect(getByText('sudo rm /etc/resolver/tail1a2b3c.ts.net')).toBeInTheDocument()
  })

  // Two different kinds of sentence, so they land in two different places. Why the mode
  // is not working right now is a fact about this moment and stays on the card; what the
  // mode does to the machine is true on every machine in every state and sits behind the
  // button, where it is one press away instead of three paragraphs above the answer.
  describe('what the mode changes, and why it is or is not working', () => {
    const CHANGES = 'It changes the machine, not just app-tail.'
    const REASON = 'the mode is set to keep the tailnet inside app-tail'

    const card = () => (
      <InterfaceModeCard
        tun={makeInterface({
          enabled: true,
          capability: {
            available: true,
            degraded: true,
            reason: REASON,
            limits: [CHANGES],
          },
        })} form={emptySettingsForm()} />
    )

    it('states on the card why it is not working', () => {
      const { getByText } = renderScoped(card())

      expect(getByText(REASON)).toBeInTheDocument()
    })

    it('states what the mode changes, once asked', () => {
      const { container } = renderScoped(card())

      expect(openInfo(container, 'Network interface')).toHaveTextContent(CHANGES)
    })

    it('keeps what the mode changes off the card until it is asked for', () => {
      const { queryByText } = renderScoped(card())

      expect(queryByText(CHANGES)).not.toBeInTheDocument()
    })
  })

  // A platform that cannot run the mode at all is a different weight from one that could
  // and is not: the remedy for "not supported here" is not the remedy for "not installed".
  it('weights a machine that cannot carry the mode as an error', () => {
    const { container } = renderScoped(
      <InterfaceModeCard
        tun={makeInterface({
          enabled: true,
          interface: '',
          capability: {
            available: false,
            degraded: false,
            reason: 'this platform cannot run app-tail on a network interface',
          },
        })} form={emptySettingsForm()} />,
    )

    expect(container.querySelector('.notice.error')).toHaveTextContent('cannot run app-tail')
  })
})

// The agent sends one sentence for two fields: the helper's complaint is both the reason
// the mode is unavailable and the state of the helper itself. Rendered in both places it
// reads as two separate faults on a machine that has one.
it('states the helper problem once, not once per field it arrives in', () => {
  const problem = 'the privileged helper is not running: /var/run/app-tail/helper.sock'
  const { container } = renderScoped(
    <InterfaceModeCard
      tun={makeInterface({
        enabled: true,
        helper: { design: true, installable: true, installed: true, running: false, problem },
        capability: { available: false, degraded: true, reason: problem },
      })}
      form={emptySettingsForm()}
    />,
  )

  const hits = (container.textContent ?? '').split(problem).length - 1
  expect(hits).toBe(1)
})

// The one CLI command this card used to require. The mode needs a process running as
// root, obtaining one needs a password, and the surface reporting the mode is broken is
// the surface somebody is looking at when they want it fixed.
describe('setting the machine up from the card', () => {
  const noHelper = { design: true, installable: true, installed: false, running: false }

  it('offers the setup on a machine whose helper is missing', async () => {
    const { getByRole } = await renderAgent(
      <InterfaceModeCard tun={makeInterface({ enabled: true, helper: noHelper })} form={emptySettingsForm()} />,
    )

    expect(getByRole('button', { name: 'Set this machine up' })).toBeEnabled()
  })

  // Two machines with nothing to press for. A platform that installs no helper has only a
  // root command to be run by hand, and one already running its helper is set up: a button
  // on either does nothing and reads as the fix that did not work.
  it.each([
    ['the helper is already running', { design: true, installable: true, installed: true, running: true }],
    ['this platform cannot install one', { design: true, installable: false, installed: false, running: false }],
    ['this platform needs no helper', { design: false, installable: false, installed: false, running: false }],
  ])('is not offered when %s', async (_why, helper) => {
    const { queryByRole } = await renderAgent(
      <InterfaceModeCard tun={makeInterface({ enabled: true, helper })} form={emptySettingsForm()} />,
    )

    expect(queryByRole('button', { name: 'Set this machine up' })).toBeNull()
  })

  // The helper is installed but the running node was built without one, so the mode
  // arrives with the node that replaces it. Reporting only success would leave the card
  // still saying the mode is not in force with nothing explaining why.
  it('asks the agent and then says a restart is what puts the mode in force', async () => {
    const { agent, getByRole, getByText } = await renderAgent(
      <InterfaceModeCard tun={makeInterface({ enabled: true, helper: noHelper })} form={emptySettingsForm()} />,
      { 'POST /api/tun/setup': { restartNeeded: true } },
    )

    fireEvent.click(getByRole('button', { name: 'Set this machine up' }))
    await settle()

    expect(agent.countOf('POST /api/tun/setup')).toBe(1)
    expect(getByText(/moves onto the network interface when app-tail restarts/)).toBeInTheDocument()
    expect(getByRole('button', { name: 'Restart app-tail' })).toBeInTheDocument()
  })

  // A dismissed password dialog is an answer, and one that vanished would leave the card
  // claiming the machine was set up while the helper is still not there.
  it('shows the refusal instead of reporting the machine set up', async () => {
    const { getByRole, getByText, queryByText } = await renderAgent(
      <InterfaceModeCard tun={makeInterface({ enabled: true, helper: noHelper })} form={emptySettingsForm()} />,
      { 'POST /api/tun/setup': failWith(500, 'the request for administrator rights was declined') },
    )

    fireEvent.click(getByRole('button', { name: 'Set this machine up' }))
    await settle()

    expect(getByText('the request for administrator rights was declined')).toBeInTheDocument()
    expect(queryByText(/moves onto the network interface/)).toBeNull()
    // Still offered: a dialog dismissed by accident is the case where pressing again is
    // exactly the right thing to do.
    expect(getByRole('button', { name: 'Set this machine up' })).toBeEnabled()
  })

  // The dialog is a system prompt that sits until it is answered. A second press behind it
  // queues a second prompt against a machine the first one may already have fixed.
  it('cannot be pressed again while the password prompt is still up', async () => {
    const pending = deferred<{ restartNeeded: boolean }>()
    const { getByRole } = await renderAgent(
      <InterfaceModeCard tun={makeInterface({ enabled: true, helper: noHelper })} form={emptySettingsForm()} />,
      { 'POST /api/tun/setup': () => pending.promise },
    )

    fireEvent.click(getByRole('button', { name: 'Set this machine up' }))
    await settle(1)

    expect(getByRole('button', { name: 'Waiting for your password…' })).toBeDisabled()

    pending.resolve({ restartNeeded: true })
    await settle()
  })
})

// The setup that just succeeded is what stops the machine needing one, so the next poll
// of the card withdraws the offer. Taking the notice with it would remove the sentence
// naming the remaining step, seconds after it appeared, and read as the fix being undone.
it('keeps saying a restart is left after the machine stops needing setting up', async () => {
  const noHelper = { design: true, installable: true, installed: false, running: false }
  const { getByRole, getByText, rerender } = await renderAgent(
    <InterfaceModeCard tun={makeInterface({ enabled: true, helper: noHelper })} form={emptySettingsForm()} />,
    { 'POST /api/tun/setup': { restartNeeded: true } },
  )

  fireEvent.click(getByRole('button', { name: 'Set this machine up' }))
  await settle()

  // What the poll after a successful setup reports: the helper is there and answering.
  rerender(
    <InterfaceModeCard
      tun={makeInterface({
        enabled: true,
        helper: { design: true, installable: true, installed: true, running: true, version: 'dev' },
      })}
      form={emptySettingsForm()}
    />,
  )

  expect(getByText(/moves onto the network interface when app-tail restarts/)).toBeInTheDocument()
})
