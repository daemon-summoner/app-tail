// SPDX-License-Identifier: MIT

import { fireEvent, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import type { Approvals } from '../api'
import {
  deferred,
  failWith,
  makeApprovalNeed,
  makeApprovals,
  renderAgent,
  settle,
} from '../test/agent'
import { ApprovalBanner } from './ApprovalBanner'

const COMMAND = "sudo app-tail tun grant --full-tunnel '--route=203.0.113.0/24'"
const FULL_TUNNEL = "carry all of this machine's internet traffic through app-tail"
const ROUTE = 'send 203.0.113.0/24 through app-tail'
const INTERCEPT = 'open encrypted connections and read what they carry'

/** Three changes from three parts of app-tail, which is what a machine set up all at once
 *  has waiting the first time it runs. */
function pending(): Approvals {
  return makeApprovals({
    needs: [
      makeApprovalNeed({ kind: 'full-tunnel', reason: FULL_TUNNEL, features: ['interface'] }),
      makeApprovalNeed({ kind: 'route', value: '203.0.113.0/24', reason: ROUTE, features: ['fabric'] }),
      makeApprovalNeed({ kind: 'tls-interception', reason: INTERCEPT, features: ['tls-interception'] }),
    ],
    command: COMMAND,
  })
}

const NOTHING_LEFT: Approvals = { needs: [], command: '' }

describe('the approval banner', () => {
  // The reasons are the whole point: an administrator asked to approve has to see what they
  // are approving before the system prompt asks for a password.
  it('lists every change waiting, and the terminal line that approves them', async () => {
    const { getByRole } = await renderAgent(
      <ApprovalBanner approvals={pending()} onApproved={() => {}} />,
    )

    const banner = getByRole('region', { name: 'Needs your approval' })
    const listed = within(banner)
      .getAllByRole('listitem')
      .map((li) => li.textContent)
    expect(listed).toEqual([FULL_TUNNEL, ROUTE, INTERCEPT])
    expect(banner).toHaveTextContent('Prefer the terminal?')
    expect(banner).toHaveTextContent(COMMAND)
    expect(within(banner).getByRole('button', { name: 'Approve…' })).toBeEnabled()
  })

  it('shows nothing while nothing is waiting', async () => {
    const absent = await renderAgent(<ApprovalBanner approvals={undefined} onApproved={() => {}} />)
    expect(absent.queryByRole('region', { name: 'Needs your approval' })).not.toBeInTheDocument()
    expect(absent.container).toBeEmptyDOMElement()

    const empty = await renderAgent(<ApprovalBanner approvals={NOTHING_LEFT} onApproved={() => {}} />)
    expect(empty.container).toBeEmptyDOMElement()
  })

  // The request is held open for as long as the password prompt is on screen, which can be a
  // minute. A button that stayed live would invite a second prompt on top of the first.
  it('approves through the agent, waits visibly, and goes away once nothing is left', async () => {
    const answer = deferred<Approvals>()
    const onApproved = vi.fn()
    const { agent, getByRole, container } = await renderAgent(
      <ApprovalBanner approvals={pending()} onApproved={onApproved} />,
      { 'POST /api/tun/approve': () => answer.promise },
    )

    fireEvent.click(getByRole('button', { name: 'Approve…' }))
    await settle()

    const waiting = getByRole('button', { name: 'Waiting for approval…' })
    expect(waiting).toBeDisabled()
    expect(waiting).toHaveAttribute('aria-busy', 'true')
    expect(agent.countOf('POST /api/tun/approve')).toBe(1)
    expect(agent.calls.find((c) => c.url === '/api/tun/approve')?.body).toBeUndefined()

    answer.resolve(NOTHING_LEFT)
    await settle()

    // Gone on the agent's answer alone: the parent's status has not been read again yet.
    expect(container).toBeEmptyDOMElement()
    expect(onApproved).toHaveBeenCalledTimes(1)
  })

  // Something new can arrive between the page's last poll and the approval; the banner shows
  // what the agent says is still waiting rather than assuming the slate is clean.
  it('keeps showing what is still waiting after an approval', async () => {
    const left = makeApprovals({
      needs: [makeApprovalNeed({ kind: 'system-dns', reason: 'answer every DNS question on this machine', features: ['system-dns'] })],
      command: 'sudo app-tail tun grant --system-dns',
    })
    const { getByRole } = await renderAgent(
      <ApprovalBanner approvals={pending()} onApproved={() => {}} />,
      { 'POST /api/tun/approve': left },
    )

    fireEvent.click(getByRole('button', { name: 'Approve…' }))
    await settle()

    const banner = getByRole('region', { name: 'Needs your approval' })
    expect(within(banner).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      'answer every DNS question on this machine',
    ])
    expect(banner).toHaveTextContent('sudo app-tail tun grant --system-dns')
    expect(banner).not.toHaveTextContent(FULL_TUNNEL)
  })

  // The answer to one approval must not outlive the next poll: whatever the agent reports
  // afterwards is what is waiting.
  it('follows a newer status once one arrives', async () => {
    const onApproved = vi.fn()
    const { getByRole, rerender, container } = await renderAgent(
      <ApprovalBanner approvals={pending()} onApproved={onApproved} />,
      { 'POST /api/tun/approve': NOTHING_LEFT },
    )
    fireEvent.click(getByRole('button', { name: 'Approve…' }))
    await settle()
    expect(container).toBeEmptyDOMElement()

    rerender(
      <ApprovalBanner
        approvals={makeApprovals({ needs: [makeApprovalNeed({ reason: 'a change asked for later' })] })}
        onApproved={onApproved}
      />,
    )

    expect(getByRole('region', { name: 'Needs your approval' })).toHaveTextContent(
      'a change asked for later',
    )
  })

  // Cancelling the prompt is a choice, not a fault: it reads as a notice, and the button stays
  // so they can change their mind.
  it('says the prompt was cancelled without calling it a failure, and offers it again', async () => {
    const message = 'The administrator password prompt was cancelled, so nothing was approved.'
    const onApproved = vi.fn()
    const { getByRole, queryByRole } = await renderAgent(
      <ApprovalBanner approvals={pending()} onApproved={onApproved} />,
      { 'POST /api/tun/approve': failWith(409, message) },
    )

    fireEvent.click(getByRole('button', { name: 'Approve…' }))
    await settle()

    const banner = getByRole('region', { name: 'Needs your approval' })
    expect(within(banner).getByRole('status')).toHaveTextContent(message)
    expect(queryByRole('alert')).not.toBeInTheDocument()
    expect(within(banner).getByRole('button', { name: 'Approve…' })).toBeEnabled()
    expect(within(banner).getAllByRole('listitem')).toHaveLength(3)
    expect(onApproved).not.toHaveBeenCalled()
  })

  // Linux and Windows have no prompt the dashboard can raise; the agent's message names the
  // command to run instead.
  it('passes on what to run where the dashboard cannot ask for administrator rights', async () => {
    const message = `This system cannot ask for administrator rights from the dashboard. Run: ${COMMAND}`
    const { getByRole } = await renderAgent(
      <ApprovalBanner approvals={pending()} onApproved={() => {}} />,
      { 'POST /api/tun/approve': failWith(501, message) },
    )

    fireEvent.click(getByRole('button', { name: 'Approve…' }))
    await settle()

    expect(getByRole('alert')).toHaveTextContent(message)
    expect(getByRole('region', { name: 'Needs your approval' })).toBeInTheDocument()
  })

  it('shows why an approval failed, apart from a cancelled prompt', async () => {
    const message = 'the root helper is not installed'
    const { getByRole, queryByRole } = await renderAgent(
      <ApprovalBanner approvals={pending()} onApproved={() => {}} />,
      { 'POST /api/tun/approve': failWith(500, message) },
    )

    fireEvent.click(getByRole('button', { name: 'Approve…' }))
    await settle()

    expect(getByRole('alert')).toHaveTextContent(`Could not approve: ${message}`)
    expect(queryByRole('status')).not.toBeInTheDocument()
    expect(getByRole('button', { name: 'Approve…' })).toBeEnabled()
  })

  // One OpenVPN server reached with two different certificate authorities is two separate
  // approvals; React keys that ignored the pin would have it render one row twice or drop
  // one when the list changes.
  it('keeps two needs for the same server apart when their certificate pins differ', async () => {
    const first = 'connect to vpn.example.com:1194 trusting CA aaaa'
    const second = 'connect to vpn.example.com:1194 trusting CA bbbb'
    const both = makeApprovals({
      needs: [
        makeApprovalNeed({ kind: 'openvpn-remote', value: 'vpn.example.com:1194', caSha256: ['aaaa'], reason: first }),
        makeApprovalNeed({ kind: 'openvpn-remote', value: 'vpn.example.com:1194', caSha256: ['bbbb'], reason: second }),
      ],
      command: COMMAND,
    })
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const { getByRole } = await renderAgent(<ApprovalBanner approvals={both} onApproved={() => {}} />)
      const listed = within(getByRole('region', { name: 'Needs your approval' }))
        .getAllByRole('listitem')
        .map((li) => li.textContent)
      expect(listed).toEqual([first, second])
      expect(errors.mock.calls.flat().join(' ')).not.toMatch(/same key/)
    } finally {
      errors.mockRestore()
    }
  })

  describe('on the page of the feature that asked', () => {
    it('leads with that feature, and says what else the same approval covers', async () => {
      const { getByRole } = await renderAgent(
        <ApprovalBanner approvals={pending()} feature="tls-interception" onApproved={() => {}} />,
      )

      const banner = getByRole('region', { name: 'Needs your approval' })
      const lists = within(banner).getAllByRole('list')
      expect(lists).toHaveLength(2)
      expect(within(lists[0]!).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
        INTERCEPT,
      ])
      expect(banner).toHaveTextContent('The same approval also covers')
      expect(within(lists[1]!).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
        FULL_TUNNEL,
        ROUTE,
      ])
    })

    it('shows nothing when this feature is not among the changes waiting', async () => {
      const { container } = await renderAgent(
        <ApprovalBanner approvals={pending()} feature="openvpn:tn_office" onApproved={() => {}} />,
      )

      expect(container).toBeEmptyDOMElement()
    })
  })
})
