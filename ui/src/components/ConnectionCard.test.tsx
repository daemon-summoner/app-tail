// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { deferred, failWith, makeStatus, renderAgent, settle } from '../test/agent'
import { ConnectionCard } from './ConnectionCard'
import type { Status } from '../api'

function card(status: Status, onChanged = () => {}, onSetupTags = () => {}) {
  return <ConnectionCard status={status} onChanged={onChanged} onSetupTags={onSetupTags} />
}

// What the agent answers when the card asks for the login already in progress. The status
// says only that one is waiting: the URL that completes an enrolment is handed over by a
// request of its own.
const pendingLogin = { authURL: 'https://login.tailscale.com/a/abc', backendState: 'NeedsLogin' }

// The state line is the first thing read on the page. Every one of these words means
// a different next action, so falling through to the raw backend enum -- or to the
// wrong branch -- sends the user somewhere unhelpful.
describe('what the card calls each backend state', () => {
  it.each([
    ['Running', true, 'Connected'],
    ['Starting', false, 'Connecting'],
    ['NeedsLogin', false, 'Not signed in'],
    ['NeedsMachineAuth', false, 'Waiting for device approval'],
    ['Stopped', false, 'Stopped'],
    // An enum this dashboard has not been taught yet is still shown, verbatim,
    // rather than swallowed.
    ['NoState', false, 'NoState'],
    ['', false, 'Unknown'],
  ])('renders %s as %s', async (backendState, running, label) => {
    const { container } = await renderAgent(card(makeStatus({ backendState, running })))

    expect(container.querySelector('.panel-head .status')).toHaveTextContent(label)
  })
})

// The tone is read from `running`, which is the agent's own answer to "is the
// tailnet actually usable". backendState can say Running while the node has no
// usable address, and a green dot there tells the user to stop debugging.
describe('the colour the state gets', () => {
  it.each([
    ['a node that is really up', { backendState: 'Running', running: true }, 'running'],
    ['a node still coming up', { backendState: 'Starting', running: false }, 'pending'],
    ['a node that needs a login', { backendState: 'NeedsLogin', running: false }, 'error'],
    // The case the plain-enum reading gets wrong.
    ['a node the control plane calls Running but is not', { backendState: 'Running', running: false }, 'error'],
  ])('shows %s as %s', async (_case, overrides, tone) => {
    const { container } = await renderAgent(card(makeStatus(overrides)))

    expect(container.querySelector('.panel-head .status')).toHaveClass('status', tone)
  })
})

describe('the sign-in and sign-out button', () => {
  it('offers sign-out on a connected node and logs out through the agent', async () => {
    const onChanged = vi.fn()
    const { getByRole, queryByRole, agent } = await renderAgent(
      card(makeStatus({ running: true }), onChanged),
      { 'POST /api/logout': { backendState: 'Stopped' } },
    )

    expect(queryByRole('button', { name: /Sign in/ })).not.toBeInTheDocument()
    fireEvent.click(getByRole('button', { name: 'Sign out' }))
    await settle()

    expect(agent.countOf('POST /api/logout')).toBe(1)
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  it('offers sign-in on a disconnected node and starts a login', async () => {
    const onChanged = vi.fn()
    const { getByRole, agent } = await renderAgent(
      card(makeStatus({ backendState: 'NeedsLogin', running: false }), onChanged),
      { 'POST /api/login': { authURL: 'https://login.tailscale.com/a/abc', backendState: 'NeedsLogin' } },
    )

    fireEvent.click(getByRole('button', { name: 'Sign in to tailnet' }))
    await settle()

    expect(agent.countOf('POST /api/login')).toBe(1)
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  // A login link expires. Once one is already on screen the button's job is issuing
  // a fresh one, and calling it "Sign in" reads as if the first attempt was ignored.
  it('renames itself once a sign-in link is already showing', async () => {
    const { getByRole } = await renderAgent(
      card(makeStatus({ backendState: 'NeedsLogin', running: false, authPending: true })),
      { 'POST /api/login/url': pendingLogin },
    )
    await settle()

    expect(getByRole('button', { name: 'New sign-in link' })).toBeInTheDocument()
  })

  // Both calls take a round trip through tailscaled. Without the disable, a second
  // click starts a second login while the first is still running.
  it('cannot be pressed twice while the agent is working', async () => {
    const pending = deferred<void>()
    const { getByRole } = await renderAgent(card(makeStatus({ running: true })), {
      'POST /api/logout': () => pending.promise.then(() => ({ backendState: 'Stopped' })),
    })

    const button = getByRole('button', { name: 'Sign out' })
    fireEvent.click(button)
    await settle(1)

    expect(button).toBeDisabled()

    pending.resolve()
    await settle()

    expect(button).toBeEnabled()
  })

  it('reports a refused sign-out instead of appearing to do nothing', async () => {
    const onChanged = vi.fn()
    const { getByRole, getByText } = await renderAgent(
      card(makeStatus({ running: true }), onChanged),
      { 'POST /api/logout': failWith(500, 'tailscaled is not responding') },
    )

    fireEvent.click(getByRole('button', { name: 'Sign out' }))
    await settle()

    expect(getByText('tailscaled is not responding')).toBeInTheDocument()
    expect(onChanged).not.toHaveBeenCalled()
  })
})

// The QR block needs BOTH halves of its condition. Dropping the running check leaves
// a working node showing a login code -- scanning it re-enrols the device. Dropping
// the link check renders a QR for an empty string.
describe('the sign-in code', () => {
  // The status says a login is waiting and nothing more, so the code on screen can only
  // have come from the request that hands the URL over.
  it('appears for a node that is waiting to be signed in', async () => {
    const { container, getByRole, agent } = await renderAgent(
      card(makeStatus({ backendState: 'NeedsLogin', running: false, authPending: true })),
      { 'POST /api/login/url': pendingLogin },
    )
    await settle()

    expect(agent.countOf('POST /api/login/url')).toBe(1)
    expect(container.querySelector('.qr svg')).toBeInTheDocument()
    expect(getByRole('link', { name: 'https://login.tailscale.com/a/abc' })).toHaveAttribute(
      'href',
      'https://login.tailscale.com/a/abc',
    )
  })

  it.each([
    ['the node is already connected', { running: true, backendState: 'Running', authPending: true }],
    [
      'the node is still starting',
      { running: false, backendState: 'Starting', authPending: true },
    ],
    ['there is no link to show', { running: false, backendState: 'NeedsLogin' }],
  ])('stays hidden when %s', async (_case, overrides) => {
    const { container } = await renderAgent(card(makeStatus(overrides)), {
      'POST /api/login/url': pendingLogin,
    })
    await settle()

    expect(container.querySelector('.qr')).not.toBeInTheDocument()
  })
})

describe('the identity it reports', () => {
  it('shows the name, addresses, account and tags the node is joined as', async () => {
    const { container } = await renderAgent(
      card(
        makeStatus({
          dnsName: 'app-tail-box.tail1234.ts.net',
          tailscaleIps: ['100.64.0.2', 'fd7a::2'],
          loginName: 'someone@example.com',
          tags: ['tag:app-tail', 'tag:prod'],
          authMode: 'oauth',
        }),
      ),
    )

    const detail = container.querySelector('.detail')
    expect(detail).toHaveTextContent('app-tail-box.tail1234.ts.net')
    expect(detail).toHaveTextContent('100.64.0.2')
    expect(detail).toHaveTextContent('fd7a::2')
    expect(detail).toHaveTextContent('someone@example.com')
    expect(detail).toHaveTextContent('tag:app-tail tag:prod')
    // How the node authenticates decides whether it can re-enrol unattended, so it
    // is shown even when everything else is absent.
    expect(detail).toHaveTextContent('auth: oauth')
  })

  it('shows only the auth mode on a node that has never connected', async () => {
    const { container } = await renderAgent(
      card(
        makeStatus({
          backendState: 'NeedsLogin',
          running: false,
          authMode: 'interactive',
          dnsName: '',
          loginName: '',
          tags: [],
          tailscaleIps: [],
        }),
      ),
    )

    expect(container.querySelector('.detail')).toHaveTextContent('auth: interactive')
    expect(container.querySelector('.detail .mono')).not.toBeInTheDocument()
  })

  // The diagnosis is the only thing explaining why a node will not come up -- an
  // expired key, a tag the tailnet does not define. Hiding it leaves "Not signed in"
  // and nothing else.
  it('surfaces the diagnosis while the node is down', async () => {
    const { getByText } = await renderAgent(
      card(
        makeStatus({
          backendState: 'NeedsLogin',
          running: false,
          problem: 'requested tags [tag:app-tail] are invalid or not permitted',
        }),
      ),
    )

    expect(getByText(/requested tags/)).toBeInTheDocument()
  })

  // A problem left over from before the node came up would otherwise sit on a
  // healthy card forever.
  it('drops the diagnosis once the node is up', async () => {
    const { queryByText } = await renderAgent(
      card(makeStatus({ running: true, problem: 'a stale complaint' })),
    )

    expect(queryByText('a stale complaint')).not.toBeInTheDocument()
  })

  it('opens tag setup from the card', async () => {
    const onSetupTags = vi.fn()
    const { getByRole } = await renderAgent(card(makeStatus(), () => {}, onSetupTags))

    fireEvent.click(getByRole('button', { name: 'Tag setup' }))

    expect(onSetupTags).toHaveBeenCalledTimes(1)
  })
})

// The device name, the credentials and everything else this connection enrolled with are
// the connection's own settings and live on its page. This card says what the connection
// is doing, so the way to what it is set to has to be on it -- otherwise the settings that
// moved are reachable only by someone who knows the connections section exists.
it('points at the page holding this connection’s own settings', async () => {
  const { getByRole } = await renderAgent(card(makeStatus({ tunnelId: 'tn_primary' })))

  expect(getByRole('link', { name: 'Settings' })).toHaveAttribute(
    'href',
    '#/connections/tailscale/tn_primary',
  )
})
