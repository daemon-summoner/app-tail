// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import {
  deferred,
  failWith,
  makeForward,
  makePeer,
  makePreset,
  makeSettings,
  makeTunnel,
  netFail,
  renderAgent,
  settle,
  tunnelRoutes,
} from '../test/agent'
import type { AgentCall, AgentView, Routes } from '../test/agent'
import { ForwardDialog } from './ForwardDialog'
import type { Forward, ForwardSpec, PeerState } from '../api'

/** open mounts the dialog in add mode unless a forward to edit is given. */
async function open(
  routes: Routes = {},
  editing?: Forward,
  handlers: { onClose?: () => void; onSaved?: () => void } = {},
): Promise<AgentView> {
  return renderAgent(
    <ForwardDialog
      editing={editing}
      onClose={handlers.onClose ?? (() => {})}
      onSaved={handlers.onSaved ?? (() => {})}
    />,
    routes,
  )
}

/** fill types into a labelled control. */
function fill(view: AgentView, label: string | RegExp, value: string): void {
  fireEvent.change(view.getByLabelText(label), { target: { value } })
}

function save(view: AgentView): void {
  fireEvent.click(view.getByRole('button', { name: 'Create forward' }))
}

/** A single created forward, so a create route only has to exist. */
const created = makeForward()

describe('what the dialog refuses to send', () => {
  it.each([
    [
      'no port at all',
      (view: AgentView) => fill(view, 'Host', 'gpu-box'),
      'Enter at least one port.',
    ],
    [
      'a port that is not a number',
      (view: AgentView) => {
        fill(view, 'Host', 'gpu-box')
        fill(view, /^Port\(s\)/, 'ssh')
      },
      '"ssh" is not a port or range. Try e.g. 8100, 9000-9005.',
    ],
    [
      'a port outside the valid range',
      (view: AgentView) => {
        fill(view, 'Host', 'gpu-box')
        fill(view, /^Port\(s\)/, '70000')
      },
      '"70000" is not a valid port (1-65535).',
    ],
    [
      'a backwards range',
      (view: AgentView) => {
        fill(view, 'Host', 'gpu-box')
        fill(view, /^Port\(s\)/, '9005-9000')
      },
      'Range "9005-9000" is backwards; put the lower port first.',
    ],
    [
      'no device and no host',
      (view: AgentView) => fill(view, /^Port\(s\)/, '22'),
      'Choose a device or enter a host.',
    ],
    [
      'a listen port override out of range',
      (view: AgentView) => {
        fill(view, 'Host', 'gpu-box')
        fill(view, /^Port\(s\)/, '22')
        fill(view, 'Local port', '70000')
      },
      'The listen port override must be 1-65535.',
    ],
  ])('refuses %s', async (_case, prepare, message) => {
    const onSaved = vi.fn()
    const view = await open({}, undefined, { onSaved })

    prepare(view)
    save(view)
    await settle()

    // The notice specifically: a bad port spec also renders an inline hint under the
    // field, and matching either one would let a missing notice pass.
    expect(view.container.querySelector('.notice.error')).toHaveTextContent(message)
    // Nothing reached the agent: a refusal that still posted would create a broken
    // forward and then complain about it.
    expect(view.agent.countOf('POST /api/forwards')).toBe(0)
    expect(onSaved).not.toHaveBeenCalled()
  })

  // "Specific IP" with nothing typed would post an empty bindAddr, which the agent
  // reads as loopback -- the opposite of asking for one particular interface.
  it('refuses a specific-interface bind with no IP typed', async () => {
    const view = await open()

    fill(view, 'Host', 'gpu-box')
    fill(view, /^Port\(s\)/, '22')
    fireEvent.change(view.getByLabelText('Bind address'), { target: { value: '__bind_custom__' } })
    save(view)
    await settle()

    expect(
      view.getByText('Enter an IP for the specific interface, or pick Loopback or All interfaces.'),
    ).toBeInTheDocument()
    expect(view.agent.countOf('POST /api/forwards')).toBe(0)
  })

  // effectiveHost() substitutes 127.0.0.1 for a blank to_tailnet host, so the
  // "Enter the local service host." branch in validate() can never be reached. What
  // actually happens is that a blank field silently publishes loopback -- which is
  // the right default, but it is the behaviour, not the message, that is real.
  it('publishes loopback when the local service host is left blank', async () => {
    const view = await open({ 'POST /api/forwards': created })

    fireEvent.change(view.getByLabelText('Direction'), { target: { value: 'to_tailnet' } })
    fill(view, /^Port\(s\)/, '3000')
    save(view)
    await settle()

    expect(view.agent.bodyOf<ForwardSpec>('POST /api/forwards').target).toBe('127.0.0.1:3000')
  })
})

describe('creating one forward', () => {
  // A local port that is already taken makes the forward fail to bind the moment it
  // is created. Asking the agent for a free one is what makes the common case work
  // without the user having to know what is listening on this machine.
  it('asks the agent for a bindable local port and uses it', async () => {
    const onSaved = vi.fn()
    const onClose = vi.fn()
    const view = await open(
      { 'GET /api/forwards/suggest-port': { port: 41007 }, 'POST /api/forwards': created },
      undefined,
      { onSaved, onClose },
    )

    fill(view, 'Host', 'gpu-box')
    fill(view, /^Port\(s\)/, '22')
    save(view)
    await settle()

    expect(view.agent.urlOf('GET /api/forwards/suggest-port')).toBe(
      '/api/forwards/suggest-port?protocol=tcp&target=gpu-box%3A22&bindAddr=127.0.0.1',
    )
    expect(view.agent.bodyOf<ForwardSpec>('POST /api/forwards')).toEqual({
      name: '',
      tunnelId: 'tn_primary',
      direction: 'to_local',
      protocol: 'tcp',
      listenPort: 41007,
      target: 'gpu-box:22',
      udpTimeoutSec: 0,
      bindAddr: '127.0.0.1',
      exposeToNetwork: false,
    })
    expect(onSaved).toHaveBeenCalledTimes(1)
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  // The suggestion is a convenience. An agent that cannot answer it must not block
  // the create -- mirroring the service port is a perfectly good forward.
  it('mirrors the service port when the agent cannot suggest one', async () => {
    const view = await open({
      'GET /api/forwards/suggest-port': failWith(503, 'the port scanner is unavailable'),
      'POST /api/forwards': created,
    })

    fill(view, 'Host', 'gpu-box')
    fill(view, /^Port\(s\)/, '22')
    save(view)
    await settle()

    expect(view.agent.bodyOf<ForwardSpec>('POST /api/forwards').listenPort).toBe(22)
  })

  // A port the user typed themselves is a decision, not a suggestion; asking the
  // agent anyway would silently move the forward off the port they chose.
  it('never asks for a suggestion when a local port was typed', async () => {
    const view = await open({ 'POST /api/forwards': created })

    fill(view, 'Host', 'gpu-box')
    fill(view, /^Port\(s\)/, '22')
    fill(view, 'Local port', '9022')
    save(view)
    await settle()

    expect(view.agent.countOf('GET /api/forwards/suggest-port')).toBe(0)
    expect(view.agent.bodyOf<ForwardSpec>('POST /api/forwards').listenPort).toBe(9022)
  })

  // A published port has to stay the number the user told their colleagues; there is
  // no local conflict to dodge on the tailnet side.
  it('never asks for a suggestion for a service it is exposing', async () => {
    const view = await open({ 'POST /api/forwards': created })

    fireEvent.change(view.getByLabelText('Direction'), { target: { value: 'to_tailnet' } })
    fill(view, 'Local service host', '127.0.0.1')
    fill(view, /^Port\(s\)/, '3000')
    save(view)
    await settle()

    expect(view.agent.countOf('GET /api/forwards/suggest-port')).toBe(0)
    const spec = view.agent.bodyOf<ForwardSpec>('POST /api/forwards')
    expect(spec.listenPort).toBe(3000)
    // bindAddr is a to_local concept; sending it here would bind the tailnet
    // listener to a local interface.
    expect(spec).not.toHaveProperty('bindAddr')
  })

  it('sends a UDP idle timeout only when the user set one', async () => {
    const view = await open({ 'POST /api/forwards': created })

    fireEvent.change(view.getByLabelText('Protocol'), { target: { value: 'udp' } })
    fill(view, 'Host', 'gpu-box')
    fill(view, /^Port\(s\)/, '53')
    fill(view, 'UDP session timeout (seconds)', '30')
    fill(view, 'Local port', '5353')
    save(view)
    await settle()

    expect(view.agent.bodyOf<ForwardSpec>('POST /api/forwards').udpTimeoutSec).toBe(30)
  })
})

describe('creating a range of forwards', () => {
  it('creates one forward per port and appends the port to each name', async () => {
    const view = await open({ 'POST /api/forwards': created })

    fill(view, /^Name/, 'web')
    fill(view, 'Host', 'gpu-box')
    fill(view, /^Port\(s\)/, '9000-9002')
    save(view)
    await settle()

    expect(view.agent.countOf('POST /api/forwards')).toBe(3)
    // A range mirrors rather than asking for suggestions, so the ports stay
    // predictable across the whole batch.
    expect(view.agent.countOf('GET /api/forwards/suggest-port')).toBe(0)
    for (const [i, port] of [9000, 9001, 9002].entries()) {
      const spec = view.agent.bodyOf<ForwardSpec>('POST /api/forwards', i)
      expect(spec.name).toBe(`web ${port}`)
      expect(spec.listenPort).toBe(port)
      expect(spec.target).toBe(`gpu-box:${port}`)
    }
  })

  // A batch is not atomic: one taken port must not discard the forwards that were
  // created, and the user has to be told exactly which port failed and why, or they
  // cannot tell what to retry.
  it('keeps the forwards it created and names the ones it could not', async () => {
    const onSaved = vi.fn()
    const onClose = vi.fn()
    const view = await open(
      {
        'POST /api/forwards': (call: AgentCall) => {
          const spec = JSON.parse(call.body ?? '{}') as ForwardSpec
          return spec.listenPort === 9001
            ? failWith(409, 'port 9001 is already in use')
            : created
        },
      },
      undefined,
      { onSaved, onClose },
    )

    fill(view, 'Host', 'gpu-box')
    fill(view, /^Port\(s\)/, '9000-9002')
    save(view)
    await settle()

    expect(view.getByText(/Created 2 forwards\./)).toHaveTextContent(
      'Could not add 1: port 9001 (port 9001 is already in use)',
    )
    // The table has to refresh -- two of them are live -- but the dialog stays open
    // so the failure is still readable.
    expect(onSaved).toHaveBeenCalledTimes(1)
    expect(onClose).not.toHaveBeenCalled()
  })

  it('reports a batch where nothing at all could be created', async () => {
    const view = await open({ 'POST /api/forwards': failWith(409, 'already in use') })

    fill(view, 'Host', 'gpu-box')
    fill(view, /^Port\(s\)/, '9000-9001')
    save(view)
    await settle()

    const notice = view.container.querySelector('.notice.error')
    expect(notice).toHaveTextContent('Could not add 2:')
    expect(notice).not.toHaveTextContent('Created')
  })
})

describe('editing an existing forward', () => {
  const editing = makeForward({
    id: 'fwd-ssh',
    name: 'ssh',
    target: 'gpu-box:22',
    listenPort: 2222,
    bindAddr: '127.0.0.1',
  })

  it('opens on the values the forward already has', async () => {
    const view = await open({}, editing)

    expect(view.getByRole('dialog')).toHaveAccessibleName('Edit forward')
    expect(view.getByLabelText(/^Name/)).toHaveValue('ssh')
    expect(view.getByLabelText('Host')).toHaveValue('gpu-box')
    expect(view.getByLabelText(/^Port\(s\)/)).toHaveValue('22')
    // The listen port is shown only because it differs from the service port.
    expect(view.getByLabelText('Local port')).toHaveValue(2222)
  })

  // Leaving the override blank means "same as the service port". Prefilling it with
  // the matching number would turn an implicit mirror into a pinned value, which
  // then stops tracking the service port if the user edits it.
  it('leaves the listen port blank when it already mirrors the service port', async () => {
    const view = await open({}, makeForward({ target: 'gpu-box:22', listenPort: 22 }))

    expect(view.getByLabelText('Local port')).toHaveValue(null)
    expect(view.getByLabelText('Local port')).toHaveAttribute('placeholder', 'same (22)')
  })

  it('updates in place rather than creating a second forward', async () => {
    const onSaved = vi.fn()
    const onClose = vi.fn()
    const view = await open({ 'PUT /api/forwards/fwd-ssh': created }, editing, { onSaved, onClose })

    fill(view, /^Name/, 'ssh to gpu')
    fireEvent.click(view.getByRole('button', { name: 'Save changes' }))
    await settle()

    expect(view.agent.countOf('POST /api/forwards')).toBe(0)
    expect(view.agent.bodyOf<ForwardSpec>('PUT /api/forwards/fwd-ssh')).toEqual({
      name: 'ssh to gpu',
      tunnelId: 'tn_primary',
      direction: 'to_local',
      protocol: 'tcp',
      listenPort: 2222,
      target: 'gpu-box:22',
      udpTimeoutSec: 0,
      bindAddr: '127.0.0.1',
      exposeToNetwork: false,
    })
    expect(onSaved).toHaveBeenCalledTimes(1)
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  // "Port already in use" is useless on its own when the user cannot see which of
  // their own rules is holding it.
  it('names the forward already holding the port', async () => {
    const view = await open(
      {
        'PUT /api/forwards/fwd-ssh': failWith(409, 'port 2222 is already in use', {
          endpoint: 'tcp 127.0.0.1:2222',
          forwardId: 'fwd-other',
          name: 'old ssh',
        }),
      },
      editing,
    )

    fireEvent.click(view.getByRole('button', { name: 'Save changes' }))
    await settle()

    expect(view.container.querySelector('.notice.error')).toHaveTextContent(
      'port 2222 is already in use (conflicting forward: fwd-other)',
    )
  })

  // Edit keeps the device dropdown on manual entry: the stored target may name a
  // host that is not a tailnet peer at all, and re-deriving it from the peer list
  // would silently retarget the forward on open.
  it('keeps the stored target rather than re-picking a device', async () => {
    const view = await open(
      { 'GET /api/tunnels/tn_primary/peers': { peers: [makePeer({ dnsName: 'other.tail1234.ts.net' })] } },
      makeForward({ target: '192.168.1.10:8080', listenPort: 8080 }),
    )

    expect(view.getByLabelText('Host')).toHaveValue('192.168.1.10')
  })
})

describe('picking the device to reach', () => {
  const peers = [
    makePeer({
      id: 'p-fleet',
      hostName: 'gpu-box',
      dnsName: 'gpu-box.tail1234.ts.net',
      tags: ['tag:app-tail'],
    }),
    makePeer({
      id: 'p-other',
      hostName: 'laptop',
      dnsName: 'laptop.tail1234.ts.net',
      ips: ['100.64.0.9'],
    }),
  ]

  // The fleet grouping is what tells the user which devices are running app-tail and
  // can therefore answer a forward at all.
  it('separates this fleet from the rest of the tailnet', async () => {
    const view = await open({
      'GET /api/tunnels/tn_primary/peers': { peers },
      'GET /api/settings': makeSettings({ tags: ['tag:app-tail'] }),
    })

    const groups = view.container.querySelectorAll('optgroup')
    expect(groups[0]).toHaveAttribute('label', 'app-tail devices')
    expect(groups[0]).toHaveTextContent('gpu-box')
    expect(groups[1]).toHaveAttribute('label', 'Other devices')
    expect(groups[1]).toHaveTextContent('laptop')
  })

  // Falling back to the built-in tag rather than showing no fleet at all: settings
  // are a badge input, and a failed load must not reclassify every device.
  it('groups by the built-in tag when settings cannot be read', async () => {
    const view = await open({ 'GET /api/tunnels/tn_primary/peers': { peers }, 'GET /api/settings': netFail() })

    expect(view.container.querySelector('optgroup')).toHaveAttribute('label', 'app-tail devices')
  })

  // A peer's IP changes when it re-registers; its DNS name does not. Targeting the
  // IP leaves a forward that quietly stops working weeks later.
  it('targets a device by DNS name when it has one', async () => {
    const view = await open({
      'GET /api/tunnels/tn_primary/peers': { peers },
      'POST /api/forwards': created,
      'GET /api/forwards/suggest-port': { port: 41000 },
    })

    fireEvent.change(view.getByLabelText('Device'), {
      target: { value: 'gpu-box.tail1234.ts.net' },
    })
    fill(view, /^Port\(s\)/, '22')
    save(view)
    await settle()

    expect(view.agent.bodyOf<ForwardSpec>('POST /api/forwards').target).toBe(
      'gpu-box.tail1234.ts.net:22',
    )
  })

  it.each([
    ['an IP when there is no DNS name', { dnsName: '', ips: ['100.64.0.7'] }, '100.64.0.7'],
    ['the host name when there is neither', { dnsName: '', ips: [] }, 'gpu-box'],
  ])('falls back to %s', async (_case, overrides, want) => {
    const view = await open({
      'GET /api/tunnels/tn_primary/peers': { peers: [makePeer({ hostName: 'gpu-box', ...overrides })] },
    })

    expect(view.getByRole('option', { name: new RegExp(want) })).toHaveValue(want)
  })

  it('marks a peer that is currently offline', async () => {
    const view = await open({
      'GET /api/tunnels/tn_primary/peers': { peers: [makePeer({ hostName: 'gpu-box', online: false })] },
    })

    expect(view.getByRole('option', { name: /gpu-box/ })).toHaveTextContent('(offline)')
  })

  // The agent's verdict has to beat `online`, because the case it exists for is exactly
  // the one where they disagree: the tailnet reports the device up and this node cannot
  // reach it. Picking such a device silently produces a forward that never connects.
  it.each<[PeerState, string]>([
    ['no-path', 'unreachable'],
    ['expired', 'key expired'],
    ['relayed', 'relayed'],
  ])('marks an online peer the agent reports as %s', async (state, want) => {
    const view = await open({
      'GET /api/tunnels/tn_primary/peers': {
        peers: [makePeer({ hostName: 'gpu-box', online: true, reach: { state } })],
      },
    })

    expect(view.getByRole('option', { name: /gpu-box/ })).toHaveTextContent(`(${want})`)
  })

  // A dashboard bundle can be older than the agent serving it. An unknown state must
  // show up verbatim rather than fall through to looking healthy, which is the one
  // outcome that would put this dropdown back to lying about a device.
  it('shows a state this bundle does not know rather than hiding it', async () => {
    const view = await open({
      'GET /api/tunnels/tn_primary/peers': {
        peers: [
          makePeer({ hostName: 'gpu-box', online: true, reach: { state: 'quarantined' as PeerState } }),
        ],
      },
    })

    expect(view.getByRole('option', { name: /gpu-box/ })).toHaveTextContent('(quarantined)')
  })

  it('leaves a healthy peer unmarked so the marked ones stand out', async () => {
    const view = await open({
      'GET /api/tunnels/tn_primary/peers': {
        peers: [makePeer({ hostName: 'gpu-box', online: true, reach: { state: 'ready' } })],
      },
    })

    expect(view.getByRole('option', { name: /gpu-box/ })).not.toHaveTextContent('(')
  })

  // Both of these leave the user with no device list. Without the fallback the
  // dialog offers an empty dropdown and no way to type a host, so no forward can be
  // created at all until the tailnet comes up.
  it.each([
    ['the tailnet has no other devices', { 'GET /api/tunnels/tn_primary/peers': { peers: [] } }],
    ['the agent cannot list them', { 'GET /api/tunnels/tn_primary/peers': netFail() }],
  ])('falls back to typing a host when %s', async (_case, routes) => {
    const view = await open(routes)

    expect(view.getByLabelText('Host')).toBeInTheDocument()
  })

  it('offers manual entry even when devices are available', async () => {
    const view = await open({ 'GET /api/tunnels/tn_primary/peers': { peers } })

    expect(view.queryByLabelText('Host')).not.toBeInTheDocument()
    fireEvent.change(view.getByLabelText('Device'), { target: { value: '__manual__' } })

    expect(view.getByLabelText('Host')).toBeInTheDocument()
  })
})

describe('choosing which network the forward crosses', () => {
  const twoConnections = tunnelRoutes([
    makeTunnel(),
    makeTunnel({ id: 'tn_office', name: 'Office', slug: 'office' }),
  ])

  // With one network there is nothing to choose, and a picker with a single option is a
  // decision put to the user that has only one answer.
  it('asks nothing when there is only one network to be on', async () => {
    const view = await open()

    expect(view.queryByLabelText('Connection')).not.toBeInTheDocument()
  })

  it('sends the connection that was chosen', async () => {
    const view = await open({
      ...twoConnections,
      'GET /api/tunnels/tn_office/peers': { peers: [] },
      'POST /api/forwards': created,
      'GET /api/forwards/suggest-port': { port: 41000 },
    })

    fireEvent.change(view.getByLabelText('Connection'), { target: { value: 'tn_office' } })
    await settle()

    fill(view, 'Host', 'db')
    fill(view, /^Port\(s\)/, '5432')
    save(view)
    await settle()

    expect(view.agent.bodyOf<ForwardSpec>('POST /api/forwards').tunnelId).toBe('tn_office')
  })

  // A device id only means something on the network that issued it. Offering the first
  // network's devices while the second is selected would build a forward pointing at a
  // name the chosen network cannot resolve.
  it('offers the devices on the network that was chosen', async () => {
    const view = await open({
      ...twoConnections,
      'GET /api/tunnels/tn_primary/peers': { peers: [makePeer({ hostName: 'home-nas' })] },
      'GET /api/tunnels/tn_office/peers': { peers: [makePeer({ hostName: 'office-db' })] },
    })

    expect(view.getByRole('option', { name: /home-nas/ })).toBeInTheDocument()

    fireEvent.change(view.getByLabelText('Connection'), { target: { value: 'tn_office' } })
    await settle()

    expect(view.getByRole('option', { name: /office-db/ })).toBeInTheDocument()
    expect(view.queryByRole('option', { name: /home-nas/ })).not.toBeInTheDocument()
  })

  // An edit must keep the forward on the network it is already on: silently moving it to
  // the first connection would repoint every rule the user only meant to rename.
  it('keeps an edited forward on the network it already crosses', async () => {
    const view = await open(
      {
        ...twoConnections,
        'GET /api/tunnels/tn_office/peers': { peers: [] },
        'PUT /api/forwards/fwd-ssh': created,
      },
      makeForward({ tunnelId: 'tn_office', target: 'db:5432' }),
    )

    expect(view.getByLabelText('Connection')).toHaveValue('tn_office')

    fireEvent.click(view.getByRole('button', { name: 'Save changes' }))
    await settle()

    expect(view.agent.bodyOf<ForwardSpec>('PUT /api/forwards/fwd-ssh').tunnelId).toBe('tn_office')
  })
})

describe('choosing what the forward binds to', () => {
  it('starts on loopback with no address to type', async () => {
    const view = await open()

    expect(view.getByLabelText('Bind address')).toHaveValue('127.0.0.1')
    expect(view.queryByLabelText('Bind IP address')).not.toBeInTheDocument()
  })

  it('reveals an empty field when a specific interface is chosen', async () => {
    const view = await open()

    fireEvent.change(view.getByLabelText('Bind address'), { target: { value: '__bind_custom__' } })

    expect(view.getByLabelText('Bind IP address')).toHaveValue('')
  })

  // The clear only fires when leaving a preset. Clearing unconditionally would wipe
  // a typed IP the moment the user re-opened the dropdown and picked the option they
  // were already on -- an ordinary thing to do while double-checking a form.
  it('keeps a typed address when Specific IP is re-selected', async () => {
    const view = await open()
    const dropdown = view.getByLabelText('Bind address')

    fireEvent.change(dropdown, { target: { value: '__bind_custom__' } })
    fill(view, 'Bind IP address', '192.168.1.50')
    fireEvent.change(dropdown, { target: { value: '__bind_custom__' } })

    expect(view.getByLabelText('Bind IP address')).toHaveValue('192.168.1.50')
  })

  it('drops back to a preset without leaving the typed address behind', async () => {
    const view = await open({ 'POST /api/forwards': created })

    fireEvent.change(view.getByLabelText('Bind address'), { target: { value: '__bind_custom__' } })
    fill(view, 'Bind IP address', '192.168.1.50')
    fireEvent.change(view.getByLabelText('Bind address'), { target: { value: '0.0.0.0' } })

    expect(view.queryByLabelText('Bind IP address')).not.toBeInTheDocument()

    fill(view, 'Host', 'gpu-box')
    fill(view, /^Port\(s\)/, '22')
    fill(view, 'Local port', '2222')
    fireEvent.click(view.getByLabelText(/Let other machines on your network use this forward/))
    save(view)
    await settle()

    expect(view.agent.bodyOf<ForwardSpec>('POST /api/forwards').bindAddr).toBe('0.0.0.0')
  })

  // The agent refuses a bind other machines can reach unless the forward says so, and
  // a forward on the LAN with no password is not something to do by picking a dropdown.
  it('refuses a LAN bind until the user agrees to share it', async () => {
    const view = await open({ 'POST /api/forwards': created })

    fireEvent.change(view.getByLabelText('Bind address'), { target: { value: '0.0.0.0' } })
    fill(view, 'Host', 'gpu-box')
    fill(view, /^Port\(s\)/, '22')
    fill(view, 'Local port', '2222')
    save(view)
    await settle()

    expect(view.getByText(/Tick "Let other machines on your network use this forward"/)).toBeInTheDocument()
    expect(view.agent.countOf('POST /api/forwards')).toBe(0)

    fireEvent.click(view.getByLabelText(/Let other machines on your network use this forward/))
    save(view)
    await settle()

    expect(view.agent.bodyOf<ForwardSpec>('POST /api/forwards').exposeToNetwork).toBe(true)
  })

  it('never asks to share a loopback forward, and never marks one shared', async () => {
    const view = await open({ 'POST /api/forwards': created })

    expect(view.queryByLabelText(/Let other machines on your network use this forward/)).not.toBeInTheDocument()
    fill(view, 'Host', 'gpu-box')
    fill(view, /^Port\(s\)/, '22')
    fill(view, 'Local port', '2222')
    save(view)
    await settle()

    expect(view.agent.bodyOf<ForwardSpec>('POST /api/forwards').exposeToNetwork).toBe(false)
  })

  // Binding to every interface puts the forward on the LAN. The hint is the only
  // thing that says so before the user commits.
  it.each([
    ['127.0.0.1', 'Only this machine can reach the forward.'],
    ['0.0.0.0', "Any device on your local network can reach it at this machine's LAN IP."],
  ])('spells out what binding %s means', async (value, hint) => {
    const view = await open()

    fireEvent.change(view.getByLabelText('Bind address'), { target: { value } })

    expect(view.getByText(hint)).toBeInTheDocument()
  })

  it('starts an edited forward on the address it was bound to', async () => {
    const view = await open({}, makeForward({ bindAddr: '192.168.1.50' }))

    expect(view.getByLabelText('Bind address')).toHaveValue('__bind_custom__')
    expect(view.getByLabelText('Bind IP address')).toHaveValue('192.168.1.50')
  })
})

describe('the fields that come and go', () => {
  it.each([
    ['tcp', false],
    ['udp', true],
    ['both', true],
  ])('shows the UDP timeout for %s: %s', async (protocol, shown) => {
    const view = await open()

    fireEvent.change(view.getByLabelText('Protocol'), { target: { value: protocol } })

    const field = view.queryByLabelText('UDP session timeout (seconds)')
    if (shown) expect(field).toBeInTheDocument()
    else expect(field).not.toBeInTheDocument()
  })

  // The override applies to one port; a range always mirrors, so offering the field
  // would let the user set a value that is silently ignored.
  it('offers a listen port override only for a single port', async () => {
    const view = await open()

    fill(view, /^Port\(s\)/, '22')
    expect(view.getByLabelText('Local port')).toBeInTheDocument()

    fill(view, /^Port\(s\)/, '9000-9002')
    expect(view.queryByLabelText('Local port')).not.toBeInTheDocument()
  })

  it('swaps the device picker for a local host field when exposing a service', async () => {
    const view = await open()

    fireEvent.change(view.getByLabelText('Direction'), { target: { value: 'to_tailnet' } })

    expect(view.queryByLabelText('Device')).not.toBeInTheDocument()
    expect(view.queryByLabelText('Bind address')).not.toBeInTheDocument()
    expect(view.getByLabelText('Local service host')).toBeInTheDocument()
    // The blast radius of publishing is worth saying out loud.
    expect(view.getByText(/Every device your ACLs allow/)).toBeInTheDocument()
  })

  it('names the ports for the side they belong to', async () => {
    const view = await open()

    fill(view, /^Port\(s\)/, '22')
    expect(view.getByLabelText('Port(s) on the device')).toBeInTheDocument()
    expect(view.getByLabelText('Local port')).toBeInTheDocument()

    fireEvent.change(view.getByLabelText('Direction'), { target: { value: 'to_tailnet' } })

    expect(view.getByLabelText('Port(s) to expose')).toBeInTheDocument()
    expect(view.getByLabelText('Tailnet port')).toBeInTheDocument()
  })

  it('counts the forwards a range will create', async () => {
    const view = await open()

    fill(view, /^Port\(s\)/, '9000-9002')

    expect(view.getByText('Creates 3 forwards, one per port.')).toBeInTheDocument()
  })
})

describe('the common-service shortcut', () => {
  it('fills the protocol and port from a preset', async () => {
    const view = await open({
      'GET /api/presets': {
        presets: [makePreset({ id: 'preset-dns', name: 'DNS', protocol: 'udp', remotePort: 53 })],
      },
    })

    fireEvent.change(view.getByLabelText(/^Common service/), { target: { value: 'preset-dns' } })

    expect(view.getByLabelText('Protocol')).toHaveValue('udp')
    expect(view.getByLabelText(/^Port\(s\)/)).toHaveValue('53')
  })

  it('hides itself entirely when there are no presets', async () => {
    const view = await open({ 'GET /api/presets': { presets: [] } })

    expect(view.queryByLabelText(/^Common service/)).not.toBeInTheDocument()
  })

  // Presets are a convenience; an agent that cannot list them must still let the
  // form be used.
  it('leaves the form usable when presets cannot be loaded', async () => {
    const view = await open({ 'GET /api/presets': netFail() })

    expect(view.getByRole('button', { name: 'Create forward' })).toBeEnabled()
  })
})

describe('while a save is in flight', () => {
  // Each port in a batch is a separate request. A second click would run the whole
  // batch again and duplicate every forward that succeeded the first time.
  it('disables the save button and says what it is doing', async () => {
    const pending = deferred<void>()
    const view = await open({
      'POST /api/forwards': () => pending.promise.then(() => created),
    })

    fill(view, 'Host', 'gpu-box')
    fill(view, /^Port\(s\)/, '22')
    fill(view, 'Local port', '2222')
    save(view)
    await settle(1)

    const button = view.getByRole('button', { name: 'Saving…' })
    expect(button).toBeDisabled()

    pending.resolve()
    await settle()

    expect(view.agent.countOf('POST /api/forwards')).toBe(1)
  })
})
