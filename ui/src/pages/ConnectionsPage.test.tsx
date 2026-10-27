// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { ConnectionsPage } from './ConnectionsPage'
import {
  deferred,
  emptySettingsForm,
  failWith,
  makeApprovalNeed,
  makeApprovals,
  makeExitNode,
  makeFabric,
  makeRoutes,
  makeStatus,
  makeTunnel,
  makeTunnelSchema,
  tunnelField,
  noContent,
  pressEscape,
  rejectField,
  renderAgent,
  settingsFormWithModules,
  settle,
  tunnelRoutes,
  type Routes,
} from '../test/agent'
import type { SettingsForm } from '../components/settings/useSettingsDraft'
import type { SettingFieldSchema, TunnelView } from '../api'

/** at renders the section at one address, which is the whole input this page takes. The
 *  form is the installation's, which is where the module switches gating some of a
 *  connection's settings are held. */
function at(params: readonly string[], routes: Routes = {}, form: SettingsForm = emptySettingsForm()) {
  return renderAgent(<ConnectionsPage params={params} form={form} />, {
    ...tunnelRoutes(),
    ...routes,
  })
}

const OFFICE: TunnelView = makeTunnel({
  id: 'tn_office',
  type: 'wireguard',
  typeLabel: 'WireGuard',
  name: 'Office',
  slug: 'office',
  state: 'off',
  stateLabel: 'Off',
  live: false,
})

/** The kind of connection that is configured from a file the server issues. */
const WIREGUARD_OFFER = { value: 'wireguard', label: 'WireGuard' } as const

/** A server's own file, as short as one can be and still describe a connection. It is
 *  passed through untouched, so what is in it matters only in that it arrives whole. */
const WG_FILE = `[Interface]
PrivateKey = aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc=
Address = 10.7.0.4/24

[Peer]
PublicKey = vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM=
AllowedIPs = 10.7.0.0/24
Endpoint = gateway.example.com:51820
`

/** A schema whose one field is in the section the subnet-route card owns, so a test can
 *  tell the card's own body apart from a section drawn beside it. */
function routingSchema(overrides: Partial<SettingFieldSchema> = {}) {
  return {
    ...makeTunnelSchema([
      tunnelField('routes.accept', 'Reach networks other devices advertise', {
        kind: 'bool',
        group: 'routing',
        module: 'routing',
        ...overrides,
      }),
    ]),
    groups: [
      { id: 'routing', label: 'Routing', description: 'What this connection routes.' },
    ],
  }
}

describe('what one connection shows', () => {
  // The card describes this network: what it reaches, what it offers, and the fields that
  // decide both. Drawing the same fields again under a section heading of their own would
  // read as two different settings that happen to agree.
  it('draws a section a state card owns only once', async () => {
    const view = await at(
      ['tailscale', 'tn_primary'],
      {
        'GET /api/tunnels/schema': routingSchema(),
        'GET /api/routes': makeRoutes({ enabled: true, accepting: true }),
      },
      settingsFormWithModules('routing'),
    )

    expect(view.getByRole('region', { name: 'Subnet routes' })).toBeInTheDocument()
    expect(view.queryByRole('region', { name: 'Routing' })).not.toBeInTheDocument()
    expect(
      view.getByLabelText('Reach networks other devices advertise'),
    ).toBeInTheDocument()
  })

  // The other half of the same rule. A view describes one connection, so on any other the
  // fields are drawn under their own heading -- otherwise a second tailnet's routing
  // settings would be unreachable because a card about the first one is not on the page.
  it('draws the section itself on a connection no card describes', async () => {
    const lab = makeTunnel({ id: 'tn_lab', name: 'Lab', slug: 'lab' })
    const view = await at(
      ['tailscale', 'tn_lab'],
      {
        ...tunnelRoutes([makeTunnel(), lab]),
        'GET /api/tunnels/schema': routingSchema(),
        'GET /api/routes': makeRoutes({ enabled: true }),
        'GET /api/exitnode': makeExitNode({ enabled: true }),
      },
      settingsFormWithModules('routing'),
    )

    expect(view.getByRole('region', { name: 'Routing' })).toBeInTheDocument()
    expect(view.queryByRole('region', { name: 'Subnet routes' })).not.toBeInTheDocument()
    expect(view.queryByRole('region', { name: 'Exit node' })).not.toBeInTheDocument()
  })

  // The same rule for the other reason a section can come out empty: every field in it is
  // gated on a module this installation has switched off. The heading and its description
  // read as a feature that failed to load, and there is nothing under them to act on.
  it('draws no heading for a section whose every field is gated off', async () => {
    const lab = makeTunnel({ id: 'tn_lab', name: 'Lab', slug: 'lab' })
    const view = await at(['tailscale', 'tn_lab'], {
      ...tunnelRoutes([makeTunnel(), lab]),
      'GET /api/tunnels/schema': routingSchema({ available: false }),
      'GET /api/routes': makeRoutes({ enabled: true }),
    })

    expect(
      view.queryByLabelText('Reach networks other devices advertise'),
    ).not.toBeInTheDocument()
    expect(view.queryByRole('region', { name: 'Routing' })).not.toBeInTheDocument()
  })

  // The switch is on this page, in the head of the card whose settings it governs, and the
  // agent resolved availability when the form loaded -- before it was pressed. Reading the
  // served answer alone leaves the switch turning on a feature whose settings only appear
  // after a reload, which reads as a switch that did nothing.
  it('shows a gated setting as soon as the module governing it is switched on', async () => {
    // Served the way the agent serves it with the module off: the field exists and is
    // refused, which is the answer this page has to stop believing the moment the switch
    // beside it moves.
    const view = await at(['tailscale', 'tn_primary'], {
      'GET /api/tunnels/schema': routingSchema({ available: false }),
      'GET /api/routes': makeRoutes({ enabled: true, accepting: true }),
    })
    expect(
      view.queryByLabelText('Reach networks other devices advertise'),
    ).not.toBeInTheDocument()

    view.rerender(
      <ConnectionsPage
        params={['tailscale', 'tn_primary']}
        form={settingsFormWithModules('routing')}
      />,
    )
    await settle()

    expect(view.getByLabelText('Reach networks other devices advertise')).toBeInTheDocument()
  })
})

describe('which settings a kind of connection has', () => {
  // One schema covers every kind of connection, so the kind decides which of it applies.
  // A tailnet's enrollment settings on a WireGuard connection are controls that write
  // somewhere it does not have, under a heading claiming it has one.
  it('shows only the settings the kind of connection it is actually has', async () => {
    const view = await at(['wireguard', 'tn_office'], {
      'GET /api/tunnels': { tunnels: [OFFICE] },
      'GET /api/tunnels/schema': {
        ...makeTunnelSchema([
          tunnelField('authKey', 'Auth key', { group: 'auth', variant: 'tailscale' }),
          tunnelField('wg.peer.endpoint', 'Server address', {
            group: 'server',
            variant: 'wireguard',
          }),
        ]),
        groups: [
          { id: 'auth', label: 'Authentication', description: 'How this device enrolls.' },
          { id: 'server', label: 'Server', description: 'Which server this connection dials.' },
        ],
      },
    })

    expect(view.getByLabelText('Server address')).toBeInTheDocument()
    expect(view.queryByLabelText('Auth key')).not.toBeInTheDocument()
    // And no heading for them either: an empty section reads as settings that failed to
    // load rather than settings this kind of connection does not have.
    expect(view.queryByRole('region', { name: 'Authentication' })).not.toBeInTheDocument()
  })
})

describe('the connection list', () => {
  it('lists every connection under the kind of network it is', async () => {
    const view = await at([], { 'GET /api/tunnels': { tunnels: [makeTunnel(), OFFICE] } })

    expect(view.getByRole('region', { name: 'Tailscale' })).toBeInTheDocument()
    expect(view.getByRole('region', { name: 'WireGuard' })).toBeInTheDocument()
    expect(view.getByRole('link', { name: /Tailnet/ })).toBeInTheDocument()
    expect(view.getByRole('link', { name: /Office/ })).toBeInTheDocument()
  })

  // A connection nothing is running under is off, not broken. Painting it as a failure
  // puts a fault on screen where there is none, and is how people stop believing red.
  it('reports a connection that is not up as off rather than as a failure', async () => {
    const view = await at([], { 'GET /api/tunnels': { tunnels: [OFFICE] } })

    const status = view.container.querySelector('.reach-mode .status')
    expect(status).toHaveClass('status', 'off')
    expect(status).toHaveTextContent('Off')
  })

  // The word is the state; the colour is decoration. A row that carried only the dot
  // would say nothing at all to a reader who cannot see it.
  it('names the state in words beside the dot', async () => {
    const view = await at([])

    expect(view.getByText('Connected')).toBeInTheDocument()
  })

  // A kind of network this build cannot bring up would be an offer it cannot honour, and
  // an empty heading with nothing to press reads as a connection that failed to load.
  it('names no kind that cannot be added and has nothing connected with it', async () => {
    const view = await at([])

    expect(view.queryByRole('region', { name: 'WireGuard' })).not.toBeInTheDocument()
    expect(view.queryByRole('region', { name: 'OpenVPN' })).not.toBeInTheDocument()
  })

  // The other half of the same rule: a kind that can be added is on screen with its Add
  // button before anything is connected with it, which is where somebody with no
  // connections at all starts.
  it('names a kind that can be added even with nothing connected with it', async () => {
    const view = await at([], {
      'GET /api/tunnels/schema': {
        ...makeTunnelSchema(),
        types: [
          { value: 'tailscale', label: 'Tailscale' },
          { value: 'wireguard', label: 'WireGuard' },
        ],
      },
    })

    expect(view.getByRole('region', { name: 'WireGuard' })).toBeInTheDocument()
    expect(view.getByRole('button', { name: 'Add WireGuard' })).toBeInTheDocument()
    expect(view.queryByRole('region', { name: 'OpenVPN' })).not.toBeInTheDocument()
  })

  it('adds a connection of the kind whose Add button was pressed', async () => {
    const view = await at([], {
      'POST /api/tunnels': makeTunnel({
        id: 'tn_office',
        name: 'Office',
        slug: 'office',
        state: 'off',
        stateLabel: 'Off',
        live: false,
      }),
    })

    fireEvent.click(view.getByRole('button', { name: 'Add Tailscale' }))
    fireEvent.change(view.getByLabelText('Name (optional)'), { target: { value: 'Office' } })
    fireEvent.click(view.getByRole('button', { name: 'Add connection' }))
    await settle()

    expect(view.agent.bodyOf('POST /api/tunnels')).toEqual({ type: 'tailscale', name: 'Office' })
    // Onto the new connection's own page: it was added with a name and nothing else, and
    // what makes it reach a network is configured there.
    expect(window.location.hash).toBe('#/connections/tailscale/tn_office')
  })

  // Nobody transcribes a WireGuard file by hand. Adding and then importing is the whole
  // flow, so it happens in one press: the file reaches the agent whole, and the reader
  // lands on a connection that is already configured rather than an empty form.
  it('reads a pasted configuration into the connection it just added', async () => {
    const view = await at([], {
      'GET /api/tunnels/schema': { ...makeTunnelSchema(), types: [WIREGUARD_OFFER] },
      'POST /api/tunnels': OFFICE,
      'POST /api/tunnels/tn_office/import': OFFICE,
    })

    fireEvent.click(view.getByRole('button', { name: 'Add WireGuard' }))
    fireEvent.change(view.getByLabelText('Configuration file'), {
      target: { value: WG_FILE },
    })
    fireEvent.click(view.getByRole('button', { name: 'Add connection' }))
    await settle()

    expect(view.agent.bodyOf('POST /api/tunnels/tn_office/import')).toEqual({ file: WG_FILE })
    expect(window.location.hash).toBe('#/connections/wireguard/tn_office')
  })

  // A file the agent refuses leaves nothing behind. The connection existed only to have
  // something to import into, so leaving it on the list would put an empty entry nobody
  // asked for beside a message saying the import failed.
  it('takes the connection away again when the file it was added with is refused', async () => {
    const view = await at([], {
      'GET /api/tunnels/schema': { ...makeTunnelSchema(), types: [WIREGUARD_OFFER] },
      'POST /api/tunnels': OFFICE,
      'POST /api/tunnels/tn_office/import': failWith(
        400,
        'line 4: PostUp runs a command on this machine once the connection is up',
      ),
      'DELETE /api/tunnels/tn_office': noContent(),
    })

    fireEvent.click(view.getByRole('button', { name: 'Add WireGuard' }))
    fireEvent.change(view.getByLabelText('Configuration file'), {
      target: { value: WG_FILE },
    })
    fireEvent.click(view.getByRole('button', { name: 'Add connection' }))
    await settle()

    expect(view.agent.countOf('DELETE /api/tunnels/tn_office')).toBe(1)
    expect(
      view.getByText(/PostUp runs a command on this machine once the connection is up/),
    ).toBeInTheDocument()
    // Still on the form, which is where the file that was refused is.
    expect(view.getByRole('dialog', { name: 'Add a WireGuard connection' })).toBeInTheDocument()
  })

  // Adding one to configure by hand stays possible: the file is how it is normally done,
  // not the only way, and requiring one would block someone typing in a key they hold.
  it('adds a connection with no file when none was pasted', async () => {
    const view = await at([], {
      'GET /api/tunnels/schema': { ...makeTunnelSchema(), types: [WIREGUARD_OFFER] },
      'POST /api/tunnels': OFFICE,
    })

    fireEvent.click(view.getByRole('button', { name: 'Add WireGuard' }))
    fireEvent.click(view.getByRole('button', { name: 'Add connection' }))
    await settle()

    expect(view.agent.countOf('POST /api/tunnels/tn_office/import')).toBe(0)
    expect(window.location.hash).toBe('#/connections/wireguard/tn_office')
  })

  // A tailnet is joined by signing in, not configured from a file. An empty paste box that
  // never accepts anything reads as a step that was missed.
  it('asks for no file for a kind of connection that has none', async () => {
    const view = await at([])

    fireEvent.click(view.getByRole('button', { name: 'Add Tailscale' }))

    expect(view.queryByLabelText('Configuration file')).not.toBeInTheDocument()
  })

  // A refusal is the user's to fix, so it stays on the form with the reason on it. A
  // dialog that closed on a refusal would read as a connection that was added.
  it('keeps the add form open with the reason when the agent refuses', async () => {
    const view = await at([], {
      'POST /api/tunnels': failWith(400, 'this build cannot bring up a "wireguard" connection'),
    })

    fireEvent.click(view.getByRole('button', { name: 'Add Tailscale' }))
    fireEvent.click(view.getByRole('button', { name: 'Add connection' }))
    await settle()

    expect(view.getByRole('dialog', { name: 'Add a Tailscale connection' })).toBeInTheDocument()
    expect(
      view.getByText('this build cannot bring up a "wireguard" connection'),
    ).toBeInTheDocument()
  })

  // The whole reason the report exists. Both connections report themselves connected and
  // healthy; the only place the collision can be seen is above the list, and without it the
  // second network's addresses silently answer from the first.
  it('says which networks carry the same addresses and who cannot be reached at them', async () => {
    const view = await at([], {
      'GET /api/tunnels': { tunnels: [makeTunnel(), OFFICE] },
      'GET /api/fabric': makeFabric({
        conflicts: [
          {
            prefix: '10.0.0.0/16',
            holder: 'tn_primary',
            holderName: 'Tailnet',
            claimants: [{ tunnelId: 'tn_office', name: 'Office' }],
            detail: '10.0.0.0/16 is already reached through Tailnet',
          },
        ],
      }),
    })

    const band = view.getByText(/10\.0\.0\.0\/16 is already reached through Tailnet/)
    expect(band).toHaveTextContent('Office cannot be reached at 10.0.0.0/16')
  })

  // Nothing colliding is the ordinary state, and a permanent band explaining that there is
  // no problem is how a real one stops being read.
  it('says nothing about addressing while nothing collides', async () => {
    const view = await at([])

    expect(view.queryByText(/carry the same addresses/)).not.toBeInTheDocument()
  })

  // A connection that cannot say what it carries leaves a gap in the report, and a gap
  // there looks exactly like no collision at all.
  it('names a connection whose networks could not be read', async () => {
    const view = await at([], {
      'GET /api/fabric': makeFabric({
        unread: [
          {
            tunnelId: 'tn_primary',
            name: 'Tailnet',
            error: 'the control plane is not answering',
          },
        ],
      }),
    })

    expect(
      view.getByText(/The networks Tailnet carries could not be read/),
    ).toHaveTextContent('the control plane is not answering')
  })

  it('leads to the connection its row names', async () => {
    const view = await at([])

    expect(view.getByRole('link', { name: /Tailnet/ })).toHaveAttribute(
      'href',
      '#/connections/tailscale/tn_primary',
    )
  })
})

describe('one connection', () => {
  it('reports what it is and what it is doing', async () => {
    const view = await at(['tailscale', 'tn_primary'], {
      'GET /api/tunnels': {
        tunnels: [
          makeTunnel({
            addrs: ['100.64.0.7'],
            names: ['workstation.example.ts.net'],
            detail: 'relayed',
          }),
        ],
      },
    })

    const head = view.container.querySelector('.panel-head .status')
    expect(head).toHaveClass('status', 'running')
    expect(head).toHaveTextContent('Connected')
    expect(head).toHaveTextContent('relayed')
    expect(view.getByText('100.64.0.7')).toBeInTheDocument()
    expect(view.getByText('workstation.example.ts.net')).toBeInTheDocument()
  })

  // Limits are what this kind of connection does not carry at all. Meeting one later as a
  // fault costs someone an afternoon looking for a break that was never there.
  it('states up front what this connection does not carry', async () => {
    const view = await at(['tailscale', 'tn_primary'], {
      'GET /api/tunnels': {
        tunnels: [makeTunnel({ limits: ['Ping does not cross this connection.'] })],
      },
    })

    expect(view.getByText('Ping does not cross this connection.')).toBeInTheDocument()
  })

  // The form is the served schema and nothing else, so a field added to the connection
  // registry reaches this page with no work in it.
  it('renders a control for every field the agent serves', async () => {
    const view = await at(['tailscale', 'tn_primary'])

    for (const field of makeTunnelSchema().fields) {
      expect(view.getByLabelText(field.label)).toBeInTheDocument()
    }
  })

  it('writes a rename to the connection that is open', async () => {
    const renamed = makeTunnel({ name: 'Work' })
    const view = await at(['tailscale', 'tn_primary'], {
      'PUT /api/tunnels/tn_primary': renamed,
    })

    fireEvent.change(view.getByLabelText('Name'), { target: { value: 'Work' } })
    fireEvent.click(view.getByRole('button', { name: 'Save' }))
    await settle()

    expect(view.agent.bodyOf('PUT /api/tunnels/tn_primary')).toEqual({ name: 'Work' })
  })

  // The agent refuses a rename onto a name another connection answers for. Putting the
  // reason under the control that caused it is what stops a refusal reading as a save
  // that worked, with a banner somewhere above the collapsed section that says otherwise.
  it('puts the reason a write was refused on the control that caused it', async () => {
    const view = await at(['tailscale', 'tn_primary'], {
      'PUT /api/tunnels/tn_primary': rejectField(
        'slug',
        '"office" is already used by another connection',
      ),
    })

    fireEvent.change(view.getByLabelText('Short name'), { target: { value: 'office' } })
    fireEvent.click(view.getByRole('button', { name: 'Save' }))
    await settle()

    expect(view.container.querySelector('.field-error')).toHaveTextContent(
      '"office" is already used by another connection',
    )
  })

  // Switching a connection off is the one edit made with a broken network in front of
  // somebody, so the switch writes the moment it is flipped and the write names only the
  // switch: a rename half-typed beside it must not ride along.
  it('switches a connection off at once, writing nothing but the switch', async () => {
    const office = makeTunnel({ ...OFFICE, settings: { ...OFFICE.settings, enabled: true } })
    const view = await at(['wireguard', 'tn_office'], {
      ...tunnelRoutes([makeTunnel(), office]),
      'GET /api/tunnels/schema': makeTunnelSchema([
        tunnelField('name', 'Name'),
        tunnelField('enabled', 'Connect to this network', { kind: 'bool' }),
      ]),
      // The list is polled again after the write, so the switch reads what the agent now
      // holds rather than the answer to the write alone.
      'PUT /api/tunnels/tn_office': () => {
        const off = makeTunnel({
          ...office,
          enabled: false,
          settings: { ...office.settings, enabled: false },
        })
        view.agent.set('GET /api/tunnels', { tunnels: [makeTunnel(), off] })
        return off
      },
    })
    fireEvent.change(view.getByLabelText('Name'), { target: { value: 'Office 2' } })
    expect(view.getByLabelText('Connect to this network')).toBeChecked()

    fireEvent.click(view.getByLabelText('Connect to this network'))
    await settle()

    expect(view.agent.countOf('PUT /api/tunnels/tn_office')).toBe(1)
    expect(view.agent.bodyOf('PUT /api/tunnels/tn_office')).toEqual({ enabled: false })
    expect(view.getByLabelText('Connect to this network')).not.toBeChecked()
    expect(view.getByLabelText('Name')).toHaveValue('Office 2')
  })

  // A switch the agent refused to move has to move back, or the page shows a connection as
  // off that is still carrying traffic, with the refusal somewhere below.
  it('puts the switch back with the reason when the agent refuses to move it', async () => {
    const office = makeTunnel({ ...OFFICE, settings: { ...OFFICE.settings, enabled: true } })
    const view = await at(['wireguard', 'tn_office'], {
      ...tunnelRoutes([makeTunnel(), office]),
      'GET /api/tunnels/schema': makeTunnelSchema([
        tunnelField('enabled', 'Connect to this network', { kind: 'bool' }),
      ]),
      'PUT /api/tunnels/tn_office': rejectField('enabled', 'the primary connection stays up'),
    })

    fireEvent.click(view.getByLabelText('Connect to this network'))
    await settle()

    expect(view.getByLabelText('Connect to this network')).toBeChecked()
    expect(view.container.querySelector('.field-error')).toHaveTextContent(
      'the primary connection stays up',
    )
  })

  // The primary connection is where this installation's own settings, environment and
  // flags are applied, so the agent refuses to remove it. Offering the action anyway would
  // put a button on screen whose only outcome is a refusal.
  it('offers no way to remove a connection the agent will not remove', async () => {
    const view = await at(['tailscale', 'tn_primary'])

    expect(view.queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument()
  })

  it('asks before removing a connection, and removes it once answered', async () => {
    const view = await at(['wireguard', 'tn_office'], {
      'GET /api/tunnels': { tunnels: [OFFICE] },
      'DELETE /api/tunnels/tn_office': noContent(),
    })

    fireEvent.click(view.getByRole('button', { name: 'Remove' }))
    expect(view.agent.countOf('DELETE /api/tunnels/tn_office')).toBe(0)

    fireEvent.click(view.getByRole('button', { name: 'Remove connection' }))
    await settle()

    expect(view.agent.countOf('DELETE /api/tunnels/tn_office')).toBe(1)
    expect(window.location.hash).toBe('#/connections')
  })

  it('leaves the connection alone when the question is answered with Cancel', async () => {
    const view = await at(['wireguard', 'tn_office'], {
      'GET /api/tunnels': { tunnels: [OFFICE] },
      'DELETE /api/tunnels/tn_office': noContent(),
    })

    fireEvent.click(view.getByRole('button', { name: 'Remove' }))
    fireEvent.click(view.getByRole('button', { name: 'Cancel' }))
    await settle()

    expect(view.agent.countOf('DELETE /api/tunnels/tn_office')).toBe(0)
  })

  // A refused removal has to say why on the connection it failed on. Silently staying put
  // would read as a click that did not register.
  it('reports why a removal was refused', async () => {
    const view = await at(['wireguard', 'tn_office'], {
      'GET /api/tunnels': { tunnels: [OFFICE] },
      'DELETE /api/tunnels/tn_office': failWith(400, 'the primary connection cannot be removed'),
    })

    fireEvent.click(view.getByRole('button', { name: 'Remove' }))
    fireEvent.click(view.getByRole('button', { name: 'Remove connection' }))
    await settle()

    expect(view.getByText('the primary connection cannot be removed')).toBeInTheDocument()
  })

  // Keys get rotated and servers get replaced, and both arrive as a new file. Without this
  // the only way to apply one is to retype every field it carries.
  it('reads a new configuration into a connection that already exists', async () => {
    const view = await at(['wireguard', 'tn_office'], {
      'GET /api/tunnels': { tunnels: [OFFICE] },
      'POST /api/tunnels/tn_office/import': OFFICE,
    })

    fireEvent.click(view.getByRole('button', { name: 'Import configuration' }))
    fireEvent.change(view.getByLabelText('Configuration file'), {
      target: { value: WG_FILE },
    })
    fireEvent.click(view.getByRole('button', { name: 'Import' }))
    await settle()

    expect(view.agent.bodyOf('POST /api/tunnels/tn_office/import')).toEqual({ file: WG_FILE })
    expect(view.queryByRole('dialog')).not.toBeInTheDocument()
  })

  // The refusal names the line and the directive, and it is the reader's to fix, so it
  // stays on the form beside the text that carried it.
  it('keeps the pasted file on screen with the reason it was refused', async () => {
    const view = await at(['wireguard', 'tn_office'], {
      'GET /api/tunnels': { tunnels: [OFFICE] },
      'POST /api/tunnels/tn_office/import': failWith(400, 'line 7: Table is not honoured here'),
    })

    fireEvent.click(view.getByRole('button', { name: 'Import configuration' }))
    fireEvent.change(view.getByLabelText('Configuration file'), {
      target: { value: WG_FILE },
    })
    fireEvent.click(view.getByRole('button', { name: 'Import' }))
    await settle()

    expect(view.getByText('line 7: Table is not honoured here')).toBeInTheDocument()
    expect(view.getByLabelText('Configuration file')).toHaveValue(WG_FILE)
  })

  // The state word reads 'connected' for a connection carrying traffic and for one that
  // agreed keys an hour ago and has moved nothing since. These figures are the only thing on
  // the page that tells those apart.
  it('shows what the connection has carried, how long it has been up, and when it last agreed keys', async () => {
    const view = await at(['wireguard', 'tn_office'], {
      'GET /api/tunnels': {
        tunnels: [
          makeTunnel({
            ...OFFICE,
            health: {
              up: 2048,
              down: 4096,
              since: new Date(Date.now() - 3 * 3600_000).toISOString(),
              lastHandshake: new Date(Date.now() - 120_000).toISOString(),
            },
          }),
        ],
      },
    })

    expect(view.getByText('2.0 KB sent, 4.0 KB received')).toBeInTheDocument()
    expect(view.getByText('3h')).toBeInTheDocument()
    expect(view.getByText('2m ago')).toBeInTheDocument()
  })

  // A kind that counts nothing of its own reports nothing, and the page shows nothing rather
  // than a confident zero: a tailnet's traffic is counted per device, on the activity screen.
  it('shows no carried figures for a connection nothing is counting', async () => {
    const view = await at(['tailscale', 'tn_primary'])

    expect(view.queryByText('Carried')).not.toBeInTheDocument()
  })

  // The state this exists for: a connection that says it is connected and carries nothing.
  // Nothing about it has changed, so no save would rebuild it, and until now the only lever
  // was switching it off and on again.
  it('builds a connection again when asked, without changing anything about it', async () => {
    const live = makeTunnel({ ...OFFICE, state: 'connected', stateLabel: 'Connected', live: true })
    const view = await at(['wireguard', 'tn_office'], {
      'GET /api/tunnels': { tunnels: [live] },
      'POST /api/tunnels/tn_office/retry': live,
    })

    fireEvent.click(view.getByRole('button', { name: 'Reconnect' }))
    await settle()

    expect(view.agent.countOf('POST /api/tunnels/tn_office/retry')).toBe(1)
  })

  // A refusal belongs on the connection it was refused for. Silently staying put reads as a
  // click that never registered, which is the same complaint the button exists to answer.
  it('reports why a connection could not be built again', async () => {
    const view = await at(['wireguard', 'tn_office'], {
      'GET /api/tunnels': { tunnels: [OFFICE] },
      'POST /api/tunnels/tn_office/retry': failWith(400, 'Office is switched off.'),
    })

    fireEvent.click(view.getByRole('button', { name: 'Reconnect' }))
    await settle()

    expect(view.getByText('Office is switched off.')).toBeInTheDocument()
  })

  // The agent decides what it would refuse. A button the app puts up on its own reasoning
  // is one that eventually disagrees with the agent, and its only outcome is a refusal.
  it('offers no reconnect on a connection the agent will not build again', async () => {
    const view = await at(['tailscale', 'tn_primary'])

    expect(view.queryByRole('button', { name: 'Reconnect' })).not.toBeInTheDocument()
  })

  it('offers no import on a connection that is not configured from a file', async () => {
    const view = await at(['tailscale', 'tn_primary'])

    expect(view.queryByRole('button', { name: 'Import configuration' })).not.toBeInTheDocument()
  })

  // A stale link is the usual way someone gets here. Rendering an empty form instead
  // would read as a connection with nothing configured rather than one that is gone.
  it('says so when the address names no connection', async () => {
    const view = await at(['tailscale', 'tn_absent'])

    expect(view.getByRole('region', { name: 'No such connection' })).toBeInTheDocument()
  })
})

// The dialog that reads a server's file into a connection that already exists. Its words
// are the reader's only guide to which file to paste, and its buttons are what stand
// between a stray click and a connection rebuilt from an empty file.
describe('the dialog that imports a configuration', () => {
  const VPN: TunnelView = makeTunnel({
    id: 'tn_vpn',
    type: 'openvpn',
    typeLabel: 'OpenVPN',
    name: 'Provider',
    slug: 'provider',
    state: 'off',
    stateLabel: 'Off',
    live: false,
  })

  async function open(tunnel: TunnelView, routes: Routes = {}) {
    const view = await at([tunnel.type, tunnel.id], {
      'GET /api/tunnels': { tunnels: [tunnel] },
      ...routes,
    })
    fireEvent.click(view.getByRole('button', { name: 'Import configuration' }))
    return view
  }

  // The two formats have nothing in common but that a server hands them out, so the hint
  // names the opening line of the one this connection takes rather than a file in general.
  it('describes the WireGuard file by its opening section', async () => {
    const view = await open(OFFICE)

    const dialog = view.getByRole('dialog', { name: 'Import a configuration into Office' })
    expect(dialog).toHaveTextContent('[Interface]')
    expect(dialog).toHaveTextContent('[Peer]')
    expect(dialog).not.toHaveTextContent('.ovpn')
  })

  it('describes the OpenVPN file by its name and its embedded blocks', async () => {
    const view = await open(VPN)

    const dialog = view.getByRole('dialog', { name: 'Import a configuration into Provider' })
    expect(dialog).toHaveTextContent('.ovpn')
    expect(dialog).toHaveTextContent('<ca>')
    expect(dialog).not.toHaveTextContent('[Interface]')
  })

  // An empty file would rebuild the connection from nothing. Whitespace is the same file.
  it('offers no import until something other than whitespace is pasted', async () => {
    const view = await open(OFFICE)
    const button = view.getByRole('button', { name: 'Import' })
    expect(button).toBeDisabled()

    fireEvent.change(view.getByLabelText('Configuration file'), { target: { value: '  \n\t' } })
    expect(button).toBeDisabled()

    fireEvent.change(view.getByLabelText('Configuration file'), { target: { value: WG_FILE } })
    expect(button).toBeEnabled()
  })

  // A second click while the first is in flight would send the file twice, and the second
  // answer would land on a connection the first had already rebuilt.
  it('holds the button while the import runs', async () => {
    const pending = deferred<TunnelView>()
    const view = await open(OFFICE, { 'POST /api/tunnels/tn_office/import': () => pending.promise })
    fireEvent.change(view.getByLabelText('Configuration file'), { target: { value: WG_FILE } })

    fireEvent.click(view.getByRole('button', { name: 'Import' }))
    await settle()

    expect(view.getByRole('button', { name: 'Importing…' })).toBeDisabled()
    expect(view.agent.countOf('POST /api/tunnels/tn_office/import')).toBe(1)

    pending.resolve(OFFICE)
    await settle()
    expect(view.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it.each([
    ['Escape', () => pressEscape()],
    ['Cancel', (view: { getByRole: (r: string, o: { name: string }) => HTMLElement }) =>
      fireEvent.click(view.getByRole('button', { name: 'Cancel' }))],
    ['Close', (view: { getByRole: (r: string, o: { name: string }) => HTMLElement }) =>
      fireEvent.click(view.getByRole('button', { name: 'Close' }))],
  ])('closes on %s without sending anything', async (_way, leave) => {
    const view = await open(OFFICE)
    fireEvent.change(view.getByLabelText('Configuration file'), { target: { value: WG_FILE } })

    leave(view)
    await settle()

    expect(view.queryByRole('dialog')).not.toBeInTheDocument()
    expect(view.agent.countOf('POST /api/tunnels/tn_office/import')).toBe(0)
  })
})

// An OpenVPN connection whose server the root helper has not been told about stays down, and
// its own page is where somebody goes to find out why.
describe('a connection waiting for an administrator', () => {
  const VPN: TunnelView = makeTunnel({
    id: 'tn_vpn',
    type: 'openvpn',
    typeLabel: 'OpenVPN',
    name: 'Provider',
    slug: 'provider',
    state: 'off',
    stateLabel: 'Off',
    live: false,
  })

  function waiting(features: string[]) {
    return makeStatus({
      approvals: makeApprovals({
        needs: [
          makeApprovalNeed({
            kind: 'openvpn-remote',
            value: 'vpn.example.net:1194',
            reason: 'connect to the OpenVPN server vpn.example.net:1194',
            features,
          }),
        ],
        command: "sudo app-tail tun grant '--openvpn-remote=vpn.example.net:1194'",
      }),
    })
  }

  it('offers the approval on the page of the connection that asked', async () => {
    const view = await at([VPN.type, VPN.id], {
      'GET /api/tunnels': { tunnels: [VPN] },
      'GET /api/status': waiting(['openvpn:tn_vpn']),
    })

    const banner = view.getByRole('region', { name: 'Needs your approval' })
    expect(banner).toHaveTextContent('connect to the OpenVPN server vpn.example.net:1194')
    expect(view.getByRole('button', { name: 'Approve…' })).toBeEnabled()
  })

  it('offers nothing on the page of a connection that is not waiting', async () => {
    const view = await at([VPN.type, VPN.id], {
      'GET /api/tunnels': { tunnels: [VPN] },
      'GET /api/status': waiting(['openvpn:tn_other']),
    })

    expect(view.queryByRole('region', { name: 'Needs your approval' })).not.toBeInTheDocument()
  })
})
