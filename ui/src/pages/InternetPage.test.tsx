// SPDX-License-Identifier: MIT

import { fireEvent, within } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import App from '../App'
import { href } from '../lib/router'
import {
  makeEgress,
  makeSettings,
  makeSettingsResponse,
  renderAgent,
  settingsRoutes,
  settle,
  type Routes,
} from '../test/agent'
import type { Settings } from '../api'

/** at opens the internet page over a machine arranged the given way. */
async function at(settings: Partial<Settings> = {}, routes: Routes = {}) {
  window.history.replaceState(null, '', `/${href('internet')}`)
  return renderAgent(<App />, {
    ...settingsRoutes(makeSettings(settings)),
    'PUT /api/settings': makeSettingsResponse(settings),
    ...routes,
  })
}

afterEach(() => {
  window.history.replaceState(null, '', '/')
})

// Where everything the connections do not carry goes. The choice is on this page because
// it is a statement about this machine: put on one connection's page it would be invisible
// from the other two.
describe('where internet traffic goes', () => {
  /** The card's own region, named by the settings group it renders. */
  const PANEL = 'Internet traffic'
  /** A machine whose internet traffic is set to go through a connection. */
  const THROUGH_A_CONNECTION: Partial<Settings> = {
    'egress.mode': 'tunnel',
    'egress.tunnelId': 'tn_office',
  }

  // The connection to carry it is asked for only once somebody has said they want one.
  // Offering the picker beside "out of this machine" would put a control on screen that
  // decides nothing.
  it('leaves it on this machine and asks for no connection until told otherwise', async () => {
    const view = await at()

    const panel = view.getByRole('region', { name: PANEL })
    expect(panel).toHaveTextContent('leaving this machine')
    expect(view.queryByLabelText('Connection carrying it')).toBeNull()
  })

  it('asks which connection carries it once it is to go through one', async () => {
    const view = await at(THROUGH_A_CONNECTION)

    expect(view.getByLabelText('Connection carrying it')).toBeInTheDocument()
  })

  it('writes the choice as soon as it is made', async () => {
    const view = await at()

    fireEvent.change(view.getByLabelText('Where internet traffic goes'), {
      target: { value: 'tunnel' },
    })
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({ 'egress.mode': 'tunnel' })
  })

  // The connection as a person reads it, not the id they never chose it by.
  it('names the connection carrying it', async () => {
    const view = await at(THROUGH_A_CONNECTION, {
      'GET /api/egress': makeEgress({
        mode: 'tunnel',
        tunnelId: 'tn_office',
        tunnelName: 'Office',
        carrying: true,
      }),
    })

    const panel = view.getByRole('region', { name: PANEL })
    expect(panel).toHaveTextContent('carrying')
    expect(panel).toHaveTextContent('Office')
  })

  // The failure the card exists to show: the setting reads "through my connection" and the
  // traffic is leaving this machine exactly as it did before. Nothing else on the machine
  // says which of the two is true.
  it('says why a chosen connection is not carrying it', async () => {
    const view = await at(THROUGH_A_CONNECTION, {
      'GET /api/egress': makeEgress({
        mode: 'tunnel',
        tunnelId: 'tn_office',
        tunnelName: 'Office',
        carrying: false,
        reason: 'Office has no exit node selected on it.',
      }),
    })

    const panel = view.getByRole('region', { name: PANEL })
    expect(panel).toHaveTextContent('not carrying')
    expect(panel).toHaveTextContent('Office has no exit node selected on it.')
  })

  // What routing the traffic away does not cover. Names looked up here leave the list of
  // what is being visited on this network, which is most of what somebody choosing this
  // was trying to stop, and no other screen would ever mention it.
  it('states what the connection carrying it does not cover', async () => {
    const limit = 'Names are still looked up on this network.'
    const view = await at(THROUGH_A_CONNECTION, {
      'GET /api/egress': makeEgress({
        mode: 'tunnel',
        tunnelId: 'tn_office',
        carrying: true,
        limits: [limit],
      }),
    })

    expect(view.getByRole('region', { name: PANEL })).toHaveTextContent(limit)
  })

  // A connection stays named while the traffic goes out directly, so the agent's answer
  // about it does too. Rendering that answer would tell a reader something is wrong with an
  // arrangement they are not in.
  it('keeps a remembered connection quiet while the traffic leaves this machine', async () => {
    const view = await at(
      { 'egress.mode': 'direct', 'egress.tunnelId': 'tn_office' },
      {
        'GET /api/egress': makeEgress({
          mode: 'direct',
          tunnelId: 'tn_office',
          carrying: false,
          reason: 'Office is not running.',
          limits: ['Names are still looked up on this network.'],
        }),
      },
    )

    const panel = view.getByRole('region', { name: PANEL })
    expect(panel).not.toHaveTextContent('Office is not running.')
    expect(panel).not.toHaveTextContent('Names are still looked up')
  })
})

// The kill switch: internet traffic held here rather than let out over whatever network this
// machine is on, while the connection chosen to carry it cannot. The card's job is to make a
// promise visible while it is being kept -- what it does is otherwise only observable at the
// moment it stops traffic, which is the moment nobody is reading a checkbox.
describe('holding internet traffic rather than letting it out', () => {
  const PANEL = 'Internet traffic'
  const THROUGH_A_CONNECTION: Partial<Settings> = {
    'egress.mode': 'tunnel',
    'egress.tunnelId': 'tn_office',
  }
  /** The field's label, as the registry writes it. */
  const SWITCH = 'Hold it rather than let it out'

  it('offers the switch while one connection carries the traffic', async () => {
    const view = await at(THROUGH_A_CONNECTION)

    expect(view.getByLabelText(SWITCH)).toBeInTheDocument()
  })

  // It is read only where it applies. Offered beside "out of this machine" it would decide
  // nothing, and offered beside a set of connections it would read as switching on something
  // that mode does whether or not it is on.
  it.each([
    ['the traffic leaves this machine', { 'egress.mode': 'direct' }],
    ['several connections share it', { 'egress.mode': 'multi' }],
  ])('does not offer the switch while %s', async (_case, settings) => {
    const view = await at(settings)

    expect(view.queryByLabelText(SWITCH)).toBeNull()
  })

  it('says nothing falls back while the switch is on and the traffic is flowing', async () => {
    const view = await at(THROUGH_A_CONNECTION, {
      'GET /api/egress': makeEgress({
        mode: 'tunnel',
        tunnelId: 'tn_office',
        tunnelName: 'Office',
        carrying: true,
        killSwitch: true,
      }),
    })

    expect(view.getByRole('region', { name: PANEL })).toHaveTextContent('Held rather than leaked')
  })

  // Without the switch the same arrangement makes no such promise, and printing one would be
  // the card telling a reader their traffic is protected when it is not.
  it('promises nothing while the switch is off', async () => {
    const view = await at(THROUGH_A_CONNECTION, {
      'GET /api/egress': makeEgress({
        mode: 'tunnel',
        tunnelId: 'tn_office',
        tunnelName: 'Office',
        carrying: true,
      }),
    })

    expect(view.getByRole('region', { name: PANEL })).not.toHaveTextContent('Held rather than leaked')
  })

  // The moment the switch is for. Held and not-carrying are different outcomes -- one stops
  // the traffic here, the other lets it out the way it always went -- and only the card says
  // which of the two this machine is doing.
  it('says the traffic is held rather than not carried when the connection stops', async () => {
    const view = await at(THROUGH_A_CONNECTION, {
      'GET /api/egress': makeEgress({
        mode: 'tunnel',
        tunnelId: 'tn_office',
        tunnelName: 'Office',
        carrying: false,
        killSwitch: true,
        held: true,
        reason: 'Office is not running, so internet traffic is being held here.',
      }),
    })

    const panel = view.getByRole('region', { name: PANEL })
    expect(within(panel).getByText('held')).toBeInTheDocument()
    expect(panel).toHaveTextContent('being held here')
  })
})

// Internet traffic shared across several connections. The card's job here is different from
// the single-connection one: the set is not one thing, so "is it working" has an answer per
// member, and the failure it has to name is the traffic stopping here rather than leaving.
describe('internet traffic shared across connections', () => {
  const PANEL = 'Internet traffic'
  const SHARED: Partial<Settings> = {
    'egress.mode': 'multi',
    'egress.multi.tunnelIds': ['tn_office', 'tn_lab'],
  }

  it('asks which connections share it, and not for a single one', async () => {
    const view = await at(SHARED)

    expect(view.getByLabelText('Connections sharing it')).toBeInTheDocument()
    expect(view.queryByLabelText('Connection carrying it')).toBeNull()
  })

  // One row per member, because one of them being down has moved its share to the others
  // and left the rest working. A single line for the set could not say which.
  it('reports every connection sharing it, one at a time', async () => {
    const view = await at(SHARED, {
      'GET /api/egress': makeEgress({
        mode: 'multi',
        carrying: true,
        members: [
          { tunnelId: 'tn_office', tunnelName: 'Office', carrying: true },
          {
            tunnelId: 'tn_lab',
            tunnelName: 'Lab',
            carrying: false,
            reason: 'Lab is not running, so it is carrying none of it.',
          },
        ],
      }),
    })

    const panel = view.getByRole('region', { name: PANEL })
    expect(panel).toHaveTextContent('Office')
    expect(panel).toHaveTextContent('Lab')
    expect(panel).toHaveTextContent('Lab is not running, so it is carrying none of it.')
    expect(panel).toHaveTextContent('1 of 2 connections')
  })

  // Held and not-carrying are different outcomes, and the difference is the whole point of
  // the mode: one stops the traffic here, the other lets it out the way it always went.
  it('says the traffic is held when none of them is carrying it', async () => {
    const view = await at(SHARED, {
      'GET /api/egress': makeEgress({
        mode: 'multi',
        carrying: false,
        held: true,
        reason: 'none of these connections is carrying it, so it is being held here',
        members: [{ tunnelId: 'tn_office', tunnelName: 'Office', carrying: false }],
      }),
    })

    const panel = view.getByRole('region', { name: PANEL })
    expect(within(panel).getByText('held')).toBeInTheDocument()
    expect(panel).toHaveTextContent('being held here')
    expect(panel).not.toHaveTextContent('leaving this machine')
  })

  // The members belong to the mode that produced them. While the mode is being switched the
  // served view is still the previous one's, and rendering its rows under the new mode would
  // list connections nothing is using.
  it('shows no members while the traffic goes through a single connection', async () => {
    const view = await at(
      { 'egress.mode': 'tunnel', 'egress.tunnelId': 'tn_office' },
      {
        'GET /api/egress': makeEgress({
          mode: 'multi',
          carrying: true,
          members: [{ tunnelId: 'tn_lab', tunnelName: 'Lab', carrying: true }],
        }),
      },
    )

    expect(view.getByRole('region', { name: PANEL })).not.toHaveTextContent('Lab')
  })
})

// A chain is the same member list read differently: one route through all of them in
// order rather than several ways out. The position is the setting, since the first hop
// sees who you are and the last sees where you went, so every row has to say which it is.
describe('internet traffic chained through connections', () => {
  const PANEL = 'Internet traffic'
  const CHAINED: Partial<Settings> = {
    'egress.mode': 'multi',
    'egress.multi.tunnelIds': ['tn_office', 'tn_lab'],
    'egress.multi.shape': 'cascade',
  }

  it('numbers each hop, marks the one the internet sees, and names it in the head', async () => {
    const view = await at(CHAINED, {
      'GET /api/egress': makeEgress({
        mode: 'multi',
        shape: 'cascade',
        carrying: true,
        members: [
          { tunnelId: 'tn_office', tunnelName: 'Office', carrying: true },
          {
            tunnelId: 'tn_lab',
            tunnelName: 'Lab',
            carrying: true,
            exit: true,
            limits: ['Names are still looked up on this network.'],
          },
        ],
      }),
    })

    const panel = view.getByRole('region', { name: PANEL })
    const rows = [...panel.querySelectorAll('.egress-members li')]
    expect(rows.map((li) => li.querySelector('.egress-member-hop')?.textContent)).toEqual([
      'hop 1',
      'hop 2, out',
    ])
    expect(rows[1]).toHaveTextContent('Names are still looked up on this network.')
    expect(panel).toHaveTextContent('2 connections, out of Lab')
  })

  // A hop behind one that has not started is neither carrying nor failed. Every start of a
  // chain passes through it, so painting it as a failure would put one on the card every
  // time the app starts.
  it('shows a hop behind one still starting as waiting rather than failed', async () => {
    const view = await at(CHAINED, {
      'GET /api/egress': makeEgress({
        mode: 'multi',
        shape: 'cascade',
        carrying: false,
        members: [
          { tunnelId: 'tn_office', carrying: false, reason: 'Office is still connecting.' },
          { tunnelId: 'tn_lab', carrying: false, waiting: true, exit: true },
        ],
      }),
    })

    const panel = view.getByRole('region', { name: PANEL })
    const rows = [...panel.querySelectorAll('.egress-members li')]
    // Without names, the ids are what there is to show.
    expect(rows[0]).toHaveTextContent('tn_office')
    expect(rows[0]?.querySelector('.status')).toHaveClass('error')
    expect(rows[0]?.querySelector('.status')).toHaveTextContent('not carrying')
    expect(rows[0]).toHaveTextContent('Office is still connecting.')
    expect(rows[1]?.querySelector('.status')).toHaveClass('pending')
    expect(rows[1]?.querySelector('.status')).toHaveTextContent('waiting')
  })

  it('counts the chain when no hop is marked as the way out', async () => {
    const view = await at(CHAINED, {
      'GET /api/egress': makeEgress({
        mode: 'multi',
        shape: 'cascade',
        carrying: true,
        members: [
          { tunnelId: 'tn_office', tunnelName: 'Office', carrying: true },
          { tunnelId: 'tn_lab', tunnelName: 'Lab', carrying: true },
        ],
      }),
    })

    expect(view.getByRole('region', { name: PANEL })).toHaveTextContent(
      '2 connections in a chain',
    )
  })

  // The rows follow the shape the agent is running, not the one just chosen: a shape
  // switched in the draft applies to the connections on the next poll, and numbering rows
  // that are still sharing the traffic would describe a route that is not running.
  it('numbers nothing while the agent still reports the connections as sharing', async () => {
    const view = await at(CHAINED, {
      'GET /api/egress': makeEgress({
        mode: 'multi',
        shape: 'spread',
        carrying: true,
        members: [
          { tunnelId: 'tn_office', tunnelName: 'Office', carrying: true },
          { tunnelId: 'tn_lab', tunnelName: 'Lab', carrying: true },
        ],
      }),
    })

    const panel = view.getByRole('region', { name: PANEL })
    expect(panel.querySelector('.egress-member-hop')).toBeNull()
    expect(panel).toHaveTextContent('2 of 2 connections')
  })
})
