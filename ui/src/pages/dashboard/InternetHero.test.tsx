// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { InternetHero } from './InternetHero'
import { href } from '../../lib/router'
import type { EgressView, Settings } from '../../api'
import {
  makeEgress,
  makeSettings,
  makeSettingsResponse,
  makeSettingsSchema,
  pickerChosen,
  pickerCurrent,
  pickerRows,
  pickRow,
  renderAgent,
  settle,
} from '../../test/agent'
import { useSettingsDraft } from '../../components/settings/useSettingsDraft'

/** The card driven by the real settings form, so what these tests exercise is the write
 *  the agent would actually receive rather than a stub standing in for it. */
function Hero({ egress }: { egress?: EgressView }) {
  const form = useSettingsDraft()
  return <InternetHero form={form} view={egress} />
}

/** The connections the agent resolved into the picker's setting. The served schema carries
 *  them; the generated copy cannot, because it does not know this machine's connections. */
const CONNECTIONS = [
  { value: 'tn_office', label: 'Office', help: 'A WireGuard connection.' },
  { value: 'tn_lab', label: 'Lab', help: 'A WireGuard connection.' },
]

/** The routes behind the card: the schema with the connection list filled in, the stored
 *  document, and the answer to the write it makes. */
function routes(stored: Partial<Settings> = {}) {
  const settings = makeSettings(stored)
  const schema = makeSettingsSchema(settings)
  return {
    'GET /api/settings': settings,
    'GET /api/settings/schema': {
      ...schema,
      fields: schema.fields.map((f) =>
        f.key === 'egress.tunnelId' ? { ...f, options: CONNECTIONS } : f,
      ),
    },
    'PUT /api/settings': makeSettingsResponse(stored),
  }
}

const THROUGH_OFFICE = { 'egress.mode': 'tunnel', 'egress.tunnelId': 'tn_office' } as const

function carriedByOffice(over: Partial<EgressView> = {}) {
  return makeEgress({ mode: 'tunnel', tunnelId: 'tn_office', tunnelName: 'Office', carrying: true, ...over })
}

// The picker offers this machine's own network alongside the connections. A picker of
// connections alone could move the traffic away and never bring it back, which is the one
// thing somebody flipping this repeatedly has to be able to do.
describe('choosing where internet traffic goes', () => {
  it('offers this machine and every connection, and marks the one in force', async () => {
    const { container } = await renderAgent(<Hero egress={carriedByOffice()} />, routes(THROUGH_OFFICE))

    expect(pickerRows(container, 'Internet traffic')).toEqual([
      expect.stringContaining('Out of this machine'),
      expect.stringContaining('Office'),
      expect.stringContaining('Lab'),
    ])
    expect(pickerChosen(container, 'Internet traffic')).toBe('tn_office')
  })

  // Closed, the control answers the question somebody opening the dashboard has: where is
  // this machine's traffic going right now. The other destinations are the answer to a
  // question they have not asked, and two open lists pushed the rest of the page down.
  it('shows only the destination in force until it is clicked', async () => {
    const { container } = await renderAgent(<Hero egress={carriedByOffice()} />, routes(THROUGH_OFFICE))

    expect(pickerCurrent(container, 'Internet traffic')).toHaveTextContent('Office')
    expect(container.querySelectorAll('.choice-row')).toHaveLength(0)
  })

  // Choosing is the end of the question the list was opened to answer. A list left standing
  // would cover the state the card reports underneath it.
  it('closes once a destination is chosen', async () => {
    const view = await renderAgent(<Hero egress={makeEgress()} />, routes())

    pickRow(view.container, 'Internet traffic', 'tn_lab')
    await settle()

    expect(view.container.querySelectorAll('.choice-row')).toHaveLength(0)
  })

  // The connection is not read while the mode says the traffic leaves this machine, so a
  // write naming it alone would store a choice that does nothing.
  it('writes the mode and the connection together', async () => {
    const view = await renderAgent(<Hero egress={makeEgress()} />, routes())

    pickRow(view.container, 'Internet traffic', 'tn_lab')
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({
      'egress.mode': 'tunnel',
      'egress.tunnelId': 'tn_lab',
    })
  })

  // Going back leaves the connection named. That remembered choice is what lets somebody
  // switch back and forth without picking a connection again every time.
  it('sends the traffic back out of this machine without forgetting the connection', async () => {
    const view = await renderAgent(<Hero egress={carriedByOffice()} />, routes(THROUGH_OFFICE))

    pickRow(view.container, 'Internet traffic', '')
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({ 'egress.mode': 'direct' })
  })
})

describe('what the card says at its head', () => {
  // The setting is what was asked for and the view is what is happening. They differ
  // exactly when the chosen connection cannot carry the traffic, and that gap is invisible
  // from anywhere else on this page.
  it('says when the chosen connection is not carrying it', async () => {
    const view = await renderAgent(
      <Hero egress={carriedByOffice({ carrying: false, reason: 'Office has no exit node selected on it.' })} />,
      routes(THROUGH_OFFICE),
    )

    const panel = view.getByRole('region', { name: 'Internet' })
    expect(panel).toHaveTextContent('not carrying')
    expect(panel).toHaveTextContent('Office has no exit node selected on it.')
  })

  // Stopped is not the same as leaking, and the head is the only place this page says which
  // one is happening. Reported as "not carrying", a machine holding its traffic reads exactly
  // like one letting it out over the network it is sitting on.
  it('says the traffic is held rather than not carried when it is being stopped', async () => {
    const view = await renderAgent(
      <Hero
        egress={carriedByOffice({
          carrying: false,
          killSwitch: true,
          held: true,
          reason: 'Office is not running, so internet traffic is being held here.',
        })}
      />,
      routes(THROUGH_OFFICE),
    )

    const panel = view.getByRole('region', { name: 'Internet' })
    expect(panel).toHaveTextContent('held')
    expect(panel).not.toHaveTextContent('not carrying')
  })

  // A connection stays named while the traffic goes out directly, so the agent keeps
  // answering about it. Printing that answer would report a fault in an arrangement the
  // reader is not in.
  it('stays quiet about a remembered connection while the traffic leaves this machine', async () => {
    const view = await renderAgent(
      <Hero egress={makeEgress({ mode: 'direct', tunnelId: 'tn_office', reason: 'Office is not running.' })} />,
      routes({ 'egress.mode': 'direct', 'egress.tunnelId': 'tn_office' }),
    )

    const panel = view.getByRole('region', { name: 'Internet' })
    expect(panel).toHaveTextContent('leaving this machine')
    expect(panel).not.toHaveTextContent('Office is not running.')
  })

  it('carries the gear to the internet page', async () => {
    const view = await renderAgent(<Hero egress={makeEgress()} />, routes())

    expect(view.getByRole('link', { name: 'Internet settings' })).toHaveAttribute('href', href('internet'))
  })
})

// The kill switch is read only while one connection carries the traffic, so it is shown
// only then: a switch for the arrangement the reader is not in promises something that is
// not being kept.
describe('the kill switch', () => {
  it('is offered while a connection carries the traffic, showing the stored setting', async () => {
    const view = await renderAgent(
      <Hero egress={carriedByOffice({ killSwitch: true })} />,
      routes({ ...THROUGH_OFFICE, 'egress.killSwitch': true }),
    )

    expect(view.getByRole('checkbox', { name: 'Hold it rather than let it out' })).toBeChecked()
  })

  it('is not offered while the traffic leaves this machine', async () => {
    const view = await renderAgent(<Hero egress={makeEgress()} />, routes())

    expect(view.queryByRole('checkbox', { name: 'Hold it rather than let it out' })).toBeNull()
  })

  it('is written the moment it is flipped', async () => {
    const view = await renderAgent(<Hero egress={carriedByOffice()} />, routes(THROUGH_OFFICE))

    fireEvent.click(view.getByRole('checkbox', { name: 'Hold it rather than let it out' }))
    await settle()

    expect(view.agent.bodyOf('PUT /api/settings')).toEqual({ 'egress.killSwitch': true })
  })
})
