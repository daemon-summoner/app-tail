// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { deferred, emptySettingsForm, failWith, makeRoutes, openInfo, renderAgent, settle } from '../test/agent'
import { RoutesCard } from './RoutesCard'
import type { RouteCheckResult, RoutesView } from '../api'

function card(view: Partial<RoutesView>) {
  return <RoutesCard view={makeRoutes({ enabled: true, ...view })} form={emptySettingsForm()} app={emptySettingsForm()} />
}

/** The list under one heading, as the reader sees it. */
function listUnder(container: HTMLElement, title: string): string[] {
  const heading = [...container.querySelectorAll('.routes-list h3')].find(
    (h) => h.textContent === title,
  )
  const column = heading?.closest('.routes-list')
  if (!column) throw new Error(`no route list titled ${title}`)
  return [...column.querySelectorAll('li')].map((li) => li.textContent ?? '')
}

// Advertising is a request an admin has to grant, so the two lists are different facts.
// Collapsing them into one "your networks" list is what makes the single most common
// failure -- advertised, never approved -- indistinguishable from a working route.
it('keeps what this device offers apart from what the tailnet approved', async () => {
  const { container } = await renderAgent(
    card({ advertised: ['10.20.0.0/24', '10.30.0.0/24'], approved: ['10.20.0.0/24'] }),
  )

  expect(listUnder(container, 'Offering')).toEqual(['10.20.0.0/24', '10.30.0.0/24'])
  expect(listUnder(container, 'Approved')).toEqual(['10.20.0.0/24'])
})

// A module nobody switched on and a module that could not start both arrive from the
// agent as unavailable. Painting the first one red puts a failure on the card for every
// feature the user has deliberately left alone.
it('reads a module nobody turned on as off rather than as a failure', async () => {
  const { container } = await renderAgent(
    <RoutesCard
      view={makeRoutes({
        enabled: false,
        capability: { available: false, degraded: false, reason: 'the module is switched off' },
      })}
      form={emptySettingsForm()}
      app={emptySettingsForm()}
    />,
  )

  const status = container.querySelector('.panel-head .status')
  expect(status).toHaveClass('status', 'off')
  expect(status).not.toHaveClass('error')
})

// Three empty columns read as a page that failed to load. Each is empty for a different
// reason and only one of them is something the reader can act on.
describe('empty lists', () => {
  it('says nobody is advertising when this device is accepting routes', async () => {
    const { getByText } = await renderAgent(card({ accepting: true }))

    expect(
      getByText('No device on your tailnet is advertising a network to this one.'),
    ).toBeInTheDocument()
  })

  it('says this device is not accepting when that is the reason instead', async () => {
    const { getByText } = await renderAgent(card({ accepting: false }))

    expect(
      getByText('This device is not accepting the networks its peers advertise.'),
    ).toBeInTheDocument()
  })
})

// The limits are what a userspace router cannot do at all -- UDP above everything. Left
// off the card each one is filed as a bug against a router working as far as it can.
describe('the limits a userspace router cannot get past', () => {
  const TCP_ONLY =
    'This device carries TCP only: DNS, QUIC and VoIP do not cross a route it serves.'

  const limited = () =>
    card({
      serving: false,
      capability: { available: true, degraded: true, limits: [TCP_ONLY] },
    })

  it('states them even while nothing is being carried', async () => {
    const { container } = await renderAgent(limited())

    expect(openInfo(container, 'Subnet routes')).toHaveTextContent(TCP_ONLY)
  })

  // They hold on every machine and never change, so they sit behind the button rather
  // than above the three columns that say what is actually being routed. Reaching them
  // has to stay one press away, which is what asserting the absence pins: a limit found
  // without opening anything is a limit that leaked back onto the card.
  it('keeps them out of the card until they are asked for', async () => {
    const { queryByText } = await renderAgent(limited())

    expect(queryByText(TCP_ONLY)).not.toBeInTheDocument()
  })
})

// Advertising and approval are the pair readers most often confuse, and the sentence that
// separates them is one press from the column it describes rather than a paragraph
// wedged between the heading and the prefixes.
describe('what each column means', () => {
  const APPROVED = 'What your tailnet actually routes here. Advertising is only a request.'

  it('explains the column when asked', async () => {
    const { container } = await renderAgent(card({ approved: ['10.20.0.0/24'] }))

    expect(openInfo(container, 'Approved')).toHaveTextContent(APPROVED)
  })

  it('leads with the prefixes rather than the explanation', async () => {
    const { queryByText } = await renderAgent(card({ approved: ['10.20.0.0/24'] }))

    expect(queryByText(APPROVED)).not.toBeInTheDocument()
  })
})

// Counters are meaningful once something is being carried and misleading before: a row
// of zeroes on a router nobody asked to do anything reads as one that is failing.
describe('counters', () => {
  it('reports the traffic once this device is carrying it', async () => {
    const { container } = await renderAgent(
      card({ serving: true, carried: 4, refused: 2, bytesIn: 2048, bytesOut: 1024 }),
    )

    const counters = [...container.querySelectorAll('.proxy-counters div')].map(
      (row) => row.textContent,
    )
    expect(counters).toEqual(['Carried4', 'Refused2', 'In2.0 KB', 'Out1.0 KB'])
  })

  it('are absent while nothing is being carried', async () => {
    const { container } = await renderAgent(card({ serving: false }))

    expect(container.querySelector('.proxy-counters')).toBeNull()
  })
})

// The reason the module as a whole is doing nothing and the last failure that stopped it
// carrying traffic are different sentences. Showing only the first leaves a device that
// is advertised, approved and refusing every connection with nothing on screen to say so.
it('shows the failure that stopped it carrying alongside the module reason', async () => {
  const { getByText } = await renderAgent(
    card({
      serving: false,
      error: 'the tailnet node is not running',
      capability: {
        available: true,
        degraded: true,
        reason: 'Your tailnet routes these networks here, but carrying traffic is switched off.',
      },
    }),
  )

  expect(getByText('the tailnet node is not running')).toBeInTheDocument()
  expect(
    getByText('Your tailnet routes these networks here, but carrying traffic is switched off.'),
  ).toBeInTheDocument()
})

describe('checking reachability', () => {
  // A probe on every poll would reach out to every device advertising a route four times
  // a minute for a page nobody is reading.
  it('probes only when asked', async () => {
    const { agent, getByRole } = await renderAgent(card({ accepting: true }), {
      'POST /api/routes/check': { routes: [] },
    })

    expect(agent.countOf('POST /api/routes/check')).toBe(0)

    fireEvent.click(getByRole('button', { name: 'Check reachability' }))
    await settle()

    expect(agent.countOf('POST /api/routes/check')).toBe(1)
  })

  // A route in the netmap that nothing answers for looks identical to a working one
  // everywhere else on this page, which is the entire reason to run the probe.
  it('names the devices that answered and the networks nothing did', async () => {
    const { getByText } = await renderAgent(card({ accepting: true }), {
      'POST /api/routes/check': {
        routes: [
          { prefix: '192.168.1.0/24', via: ['gateway'], reachable: true },
          { prefix: '10.9.0.0/16', reachable: false },
        ],
      },
    })

    fireEvent.click(getByText('Check reachability'))
    await settle()

    expect(getByText('carried by gateway')).toBeInTheDocument()
    // The tone as well as the words: a row that reads as a problem at a glance is the
    // only part of this a reader scanning a long list actually takes in.
    expect(getByText('no device answered for it').className).toContain('stopped')
  })

  // An empty answer with no explanation reads as "no device is reachable", which is a
  // different and much more alarming statement than "there was nothing to check".
  it('passes on the reason an empty answer was empty', async () => {
    const { getByText } = await renderAgent(card({ accepting: true }), {
      'POST /api/routes/check': {
        routes: [],
        reason: 'No device on your tailnet is advertising a network to this one.',
      },
    })

    fireEvent.click(getByText('Check reachability'))
    await settle()

    // The list above says the same thing about the netmap; this one is the answer to the
    // probe, so both are on screen and the assertion is that neither replaced the other.
    expect(
      getByText('No device on your tailnet is advertising a network to this one.', {
        selector: '.notice',
      }),
    ).toBeInTheDocument()
  })

  // A refusal that vanished would leave the reader believing the probe ran and found
  // nothing, which is the same thing the page says when every route is unreachable.
  it('shows the agent’s refusal rather than an empty result', async () => {
    const { getByText, queryByText } = await renderAgent(card({ accepting: true }), {
      'POST /api/routes/check': failWith(503, 'the tailnet node is not running'),
    })

    fireEvent.click(getByText('Check reachability'))
    await settle()

    expect(getByText('the tailnet node is not running')).toBeInTheDocument()
    expect(queryByText('Nothing was checked.')).toBeNull()
  })

  it('cannot be pressed twice while the first probe is still open', async () => {
    const pending = deferred<RouteCheckResult>()
    const { agent, getByRole } = await renderAgent(card({ accepting: true }), {
      'POST /api/routes/check': () => pending.promise,
    })

    const button = getByRole('button', { name: 'Check reachability' })
    fireEvent.click(button)
    await settle(1)
    expect(button).toBeDisabled()

    pending.resolve({ routes: [] })
    await settle()
    expect(agent.countOf('POST /api/routes/check')).toBe(1)
  })
})
