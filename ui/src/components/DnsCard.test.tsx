// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { emptySettingsForm, makeDNS, makeTunnel, openInfo, renderAgent } from '../test/agent'
import { DnsCard } from './DnsCard'
import type { DNSView, TunnelView } from '../api'

/** The two sentences the agent attaches in every state, which is the point of them. */
const LIMITS = [
  "Only app-tail's own connections use your tailnet's DNS. Other programs keep the resolver they already had.",
  'Names your tailnet serves -- device names and split-DNS domains -- resolve through app-tail’s proxy or its forwards, and nowhere else on this machine.',
]

/** The module on and resolving, which is the state a reader is most likely to misread as
 *  "this machine now uses my tailnet's DNS". */
function card(view: Partial<DNSView> = {}, tunnels: readonly TunnelView[] = []) {
  return (
    <DnsCard
      view={makeDNS({
        enabled: true,
        using: true,
        magicDNS: true,
        capability: { available: true, degraded: false, limits: LIMITS },
        ...view,
      })}
      form={emptySettingsForm()}
      tunnels={tunnels}
    />
  )
}

/** The list under one heading, as the reader sees it. */
function listUnder(container: HTMLElement, title: string): string[] {
  const heading = [...container.querySelectorAll('.dns-list h3')].find(
    (h) => h.textContent === title,
  )
  const column = heading?.closest('.dns-list')
  if (!column) throw new Error(`no DNS list titled ${title}`)
  return [...column.querySelectorAll('li')].map((li) => li.textContent ?? '')
}

// The single most important property of this card. app-tail configures the resolver inside
// its own process and changes nothing about the machine; a card that stopped saying so once
// everything was working is exactly the one a user reads as "my browser resolves through my
// tailnet now", and then files the browser not resolving as a bug.
describe('what it never oversells', () => {
  it('states the limits while everything is resolving', async () => {
    const { container } = await renderAgent(card())

    const info = openInfo(container, 'Tailnet DNS')
    for (const limit of LIMITS) expect(info).toHaveTextContent(limit)
  })

  it('states the same limits while the module is off', async () => {
    const { container } = await renderAgent(
      <DnsCard
        view={makeDNS({ capability: { available: false, degraded: false, limits: LIMITS } })}
        form={emptySettingsForm()}
        tunnels={[]}
      />,
    )

    const info = openInfo(container, 'Tailnet DNS')
    for (const limit of LIMITS) expect(info).toHaveTextContent(limit)
  })

  // The sentences are reachable on demand rather than stacked above the live answer, so
  // the card leads with what is resolving right now. Reachable is the whole promise
  // though: if these ever render while the popover is shut, they are back to being three
  // paragraphs of furniture -- and a test that found them without opening anything would
  // no longer be proving a user can get to them.
  it('keeps the limits out of the card until they are asked for', async () => {
    const { container, queryByText } = await renderAgent(card())

    for (const limit of LIMITS) expect(queryByText(limit)).not.toBeInTheDocument()

    expect(container.querySelector('.info-trigger')).toBeInTheDocument()
  })
})

// This machine's own resolver is the half that answers "why doesn't my browser resolve
// foo.corp". Rendered as a blank column it reads as a panel that failed to load, when the
// reason is the answer.
describe('this machine', () => {
  it('gives the reason nothing is configured here rather than an empty column', async () => {
    const { getByText } = await renderAgent(
      card({
        machineReason:
          'app-tail does not change how this machine resolves names. Every program other than app-tail keeps using the resolver it already had.',
      }),
    )

    expect(
      getByText(
        'app-tail does not change how this machine resolves names. Every program other than app-tail keeps using the resolver it already had.',
      ),
    ).toBeInTheDocument()
  })

  // In a mode where app-tail did write the machine's resolver, hiding what it wrote would
  // leave the one fact worth auditing off the screen.
  it('lists what it did write when the machine is managed', async () => {
    const { container } = await renderAgent(
      card({
        machine: { nameservers: ['100.100.100.100'], matchDomains: ['corp.example.com'] },
      }),
    )

    expect(listUnder(container, 'This machine')).toEqual([
      '100.100.100.100',
      'corp.example.comsent to your tailnet',
    ])
  })
})

// Two empty columns read as a failed load. Each is empty because the tailnet publishes
// nothing, which is a fact rather than a fault.
describe('what the tailnet publishes', () => {
  it('lists the nameservers and search domains it does publish', async () => {
    const { container } = await renderAgent(
      card({ resolvers: ['100.100.100.100'], searchDomains: ['tail1234.ts.net'] }),
    )

    expect(listUnder(container, 'Your tailnet')).toEqual(['100.100.100.100'])
    expect(listUnder(container, 'Search domains')).toEqual(['tail1234.ts.net'])
  })

  it('says so when it publishes neither', async () => {
    const { getByText } = await renderAgent(card())

    expect(getByText('Your tailnet publishes no nameserver of its own.')).toBeInTheDocument()
    expect(getByText('Your tailnet publishes no search domain.')).toBeInTheDocument()
  })
})

// A split-DNS domain resolves for app-tail and for nothing else on the machine, which is
// precisely the surprise this card exists to explain.
describe('split DNS', () => {
  it('names the resolver each domain is answered by', async () => {
    const { getByText } = await renderAgent(
      card({ routes: [{ suffix: 'corp.example.com', resolvers: ['10.0.0.53'] }] }),
    )

    expect(getByText('corp.example.com')).toBeInTheDocument()
    expect(getByText('10.0.0.53')).toBeInTheDocument()
  })

  // A domain the tailnet routes with no nameserver of its own is answered by the tailnet
  // itself; a blank beside it reads as a route that is misconfigured.
  it('says the tailnet answers a domain with no resolver of its own', async () => {
    const { getByText } = await renderAgent(card({ routes: [{ suffix: 'corp.example.com' }] }))

    expect(getByText("answered by your tailnet's own resolver")).toBeInTheDocument()
  })

  it('leaves the block out when the tailnet routes no domain', async () => {
    const { container } = await renderAgent(card())

    expect(container.textContent).not.toContain('Split DNS')
  })
})

it('lists the records the tailnet serves beyond its own devices', async () => {
  const { getByText } = await renderAgent(
    card({ records: [{ name: 'git.example.com', type: 'A', value: '10.0.0.9' }] }),
  )

  expect(getByText('git.example.com')).toBeInTheDocument()
  expect(getByText('A 10.0.0.9')).toBeInTheDocument()
})

// This is the property people choose an exit node for, and it is not otherwise observable
// from this machine. Which device is doing the resolving is the part that matters.
describe('resolving through the exit node', () => {
  it('names the device doing the lookups', async () => {
    const { getByText } = await renderAgent(
      card({ exitNodeResolving: true, exitNodeLabel: 'amsterdam' }),
    )

    expect(
      getByText(
        'Names outside your tailnet are being looked up by amsterdam, not from this machine.',
      ),
    ).toBeInTheDocument()
  })

  it('says nothing while the exit node is not answering', async () => {
    const { container } = await renderAgent(card({ exitNodeLabel: 'amsterdam' }))

    expect(container.textContent).not.toContain('are being looked up by')
  })
})

// Device names not resolving is a different situation from them resolving, and both are
// ordinary. A card that only ever said one of them would be wrong half the time.
describe('device names', () => {
  it('says they resolve when the tailnet answers for them', async () => {
    const { getByText } = await renderAgent(card({ magicDNS: true }))

    expect(getByText('Device names resolve through your tailnet.')).toBeInTheDocument()
  })

  it('says they do not when the tailnet does not', async () => {
    const { getByText } = await renderAgent(card({ magicDNS: false }))

    expect(getByText('Device names do not resolve through your tailnet.')).toBeInTheDocument()
  })
})

describe('the state it names', () => {
  const cases: Array<[string, Partial<DNSView>, string, string]> = [
    [
      'the module is off',
      { capability: { available: false, degraded: false, limits: LIMITS } },
      'off',
      'off',
    ],
    [
      'the tailnet DNS is switched off',
      { capability: { available: true, degraded: true, limits: LIMITS } },
      'not resolving through your tailnet',
      'pending',
    ],
    [
      'everything is resolving',
      { capability: { available: true, degraded: false, limits: LIMITS } },
      'resolving through your tailnet',
      'running',
    ],
  ]

  for (const [name, view, label, tone] of cases) {
    it(`says ${label} when ${name}`, async () => {
      const { getByText } = await renderAgent(card(view))

      expect(getByText(label).className).toContain(tone)
    })
  }
})

describe('a failed read', () => {
  const failed = "reading the tailnet's DNS configuration failed: context deadline exceeded"

  // The agent reports the failure as the module's reason too, because it is why the module
  // is degraded. Rendering both slots verbatim reads as two separate faults.
  it('is stated once when it is also the reason the module is degraded', async () => {
    const { getAllByText } = await renderAgent(
      card({
        error: failed,
        capability: { available: true, degraded: true, reason: failed, limits: LIMITS },
      }),
    )

    expect(getAllByText(failed, { selector: '.notice' })).toHaveLength(1)
  })

  it('is stated alongside a reason that says something else', async () => {
    const { getByText } = await renderAgent(
      card({
        error: failed,
        capability: {
          available: true,
          degraded: true,
          reason: "Using your tailnet's DNS is switched off.",
          limits: LIMITS,
        },
      }),
    )

    expect(getByText(failed, { selector: '.notice' })).toBeInTheDocument()
    expect(getByText("Using your tailnet's DNS is switched off.")).toBeInTheDocument()
  })
})

// Whether app-tail resolves through a network is that connection's own setting now, so
// this card is where the answer for every connection is read at once -- and the row has to
// reach the page that changes it, or the setting is findable only by someone who already
// knows where it went.
describe('which connections answer names', () => {
  it('names each connection and says whether names go through it', async () => {
    const answering = makeTunnel({})
    const quiet = makeTunnel({ id: 'tn_lab', name: 'Lab', slug: 'lab' })
    const { getByRole, container } = await renderAgent(
      card({}, [
        { ...answering, settings: { ...answering.settings, 'dns.useTailnet': true } },
        { ...quiet, settings: { ...quiet.settings, 'dns.useTailnet': false } },
      ]),
    )

    expect(listUnder(container, 'Answered by')).toEqual([
      "Tailnetnames are looked up through this network's DNS",
      'Labnot used for name resolution',
    ])
    expect(getByRole('link', { name: 'Tailnet' })).toHaveAttribute(
      'href',
      '#/connections/tailscale/tn_primary',
    )
  })

  // A connection whose kind keeps no resolver of its own is not answering names and is not
  // failing to either, so it is absent rather than listed as switched off.
  it('leaves out a connection that holds no resolver setting', async () => {
    const { container } = await renderAgent(
      card({}, [makeTunnel({ id: 'tn_office', type: 'wireguard', name: 'Office', slug: 'office' })]),
    )

    expect(container.querySelector('.dns-list h3')?.textContent).not.toBe('Answered by')
  })
})
