// SPDX-License-Identifier: MIT

import { fireEvent } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import {
  builtInDNSProfiles,
  makeDNSProfile,
  makeDNSSystem,
  makeSettings,
  makeSettingsResponse,
  openInfo,
  openPicker,
  rejectField,
  renderAgent,
  settingsRoutes,
  settle,
} from '../test/agent'
import { SystemDnsCard } from './SystemDnsCard'
import { useSettingsDraft } from './settings/useSettingsDraft'
import type { DNSSystemView } from '../api'

/** The card driven by the real settings form, which is what puts the write path under
 *  test rather than a stub of it. */
function Card({ view }: { view: DNSSystemView }) {
  const form = useSettingsDraft()
  return <SystemDnsCard view={view} form={form} />
}

/** The machine pointed at Cloudflare and answering, which is the state everything else on
 *  this card is a departure from. */
function resolving(overrides: Partial<DNSSystemView> = {}): DNSSystemView {
  return makeDNSSystem({
    enabled: true,
    applied: true,
    profile: 'cloudflare',
    profileLabel: 'Cloudflare',
    servers: ['1.1.1.1', '1.0.0.1'],
    protocols: ['plain', 'plain'],
    listen: '127.0.0.153:53',
    base: { nameservers: ['192.168.6.1'] },
    capability: { available: true, degraded: false, limits: [] },
    ...overrides,
  })
}

/** The routes a card that writes needs: the schema and document it reads its controls
 *  from, and the answer to the write it makes. */
function writable(settings: Partial<Parameters<typeof makeSettings>[0]> = {}) {
  return {
    ...settingsRoutes(makeSettings({ 'systemDns.enabled': true, 'systemDns.profile': 'cloudflare', ...settings })),
    'PUT /api/settings': makeSettingsResponse({ 'systemDns.enabled': true, ...settings }),
  }
}

// "The switch is on" and "this machine is actually resolving through app-tail" are
// different facts, and every gap between them has its own fix. A card that collapsed them
// would report a machine still on its router's DNS as working.
describe('what the card says the machine is doing', () => {
  it.each([
    ['the switch off', makeDNSSystem(), 'off'],
    ['System default chosen', makeDNSSystem({ enabled: true }), 'unchanged'],
    ['the override in force', resolving(), 'resolving through app-tail'],
    [
      'on but not applied',
      resolving({
        applied: false,
        capability: { available: true, degraded: true, reason: 'the helper is not installed' },
      }),
      'not in force',
    ],
    [
      'refused by the machine',
      resolving({
        applied: false,
        ready: false,
        blocker: 'this platform manages DNS in a way app-tail will not write',
        capability: { available: false, degraded: false, reason: 'this platform manages DNS in a way app-tail will not write' },
      }),
      'not in force',
    ],
  ])('shows %s as %s', async (_case, view, label) => {
    const { container } = await renderAgent(<Card view={view} />, writable())

    expect(container.querySelector('.panel-head .status')).toHaveTextContent(label)
  })
})

// A network that redirects port 53 answers plain queries itself: the override goes in, the
// counters climb, names resolve, and not one query reached the resolver that was picked.
// The card has to say so, and it must not say "not in force" -- the override is in force,
// and a reader sent looking for a setup step would find one that already happened.
describe('when this network answers the queries itself', () => {
  const INTERCEPTED =
    'This network answers plain DNS itself: a query addressed to a server that does not exist came back answered.'

  const view = resolving({
    intercepted: INTERCEPTED,
    capability: { available: true, degraded: true, reason: INTERCEPTED },
  })

  it('says the answers are not coming from the chosen resolver', async () => {
    const { getByText } = await renderAgent(<Card view={view} />, writable())

    expect(getByText(INTERCEPTED)).toBeInTheDocument()
  })

  it('reports it as this network answering rather than as an override that never went in', async () => {
    const { container } = await renderAgent(<Card view={view} />, writable())

    expect(container.querySelector('.panel-head .status')).toHaveTextContent(
      'this network is answering',
    )
  })
})

// The one claim this card must never let slip: it changes the machine, and it says which
// parts and how they are put back. The sentences hold in every state, including the one
// where everything is working -- which is exactly when someone decides whether to trust it.
describe('what it never oversells', () => {
  const LIMITS = [
    'While this is on, every program on this machine resolves names through app-tail.',
    'Names that belong to the network you are on keep going to that network resolver.',
  ]

  it.each([
    ['while it is resolving', resolving({ capability: { available: true, degraded: false, limits: LIMITS } })],
    ['while the switch is off', makeDNSSystem({ capability: { available: true, degraded: false, limits: LIMITS } })],
  ])('states the limits %s', async (_case, view) => {
    const { container } = await renderAgent(<Card view={view} />, writable())

    const info = openInfo(container, 'System resolver')
    for (const limit of LIMITS) expect(info).toHaveTextContent(limit)
  })

  it('keeps them out of the card until they are asked for', async () => {
    const { queryByText } = await renderAgent(
      <Card view={resolving({ capability: { available: true, degraded: false, limits: LIMITS } })} />,
      writable(),
    )

    for (const limit of LIMITS) expect(queryByText(limit)).not.toBeInTheDocument()
  })
})

describe('the resolver picker', () => {
  // Two profiles named "Work" and "Home" are indistinguishable by name alone, and which
  // resolver answers is the entire question this card exists for.
  it('names every profile in the catalog with what it resolves through', async () => {
    const { container } = await renderAgent(<Card view={resolving()} />, {
      ...writable(),
      'GET /api/dns/profiles': { profiles: [...builtInDNSProfiles(), makeDNSProfile()] },
    })

    const rows = [...openPicker(container, 'Resolver').querySelectorAll('.choice-row')].map(
      (r) => r.textContent,
    )
    expect(rows).toHaveLength(7)
    expect(
      rows.some(
        (r) => r?.includes('Cloudflare') && r.includes('https://1.1.1.1/dns-query, https://1.0.0.1/dns-query'),
      ),
    ).toBe(true)
    expect(rows.some((r) => r?.includes('NextDNS') && r.includes('https://dns.nextdns.io/abc123'))).toBe(true)
    expect(rows.some((r) => r?.includes('System default') && r.includes("Leaves this machine's own resolver"))).toBe(true)
    // The tailnet profile carries no servers of its own, so a row that only named it would
    // read as a profile with no resolvers rather than one whose resolvers come from the
    // tailnet.
    expect(
      rows.some((r) => r?.includes('Tailnet DNS') && r.includes('nameservers your tailnet publishes')),
    ).toBe(true)
  })

  // Closed, the control is the answer to "what is this machine resolving through", which is
  // the question somebody opening the page has. The rest of the catalog is the answer to a
  // question they have not asked yet.
  it('shows the profile in force without being opened', async () => {
    const { container } = await renderAgent(<Card view={resolving()} />, writable())

    expect(container.querySelector('.picker-current')).toHaveTextContent('Cloudflare')
    expect(container.querySelectorAll('.choice-row')).toHaveLength(0)
  })

  it('checks the profile in force and only that one', async () => {
    const { container } = await renderAgent(<Card view={resolving()} />, writable())

    const checked = [
      ...openPicker(container, 'Resolver').querySelectorAll<HTMLInputElement>('input'),
    ].filter((input) => input.checked)
    expect(checked.map((input) => input.value)).toEqual(['cloudflare'])
  })

  // Choosing is the end of the question the list was opened to answer, so the list closes
  // on it. Leaving it standing would cover the state the card reports underneath.
  it('closes once a profile is chosen', async () => {
    const { container } = await renderAgent(<Card view={resolving()} />, writable())

    const list = openPicker(container, 'Resolver')
    fireEvent.click(list.querySelector<HTMLInputElement>('input[value="google"]')!)
    await settle()

    expect(container.querySelectorAll('.choice-row')).toHaveLength(0)
  })

  // The switch travels with the profile, exactly as `app-tail dns use` and the menu bar
  // send them: the profile is refused while the switch governing it is off, so a picker that
  // wrote only the profile would leave the two disagreeing.
  it('switches profile with a single write carrying the switch as well', async () => {
    const { container, agent } = await renderAgent(<Card view={resolving()} />, {
      ...writable(),
      'GET /api/dns/profiles': { profiles: [...builtInDNSProfiles(), makeDNSProfile()] },
    })

    const list = openPicker(container, 'Resolver')
    fireEvent.click(list.querySelector<HTMLInputElement>('input[value="nextdns"]')!)
    await settle()

    expect(agent.countOf('PUT /api/settings')).toBe(1)
    expect(agent.bodyOf('PUT /api/settings')).toEqual({
      'systemDns.enabled': true,
      'systemDns.profile': 'nextdns',
    })
  })

  // System default means "change nothing about this machine", not "stay on pointing at a
  // profile with no servers". The switch goes on its own: the agent refuses a profile named
  // in the same write that turns its module off, and turning it off already puts the stored
  // profile back to System default.
  it('turns the module off when the profile that changes nothing is chosen', async () => {
    const { container, agent } = await renderAgent(<Card view={resolving()} />, writable())

    const list = openPicker(container, 'Resolver')
    fireEvent.click(list.querySelector<HTMLInputElement>('input[value="system"]')!)
    await settle()

    expect(agent.bodyOf('PUT /api/settings')).toEqual({ 'systemDns.enabled': false })
  })

  // A refusal that appears anywhere but under the control that caused it is one the user
  // reads as a page-wide fault rather than as an answer about the profile they just picked.
  it('puts a refused profile under the picker', async () => {
    const { container, getByText } = await renderAgent(<Card view={resolving()} />, {
      ...writable(),
      'PUT /api/settings': rejectField('systemDns.profile', 'no resolver profile is named nextdns'),
      'GET /api/dns/profiles': { profiles: [...builtInDNSProfiles(), makeDNSProfile()] },
    })

    const list = openPicker(container, 'Resolver')
    fireEvent.click(list.querySelector<HTMLInputElement>('input[value="nextdns"]')!)
    await settle()

    const notice = getByText(/no resolver profile is named nextdns/)
    expect(notice.closest('.choice-picker')).not.toBeNull()
  })
})

// Pointing the machine somewhere needs administrator rights once. The button that asks for
// them belongs beside the reason they are missing -- and nowhere near the radio buttons, so
// that picking a resolver never raises a password prompt nobody expected.
describe('arranging the machine', () => {
  it('offers the setup button only while the rights are missing', async () => {
    const arranged = await renderAgent(<Card view={resolving()} />, writable())
    expect(arranged.queryByRole('button', { name: 'Set this machine up' })).not.toBeInTheDocument()

    const missing = await renderAgent(
      <Card view={resolving({ applied: false, needsSetup: true })} />,
      writable(),
    )
    expect(missing.getByRole('button', { name: 'Set this machine up' })).toBeInTheDocument()
  })

  it('asks the agent to arrange it and says why it could not', async () => {
    const { getByRole, getByText, agent } = await renderAgent(
      <Card view={resolving({ applied: false, needsSetup: true })} />,
      { ...writable(), 'POST /api/dns/setup': rejectField('systemDns.enabled', 'the administrator prompt was declined') },
    )

    fireEvent.click(getByRole('button', { name: 'Set this machine up' }))
    await settle()

    expect(agent.countOf('POST /api/dns/setup')).toBe(1)
    expect(getByText(/the administrator prompt was declined/)).toBeInTheDocument()
  })
})

// A machine that cannot carry the override reports both the reason it cannot and the
// install that consequently failed. Printing both reads as two separate faults and sends
// somebody looking for a second thing to fix.
describe('why the machine is not resolving through app-tail', () => {
  const BLOCKER = 'the privileged helper is from another build of app-tail'

  it('states the cause once when the machine cannot carry it', async () => {
    const { container } = await renderAgent(
      <Card
        view={resolving({
          applied: false,
          ready: false,
          blocker: BLOCKER,
          error: `claim this machine's name resolution: ${BLOCKER}`,
          capability: { available: false, degraded: false, reason: BLOCKER },
        })}
      />,
      writable(),
    )

    const notices = [...container.querySelectorAll('.notice')].map((n) => n.textContent ?? '')
    expect(notices.filter((n) => n.includes(BLOCKER))).toHaveLength(1)
  })

  // A machine that could carry it and still failed is a fault of its own: the reason above
  // says the machine is fine, so swallowing the failure would leave the card explaining
  // nothing at all.
  it('states a failure the machine is ready for', async () => {
    const { getByText } = await renderAgent(
      <Card
        view={resolving({
          applied: false,
          ready: true,
          error: 'the address 127.0.0.153:53 is already in use',
          capability: { available: true, degraded: true, reason: 'this machine is not pointed at app-tail yet' },
        })}
      />,
      writable(),
    )

    expect(getByText(/already in use/)).toBeInTheDocument()
  })
})

// Each of these is a fact somebody opens the card to check, and none of them is derivable
// from the others.
describe('what it reports about the machine', () => {
  it('names the network own resolvers apart from the chosen ones', async () => {
    const { container } = await renderAgent(<Card view={resolving()} />, writable())

    const columns = [...container.querySelectorAll('.dns-list')].map((c) => c.textContent ?? '')
    expect(columns.some((c) => c.startsWith('Resolving through') && c.includes('1.1.1.1'))).toBe(true)
    expect(columns.some((c) => c.startsWith('This network') && c.includes('192.168.6.1'))).toBe(true)
  })

  it('says where app-tail answers and where the queries went', async () => {
    const { container } = await renderAgent(
      <Card
        view={resolving({
          queries: { total: 42, toProfile: 39, toLocal: 3, answered: 0, failed: 0, blocked: 0 },
        })}
      />,
      writable(),
    )

    expect(container.textContent).toContain('127.0.0.153:53')
    expect(container.textContent).toContain('42 lookups so far')
    expect(container.textContent).toContain('39 to your resolver')
  })

  // Which resolver turned a hostname into an address chose which server this machine is
  // really talking to. Saying so only when it went wrong would leave the reader unable to
  // tell a card that checked from one that has nothing to check.
  it('says what looked a resolver hostname up, and warns when this network did', async () => {
    const note = await renderAgent(
      <Card view={resolving({ bootstrap: 'Resolver hostnames were looked up through Quad9.' })} />,
      writable(),
    )
    expect(note.container.textContent).toContain('looked up through Quad9')
    expect(note.container.querySelector('.notice.warn')).not.toBeInTheDocument()

    const fellBack = await renderAgent(
      <Card
        view={resolving({
          bootstrap: "dns.nextdns.io was looked up through this network's own resolvers: Quad9 did not answer.",
          bootstrapDegraded: true,
        })}
      />,
      writable(),
    )
    expect(fellBack.container.querySelector('.notice.warn')?.textContent).toContain(
      "this network's own resolvers",
    )
  })

  // The one setting here that defeats a filtering resolver. Nobody should discover it by
  // noticing a blocked domain resolving again.
  it('warns while the NXDOMAIN retry is on', async () => {
    const { container } = await renderAgent(<Card view={resolving({ retryOnNxdomain: true })} />, writable())

    expect(container.textContent).toContain('no longer blocks it')
  })

  it('says nothing about lookups, servers or the listen address while the switch is off', async () => {
    const { container } = await renderAgent(<Card view={makeDNSSystem()} />, writable())

    expect(container.querySelector('.module-off')).toBeInTheDocument()
    expect(container.textContent).not.toContain('127.0.0.153:53')
    // The counters in either of their two forms. Matched on their own wording rather than on
    // the word "lookup", which the settings below the card use to explain themselves.
    expect(container.textContent).not.toContain('lookups so far')
    expect(container.textContent).not.toContain('No name has been looked up')
  })

  // Choosing a resolver is what turns this on, so the choices are the one thing that stays
  // on the card while it is off. Behind the switch they would be a feature nobody finds:
  // the switch alone names nothing it does.
  it('offers the resolvers while the switch is off, with none of them in force', async () => {
    const { container } = await renderAgent(<Card view={makeDNSSystem()} />, {
      ...writable(),
      'GET /api/dns/profiles': { profiles: [...builtInDNSProfiles(), makeDNSProfile()] },
    })

    const list = openPicker(container, 'Resolver')
    expect(list.querySelectorAll('.choice-row')).toHaveLength(7)
    const checked = [...list.querySelectorAll<HTMLInputElement>('input')].filter(
      (input) => input.checked,
    )
    expect(checked.map((input) => input.value)).toEqual(['system'])
  })

  // The one write that has to work from here, because it is how the feature is turned on at
  // all: the switch travels with the profile, exactly as it does when one is already chosen.
  it('turns the module on with the profile picked from the off state', async () => {
    const { container, agent } = await renderAgent(<Card view={makeDNSSystem()} />, {
      ...writable(),
      'GET /api/dns/profiles': { profiles: [...builtInDNSProfiles(), makeDNSProfile()] },
    })

    const list = openPicker(container, 'Resolver')
    fireEvent.click(list.querySelector<HTMLInputElement>('input[value="nextdns"]')!)
    await settle()

    expect(agent.bodyOf('PUT /api/settings')).toEqual({
      'systemDns.enabled': true,
      'systemDns.profile': 'nextdns',
    })
  })
})
