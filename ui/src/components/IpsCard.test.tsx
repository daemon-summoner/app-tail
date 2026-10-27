// SPDX-License-Identifier: MIT

import { fireEvent, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import {
  failWith,
  makeIPS,
  makeSettings,
  makeSettingsResponse,
  renderAgent,
  settingsRoutes,
  settle,
} from '../test/agent'
import { IpsCard } from './IpsCard'
import { useSettingsDraft } from './settings/useSettingsDraft'
import type { IPSView } from '../api'

/** The card driven by the real settings form, which is what puts the write path under
 *  test rather than a stub of it. */
function Card({ view, onChanged = () => {} }: { view: IPSView; onChanged?: () => void }) {
  const form = useSettingsDraft()
  return <IpsCard view={view} form={form} onChanged={onChanged} />
}

/** Inspection on, both signals on, entries compiled: the state everything else on this card
 *  is a departure from. */
function inspecting(overrides: Partial<IPSView> = {}): IPSView {
  return makeIPS({
    enabled: true,
    mode: 'detect',
    names: true,
    destinations: true,
    rules: 3,
    compiledAt: '2026-08-31T09:00:00Z',
    matched: 7,
    refused: 2,
    capability: { available: true, degraded: false, limits: [] },
    ...overrides,
  })
}

/** Two feeds from different publishers, one on and one off: the catalog is grouped, so a
 *  single publisher would never exercise the grouping the card puts the switches in. */
function feeds(): NonNullable<IPSView['feeds']> {
  return [
    {
      id: 'firehol-level1',
      provider: 'FireHOL',
      name: 'FireHOL level 1',
      url: 'https://feeds.example.test/level1.netset',
      builtIn: true,
      enabled: true,
      rules: 4231,
      skipped: 18,
      updatedAt: '2026-08-31T08:00:00Z',
    },
    {
      id: 'feodo',
      provider: 'abuse.ch',
      name: 'Feodo Tracker',
      url: 'https://feeds.example.test/feodo.txt',
      builtIn: true,
      enabled: false,
      rules: 0,
      skipped: 0,
      note: 'Command-and-control addresses of banking trojans.',
    },
  ]
}

/** One match, which is the shape the ring answers with. */
function match(overrides: Partial<NonNullable<IPSView['recent']>[number]> = {}) {
  return {
    at: '2026-08-31T09:05:00Z',
    signal: 'name',
    value: 'bad.example',
    source: 'your own entries',
    reason: 'bad.example is named by your own entries',
    where: 'the proxy',
    protocol: 'tcp',
    refused: false,
    ...overrides,
  }
}

/** The routes a card that writes needs: the schema and document it reads its controls from,
 *  and the answers to the writes it makes. */
function writable(settings: Partial<Parameters<typeof makeSettings>[0]> = {}) {
  const on = {
    'ips.enabled': true,
    'ips.names': true,
    'ips.destinations': true,
    ...settings,
  }
  return {
    ...settingsRoutes(makeSettings(on)),
    'PUT /api/settings': makeSettingsResponse(on),
    // The three writes that are not settings. They answer with the view, which is what the
    // page's own poll would have re-read.
    'POST /api/ips/pause': inspecting({ pausedUntil: '2099-01-01T00:00:00Z' }),
    'POST /api/ips/resume': inspecting(),
    'POST /api/ips/refresh': inspecting(),
    'POST /api/ips/preset': inspecting({ preset: 'ultimate' }),
  }
}

// Picking a level is the whole decision for most people, so the ladder has to say what each
// rung matches, mark the one in force, and admit when the feeds switched on are nobody's rung
// -- a picker that showed one selected anyway would misreport what the machine is doing.
describe('choosing a level', () => {
  it('offers every rung with what it matches, and marks the one in force', async () => {
    const { getByRole, container } = await renderAgent(<Card view={inspecting()} />, writable())

    const ladder = within(getByRole('radiogroup', { name: 'Level' }))
    expect(ladder.getByRole('radio', { name: /Minimum/ })).not.toBeChecked()
    expect(ladder.getByRole('radio', { name: /Medium/ })).toBeChecked()
    expect(ladder.getByRole('radio', { name: /Ultimate/ })).not.toBeChecked()
    expect(container.textContent).toContain('Every source on its widest tier.')
  })

  // Six rungs is five too many to read before choosing. The badge is what makes it one choice
  // with a default, so a rung marked recommended by the agent has to wear it -- and the rungs
  // beside it must not, or the mark says nothing.
  it('marks the recommended rung and only that one', async () => {
    const { getByRole } = await renderAgent(<Card view={inspecting()} />, writable())

    const ladder = within(getByRole('radiogroup', { name: 'Level' }))
    expect(ladder.getByRole('radio', { name: /Medium/ })).toHaveAccessibleName(/Recommended/)
    expect(ladder.getByRole('radio', { name: /Minimum/ })).not.toHaveAccessibleName(/Recommended/)
    expect(ladder.getByRole('radio', { name: /Ultimate/ })).not.toHaveAccessibleName(/Recommended/)
  })

  it('switches to the rung chosen and re-reads what that produced', async () => {
    let reread = 0
    const { agent, getByRole } = await renderAgent(
      <Card view={inspecting()} onChanged={() => (reread += 1)} />,
      writable(),
    )

    fireEvent.click(
      within(getByRole('radiogroup', { name: 'Level' })).getByRole('radio', { name: /Ultimate/ }),
    )
    await settle()

    expect(agent.bodyOf('POST /api/ips/preset')).toEqual({ preset: 'ultimate' })
    expect(reread).toBe(1)
  })

  it('says a set of feeds that is no level is exactly that, with nothing chosen', async () => {
    // A set of feeds the agent could not name a level for arrives with the field absent.
    const noLevel = inspecting()
    delete noLevel.preset
    const { getByRole, container } = await renderAgent(<Card view={noLevel} />, writable())

    const ladder = within(getByRole('radiogroup', { name: 'Level' }))
    for (const name of [/Minimum/, /Medium/, /Ultimate/]) {
      expect(ladder.getByRole('radio', { name })).not.toBeChecked()
    }
    expect(container.textContent).toContain('are not one of these levels')
  })

  it('shows what the agent refused rather than a level it never switched to', async () => {
    const { getByRole, container } = await renderAgent(<Card view={inspecting()} />, {
      ...writable(),
      'POST /api/ips/preset': failWith(400, 'that level is not one the agent carries'),
    })

    fireEvent.click(
      within(getByRole('radiogroup', { name: 'Level' })).getByRole('radio', { name: /Ultimate/ }),
    )
    await settle()

    expect(container.textContent).toContain('that level is not one the agent carries')
  })

  // The ladder is inside the module, so a card whose switch is off must not offer it: choosing
  // a level there writes feeds nothing inspects.
  it('offers no ladder while inspection is switched off', async () => {
    const { queryByRole } = await renderAgent(<Card view={makeIPS()} />, writable())

    expect(queryByRole('radiogroup', { name: 'Level' })).toBeNull()
  })
})

// "Inspection is switched on" and "connections are actually being checked" are different
// facts, and every gap between them has its own fix. A card that collapsed them would
// report a machine matching nothing as working. The agent's degraded state also covers a
// machine still matching its lists with one switch doing nothing, so the label sends the
// reader to the reason rather than saying nothing is inspected.
describe('what the card says inspection is doing', () => {
  it.each([
    ['the switch off', makeIPS(), 'off'],
    ['entries in force', inspecting(), 'recording'],
    ['prevent mode', inspecting({ mode: 'prevent' }), 'refusing'],
    [
      'neither signal on',
      inspecting({
        names: false,
        destinations: false,
        capability: {
          available: true,
          degraded: true,
          reason:
            'Inspection is on but neither what a connection is for nor where it is going is ' +
            'being looked at, so nothing is checked.',
        },
      }),
      'needs attention',
    ],
    [
      'encrypted connections being opened while the lists still match',
      inspecting({
        intercept: { ...makeIPS().intercept, mode: 'except', agreed: true, running: true, installed: true },
        capability: {
          available: true,
          degraded: true,
          reason: 'app-tail is opening encrypted connections to read them.',
        },
      }),
      'needs attention',
    ],
    [
      'paused',
      inspecting({
        pausedUntil: '2099-01-01T00:00:00Z',
        capability: { available: true, degraded: true, reason: 'Inspection is paused.' },
      }),
      'paused',
    ],
  ])('shows %s as %s', async (_case, view, label) => {
    const { container } = await renderAgent(<Card view={view} />, writable())

    expect(container.querySelector('.panel-head .status')).toHaveTextContent(label)
  })

  it('reports what is in force and what it has matched', async () => {
    const { container } = await renderAgent(<Card view={inspecting()} />, writable())

    expect(container.textContent).toContain('3 entries in force')
    expect(container.textContent).toContain('7 connections have matched, 2 of them refused')
  })

  // Nothing named is not a fault, and a count of zero read on its own sends somebody
  // looking for the download that never existed here: the entries are the ones they type.
  it('says nothing is named rather than showing a count of zero', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ rules: 0, matched: 0, refused: 0 })} />,
      writable(),
    )

    expect(container.textContent).toContain('Nothing has been named yet')
    expect(container.textContent).not.toContain('entries in force')
  })

  // An entry that is neither a domain nor an address is dropped at compile time and matches
  // nothing. Without this line it reads as an entry in force, which is the silent failure
  // this card exists to prevent.
  it('warns about entries that are neither a domain nor an address', async () => {
    const { container } = await renderAgent(<Card view={inspecting({ skipped: 2 })} />, writable())

    expect(container.textContent).toContain('2 entries are neither a domain nor an address')
  })

  // The watch matches against nothing that was typed, so its count folded into the matches
  // above would say a rule caught something no rule names.
  it('counts unusual patterns apart from what the entries matched', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ anomaly: true, anomalies: 4 })} />,
      writable(),
    )

    expect(container.textContent).toContain('4 runs of connections have looked unusual')
    expect(container.textContent).toContain('7 connections have matched, 2 of them refused')
  })

  // An empty list is the state a machine running only the pattern watch is meant to be in.
  // Telling that user to add an entry is telling them to fix something that is not broken.
  it('says the watch is running on a machine with nothing named', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ rules: 0, matched: 0, refused: 0, anomaly: true })} />,
      writable(),
    )

    expect(container.textContent).toContain('Unusual patterns are being watched for')
    expect(container.textContent).toContain('Nothing has looked unusual yet')
  })

  // The watch is off by default and off is the whole of what it does then: a card that
  // reported a count of zero would read as watching and finding nothing.
  it('says nothing about unusual patterns while the watch is off', async () => {
    const { container } = await renderAgent(<Card view={inspecting()} />, writable())

    expect(container.textContent).not.toContain('Unusual patterns are being watched for')
  })

  // A rhythm is an observation and the card has to say so: most of what keeps one is ordinary
  // software, and a list that read as findings would have somebody chasing their backup client.
  it('shows what is reached on a rhythm, and says nothing is refused for it', async () => {
    const { container } = await renderAgent(
      <Card
        view={inspecting({
          anomaly: true,
          beacons: [
            {
              source: 'this machine',
              addr: '93.184.216.34',
              every: 300,
              jitter: 0.02,
              count: 7,
              since: '2026-08-31T08:30:00Z',
            },
          ],
        })}
      />,
      writable(),
    )

    expect(container.textContent).toContain('93.184.216.34')
    expect(container.textContent).toContain('Every 5 minutes from this machine')
    expect(container.textContent).toContain('7 connections')
    expect(container.textContent).toContain('Nothing here is refused')
  })

  // The rhythms come off the same ledger the watch keeps. With the watch off there is no
  // ledger, so a heading offering to show them would be offering a list that cannot fill.
  it('says nothing about rhythms while the watch is off', async () => {
    const { container } = await renderAgent(
      <Card
        view={inspecting({
          beacons: [
            {
              source: 'this machine',
              addr: '93.184.216.34',
              every: 300,
              jitter: 0.02,
              count: 7,
              since: '2026-08-31T08:30:00Z',
            },
          ],
        })}
      />,
      writable(),
    )

    expect(container.textContent).not.toContain('Reached on a rhythm')
  })

  // Reading the start of a connection is what reaches traffic nothing asked app-tail about,
  // and that is a different claim from the entries matching: a card that said nothing about it
  // leaves the user unable to tell which of the two caught a connection dialled at an address.
  it('says the start of each connection is read while that is on', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ handshake: true })} />,
      writable(),
    )

    expect(container.textContent).toContain('The start of each connection is read')
    expect(container.textContent).toContain('dialled straight at an address')
  })

  // A machine with nothing named still reads the start of each connection, and that reading is
  // the only thing inspection is doing there.
  it('says the start of each connection is read on a machine with nothing named', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ rules: 0, matched: 0, refused: 0, handshake: true })} />,
      writable(),
    )

    expect(container.textContent).toContain('The start of each connection is read')
  })

  it('says nothing about reading connections while that is off', async () => {
    const { container } = await renderAgent(<Card view={inspecting()} />, writable())

    expect(container.textContent).not.toContain('The start of each connection is read')
  })

  // Fingerprinting is a separate switch under the same reading, so the line has to change with
  // it: promising a note that is never written is the same failure as writing one nobody asked
  // for.
  it('mentions the software fingerprint only while fingerprinting is on', async () => {
    const off = await renderAgent(<Card view={inspecting({ handshake: true })} />, writable())
    expect(off.container.textContent).not.toContain('Which family of software')

    const on = await renderAgent(
      <Card view={inspecting({ handshake: true, fingerprints: true })} />,
      writable(),
    )
    expect(on.container.textContent).toContain('Which family of software opened it is noted')
  })

  // The byte patterns are the one thing here with no feed behind it, and what they can do is
  // narrower than everything else on the card. A count on its own would read as the same kind
  // of coverage the entries have.
  it('counts the byte patterns and says what they cannot do', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ handshake: true, payload: true, signatures: 3 })} />,
      writable(),
    )

    expect(container.textContent).toContain('3 byte patterns are looked for')
    expect(container.textContent).toContain('Nothing encrypted is read')
    expect(container.textContent).toContain('stops the rest of that connection rather than')
  })

  // Switched on with nothing written is a switch waiting for its first pattern. A count of
  // zero folded into the line above would read as watching and finding nothing.
  it('says the patterns are on but none are written yet', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ handshake: true, payload: true, signatures: 0 })} />,
      writable(),
    )

    expect(container.textContent).toContain('none are written yet')
  })

  // A machine with nothing named still reads the patterns, and that reading is the only thing
  // inspection is doing there.
  it('counts the byte patterns on a machine with nothing named', async () => {
    const { container } = await renderAgent(
      <Card
        view={inspecting({
          rules: 0,
          matched: 0,
          refused: 0,
          handshake: true,
          payload: true,
          signatures: 1,
        })}
      />,
      writable(),
    )

    expect(container.textContent).toContain('1 byte pattern is looked for')
  })

  it('says nothing about byte patterns while they are off', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ handshake: true, signatures: 3 })} />,
      writable(),
    )

    expect(container.textContent).not.toContain('byte patterns are looked for')
    expect(container.textContent).not.toContain('none are written')
  })

  it('leaves the rhythm list out entirely while nothing keeps one', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ anomaly: true })} />,
      writable(),
    )

    expect(container.textContent).not.toContain('Reached on a rhythm')
  })
})

// Opening encrypted connections is the one thing on this card that changes what the programs on
// this machine see, and the one that needs a change made outside app-tail to work at all. A card
// that showed it as another switch would leave somebody unable to tell why every connection
// suddenly fails, or how to undo a certificate they installed last month.
describe('opening encrypted connections', () => {
  /** The interception block of the view, which every case here is a departure from. */
  function opening(overrides: Partial<IPSView['intercept']> = {}): Partial<IPSView> {
    return {
      intercept: {
        mode: 'only',
        agreed: true,
        on: true,
        running: true,
        destinations: 2,
        shipped: false,
        certPath: '/state/tls/ca.crt',
        fingerprint: 'AA:BB:CC:DD',
        expires: '2029-08-31T09:00:00Z',
        rootScope: 'only inside.example and 10.20.0.0/24',
        needsNewRoot: false,
        expiresSoon: false,
        expired: false,
        installed: true,
        install: 'security add-trusted-cert /state/tls/ca.crt',
        remove: 'security remove-trusted-cert /state/tls/ca.crt',
        opened: 12,
        failed: 0,
        ...overrides,
      },
    }
  }

  it('says connections are carried unopened while it is off', async () => {
    const { container } = await renderAgent(<Card view={inspecting()} />, writable())

    expect(container.textContent).toContain('carried without being opened')
    expect(container.textContent).not.toContain('/state/tls/ca.crt')
  })

  it('names what it is opening and says what that means', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting(opening())} />,
      writable(),
    )

    expect(container.textContent).toContain('presenting its own certificate')
    expect(container.textContent).toContain('only the 2 destinations named below')
    expect(container.textContent).toContain('readable here while this is on')
    expect(container.textContent).toContain('12 connections have been opened')
  })

  // The list app-tail ships is the answer to "why is this destination not being opened", and it
  // is not in the setting the user can see, so the card is the only place it can be said.
  it('says the list left alone is the one app-tail ships', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting(opening({ mode: 'except', destinations: 22, shipped: true }))} />,
      writable(),
    )

    expect(container.textContent).toContain('everything except the 22 destinations left alone')
    expect(container.textContent).toContain('the list app-tail ships')
  })

  // The state where every opened connection fails. Without this line the symptom is that the
  // machine's networking broke the moment interception was switched on.
  it('says so when this machine does not trust the certificate', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting(opening({ installed: false }))} />,
      writable(),
    )

    expect(container.textContent).toContain('does not trust the certificate')
    expect(container.textContent).toContain('until you install it')
    expect(container.textContent).toContain('AA:BB:CC:DD')
  })

  // Both commands, whatever state this is in: somebody who turned this on and wants out needs
  // the removal command without turning it back on to find it.
  it('shows the way in and the way out, and where the certificate is', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting(opening({ running: false, mode: 'off' }))} />,
      writable(),
    )
    expect(container.textContent).not.toContain('security remove-trusted-cert')

    const on = await renderAgent(<Card view={inspecting(opening())} />, writable())
    expect(on.container.textContent).toContain('security add-trusted-cert /state/tls/ca.crt')
    expect(on.container.textContent).toContain('security remove-trusted-cert /state/tls/ca.crt')
    expect(on.container.textContent).toContain('never leaves this machine')
  })

  // Set and not running is the state somebody arrives in after choosing a mode without
  // confirming they read what it does, and the card has to say which of the two is missing.
  it('says what is missing when it is set and nothing is being opened', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting(opening({ running: false, agreed: false }))} />,
      writable(),
    )

    expect(container.textContent).toContain('nothing is being opened')
    expect(container.textContent).toContain('Confirm you understand')
  })

  // Stopped rather than carried is the only visible sign of a destination that cannot be opened,
  // and it reads as an outage until the count says what happened.
  it('counts the connections stopped because the server could not be verified', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting(opening({ failed: 3 }))} />,
      writable(),
    )

    expect(container.textContent).toContain(
      '3 were stopped because the real server could not be verified',
    )
  })

  // Set, agreed to, and still not running is inspection itself being off: the confirmation is
  // not what is missing, and asking for it again would send somebody to re-tick a box.
  it('says inspection itself is off when the mode was agreed to and nothing is opened', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting(opening({ running: false, agreed: true }))} />,
      writable(),
    )

    expect(container.textContent).toContain('Traffic inspection itself is off.')
    expect(container.textContent).not.toContain('Confirm you understand')
  })

  // Before the first run there is no certificate to install, and a fingerprint line reading
  // as empty would look like a certificate with no fingerprint rather than none at all.
  it('says no certificate exists yet, and offers no commands for one', async () => {
    const bare = opening({ running: false, installed: false })
    delete bare.intercept!.fingerprint
    delete bare.intercept!.expires
    delete bare.intercept!.install
    delete bare.intercept!.remove
    const { container } = await renderAgent(<Card view={inspecting(bare)} />, writable())

    expect(container.textContent).toContain('No certificate has been generated yet.')
    expect(container.textContent).not.toContain('SHA-256')
    expect(container.textContent).not.toContain('impersonate websites')
    expect(container.textContent).not.toContain('Install it:')
    expect(container.textContent).not.toContain('Remove it:')
  })

  it('says when the certificate stops being usable, beside its fingerprint', async () => {
    const { container, getByLabelText } = await renderAgent(
      <Card view={inspecting(opening({ expires: '2029-08-31T09:00:00Z' }))} />,
      writable(),
    )

    expect(getByLabelText('SHA-256')).toHaveTextContent('AA:BB:CC:DD')
    expect(container.textContent).toContain(
      `It stops being usable ${new Date('2029-08-31T09:00:00Z').toLocaleString()}.`,
    )
  })

  // The fingerprint is how a person tells this root from any other in their trust store, so it
  // is shown the way trust stores list it, and the warning about the key sits beside it.
  it('shows the root fingerprint in pairs and warns what its key can do', async () => {
    const fingerprint = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    const { container, getByLabelText, getByRole } = await renderAgent(
      <Card view={inspecting(opening({ fingerprint }))} />,
      writable(),
    )

    const shown = getByLabelText('SHA-256')
    expect(shown).toHaveTextContent(
      '01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF',
    )
    expect(getByRole('region', { name: 'Root certificate' })).toContainElement(shown)
    expect(container.textContent).toContain(
      "Anyone who holds this root's private key can impersonate websites to this machine.",
    )
    expect(container.textContent).toContain(
      'This root can sign for only inside.example and 10.20.0.0/24.',
    )
    expect(container.textContent).toContain('app-tail ips remove-root')
  })

  // Off takes the key out of memory, not the root out of the trust store, so the root is still
  // shown with its warning and the way to remove it -- but not the way to install it.
  it('keeps showing a root left on disk while interception is off', async () => {
    const { container, getByLabelText } = await renderAgent(
      <Card view={inspecting(opening({ mode: 'off', on: false, running: false, installed: false }))} />,
      writable(),
    )

    expect(container.textContent).toContain('carried without being opened')
    expect(getByLabelText('SHA-256')).toHaveTextContent('AA:BB:CC:DD')
    expect(container.textContent).toContain('impersonate websites to this machine')
    expect(container.textContent).toContain('app-tail ips remove-root')
    expect(container.textContent).not.toContain('Install it:')
  })

  it('warns when the root is about to expire, and as an error once it has', async () => {
    const soon = await renderAgent(
      <Card
        view={inspecting(
          opening({ expiresSoon: true, expiryWarning: 'The interception root expires on 2029-08-31, in 12 days.' }),
        )}
      />,
      writable(),
    )
    const soonNotice = within(soon.container).getByText(/expires on 2029-08-31, in 12 days/)
    expect(soonNotice).toHaveClass('notice', 'warn')

    const gone = await renderAgent(
      <Card
        view={inspecting(
          opening({ expired: true, expiryWarning: 'The interception root expired on 2029-08-31, so nothing is opened.' }),
        )}
      />,
      writable(),
    )
    expect(within(gone.container).getByText(/expired on 2029-08-31/)).toHaveClass('notice', 'error')
  })

  it('says a new root is needed when the list reaches past the one installed', async () => {
    const reason =
      'The destinations to intercept now reach beyond what the installed root was made for.'
    const { container } = await renderAgent(
      <Card view={inspecting(opening({ needsNewRoot: true, newRootReason: reason }))} />,
      writable(),
    )

    expect(container.textContent).toContain(reason)

    const fine = await renderAgent(
      <Card view={inspecting(opening({ needsNewRoot: false, newRootReason: reason }))} />,
      writable(),
    )
    expect(fine.container.textContent).not.toContain(reason)
  })

  // A root file that cannot be read is announced as an error, not shown as no root at all.
  it('reports a root that could not be read as an error', async () => {
    const broken = opening({ rootError: 'The root certificate at /state/tls/ca.crt could not be read.' })
    delete broken.intercept!.fingerprint
    const { getByRole, container } = await renderAgent(<Card view={inspecting(broken)} />, writable())

    expect(getByRole('alert')).toHaveTextContent('could not be read')
    expect(container.textContent).not.toContain('No certificate has been generated yet.')
  })

  // The note is the agent's own word about this platform's trust store, and it exists only
  // when there is one to give.
  it('passes on what the agent says about this platform, when it says anything', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting(opening({ note: 'Firefox keeps its own trust store.' }))} />,
      writable(),
    )

    expect(container.textContent).toContain('Firefox keeps its own trust store.')
  })

  it('counts one destination, one opened connection and one stopped in the singular', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting(opening({ destinations: 1, opened: 1, failed: 1 }))} />,
      writable(),
    )

    expect(container.textContent).toContain('only the 1 destination named below')
    expect(container.textContent).toContain('1 connection has been opened.')
    expect(container.textContent).toContain('1 was stopped because the real server could not be verified')
  })

  // The root helper refuses interception nobody approved, which otherwise reads as a switch
  // that is on and does nothing.
  it('says interception is waiting for an administrator, and why', async () => {
    const reason = 'open encrypted connections and read what they carry'
    const { getByText } = await renderAgent(
      <Card view={inspecting(opening({ running: false, awaitingApproval: reason }))} />,
      writable(),
    )

    const notice = getByText(/Waiting for an administrator's approval/)
    expect(notice).toHaveClass('notice', 'warn')
    expect(notice).toHaveTextContent(reason)

    const approved = await renderAgent(<Card view={inspecting(opening())} />, writable())
    expect(approved.container.textContent).not.toContain("administrator's approval")
  })

  it('reports an approvals file that could not be read as an error', async () => {
    const problem = 'The approvals file /etc/app-tail/approvals.json could not be read.'
    const { getByRole } = await renderAgent(
      <Card view={inspecting(opening({ running: false, approvalError: problem }))} />,
      writable(),
    )

    expect(getByRole('alert')).toHaveTextContent(problem)
  })
})

// A pause is the control somebody reaches for with a broken connection in front of them, so
// it has to apply at once and say when it ends. It is held in memory, so nothing but this
// card reports it.
// A feed is the difference between inspection matching what somebody typed and inspection
// matching several hundred thousand addresses nobody could type. What each one contributed
// has to be visible per feed: a feed that downloaded nothing and a feed that is off look the
// same from the total.
describe('what each feed contributed', () => {
  it('shows the addresses kept and the ones left out of a feed', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ feeds: feeds() })} />,
      writable(),
    )

    expect(container.textContent).toContain('4,231 addresses, 18 left out')
  })

  it('names the failure on a feed that could not be downloaded', async () => {
    const failed = feeds()
    failed[0]!.error = 'connection refused'
    const { container } = await renderAgent(
      <Card view={inspecting({ feeds: failed })} />,
      writable(),
    )

    expect(container.textContent).toContain('connection refused')
  })

  it('writes the whole set of enabled feeds when one row is switched on', async () => {
    const { agent, container, getByLabelText } = await renderAgent(
      <Card view={inspecting({ feeds: feeds() })} />,
      writable(),
    )

    const switches = within(container.querySelector('.picker') as HTMLElement)
    fireEvent.click(switches.getByRole('button', { name: /abuse\.ch/ }))
    fireEvent.click(getByLabelText('Use Feodo Tracker'))
    await settle()

    expect(agent.bodyOf('PUT /api/settings')).toEqual({
      'ips.lists': ['firehol-level1', 'feodo'],
    })
  })

  it('drops a row from the set when it is switched off', async () => {
    const { agent, getByLabelText } = await renderAgent(
      <Card view={inspecting({ feeds: feeds() })} />,
      writable(),
    )

    fireEvent.click(getByLabelText('Use FireHOL level 1'))
    await settle()

    expect(agent.bodyOf('PUT /api/settings')).toEqual({ 'ips.lists': [] })
  })

  // A refused write changed nothing, so re-reading the view would only confirm that; the
  // reason belongs on the card, beside the row that asked for it.
  it('shows why a row could not be switched, and does not re-read the view', async () => {
    let reread = 0
    const { getByLabelText, container } = await renderAgent(
      <Card view={inspecting({ feeds: feeds() })} onChanged={() => (reread += 1)} />,
      { ...writable(), 'PUT /api/settings': failWith(400, 'that feed is not one the agent carries') },
    )

    fireEvent.click(getByLabelText('Use FireHOL level 1'))
    await settle()

    expect(reread).toBe(0)
    expect(container.textContent).toContain('that feed is not one the agent carries')
  })

  // The group holding a feed already on is the one somebody came to read, so it opens; the
  // rest stay shut or the switches are a wall nobody reads.
  it('opens the groups holding an enabled feed and leaves the rest shut', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ feeds: feeds() })} />,
      writable(),
    )
    const switches = within(container.querySelector('.picker') as HTMLElement)

    expect(switches.getByRole('button', { name: /FireHOL/ })).toHaveAttribute(
      'aria-expanded',
      'true',
    )
    const abuse = switches.getByRole('button', { name: /abuse\.ch/ })
    expect(abuse).toHaveAttribute('aria-expanded', 'false')
    expect(switches.queryByLabelText('Use Feodo Tracker')).toBeNull()

    fireEvent.click(abuse)

    expect(switches.getByLabelText('Use Feodo Tracker')).toBeTruthy()
  })

  // A feed that is off shows what it would carry rather than a count of zero, which reads as
  // a download that failed.
  it('describes a feed that is off rather than counting nothing', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ feeds: feeds() })} />,
      writable(),
    )
    const switches = within(container.querySelector('.picker') as HTMLElement)

    fireEvent.click(switches.getByRole('button', { name: /abuse\.ch/ }))
    expect(switches.getByRole('group', { name: 'abuse.ch' })).toHaveTextContent(
      'Command-and-control addresses of banking trojans.',
    )
  })

  it('says when every feed is due to be fetched again', async () => {
    const { container } = await renderAgent(
      <Card
        view={inspecting({
          feeds: feeds(),
          refreshHours: 12,
          nextRefresh: '2026-09-01T08:00:00Z',
        })}
      />,
      writable(),
    )

    expect(container.textContent).toContain('fetched again after 12 hours')
  })

  // Nothing named on a machine with a feed switched on is a download that has not landed
  // yet, not a machine with nothing to match: sending somebody to type an address would be
  // the wrong instruction.
  it('says a feed is chosen rather than telling somebody to name something', async () => {
    const waiting = feeds()
    waiting[0]!.rules = 0
    delete waiting[0]!.updatedAt
    const { container } = await renderAgent(
      <Card view={inspecting({ rules: 0, matched: 0, refused: 0, feeds: waiting })} />,
      writable(),
    )

    expect(container.textContent).toContain('Switch on a feed of known-bad addresses')
    expect(container.textContent).toContain('not downloaded yet')
  })

  it('shows what the last round of downloads ended with', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ feeds: feeds(), error: 'firehol level 1: 503' })} />,
      writable(),
    )

    expect(container.textContent).toContain('firehol level 1: 503')
  })

  // The same sentence in both places is one fault, and printing it twice reads as two.
  it('does not repeat the failure the capability is already reporting', async () => {
    const same = 'Every feed failed to download.'
    const { container } = await renderAgent(
      <Card
        view={inspecting({
          feeds: feeds(),
          error: same,
          capability: { available: true, degraded: true, reason: same },
        })}
      />,
      writable(),
    )

    expect(container.textContent?.match(new RegExp(same, 'g'))).toHaveLength(1)
  })
})

describe('pausing inspection', () => {
  it('pauses for the length on the button', async () => {
    const { agent, getByLabelText } = await renderAgent(<Card view={inspecting()} />, writable())

    fireEvent.click(getByLabelText('Pause inspection for 15 minutes'))
    await settle()

    expect(agent.bodyOf('POST /api/ips/pause')).toEqual({ minutes: 15 })
  })

  it('offers a way back while paused, and says when it ends by itself', async () => {
    const paused = inspecting({
      pausedUntil: '2099-01-01T00:00:00Z',
      capability: { available: true, degraded: true, reason: 'Inspection is paused.' },
    })
    const { agent, getByText, container } = await renderAgent(<Card view={paused} />, writable())

    expect(container.textContent).toContain('comes back by itself')

    fireEvent.click(getByText('Resume inspection'))
    await settle()

    expect(agent.countOf('POST /api/ips/resume')).toBe(1)
  })

  it('downloads on request without waiting for the schedule', async () => {
    const { agent, getByText } = await renderAgent(
      <Card view={inspecting({ feeds: feeds() })} />,
      writable(),
    )

    fireEvent.click(getByText('Download now'))
    await settle()

    expect(agent.countOf('POST /api/ips/refresh')).toBe(1)
  })

  it('shows what the agent refused rather than dropping it', async () => {
    const { getByLabelText, container } = await renderAgent(<Card view={inspecting()} />, {
      ...writable(),
      'POST /api/ips/pause': failWith(503, 'traffic inspection is not wired'),
    })

    fireEvent.click(getByLabelText('Pause inspection for 5 minutes'))
    await settle()

    expect(container.textContent).toContain('traffic inspection is not wired')
  })
})

// Somebody arrives at this card with a broken connection in front of them, and the question
// is whether inspection is what broke it. Only the agent can answer: it holds the compiled
// entries, and it knows the answers that are not about an entry at all.
describe('asking whether one destination is stopped', () => {
  const check = (answer: unknown) => ({ ...writable(), 'GET /api/ips/check': answer })

  it('asks about the destination typed in and names the entry that matched', async () => {
    const { agent, getByLabelText, getByText, container } = await renderAgent(
      <Card view={inspecting()} />,
      check({
        destination: '10.1.2.9',
        matched: true,
        refused: true,
        signal: 'destination',
        value: '10.1.2.0/24',
        source: 'your own entries',
        reason:
          'the address is in 10.1.2.0/24, which is named by your own entries, and is refused',
      }),
    )

    fireEvent.change(getByLabelText('Would a destination be stopped?'), {
      target: { value: '10.1.2.9' },
    })
    fireEvent.click(getByText('Check'))
    await settle()

    expect(agent.urlOf('GET /api/ips/check')).toContain('dest=10.1.2.9')
    expect(container.textContent).toContain('10.1.2.0/24')
    expect(container.textContent).toContain('is refused')
  })

  it('says a destination is carried rather than only that nothing matched', async () => {
    const { getByLabelText, getByText, container } = await renderAgent(
      <Card view={inspecting()} />,
      check({
        destination: 'example.com',
        matched: false,
        refused: false,
        reason: 'nothing you have named matches this, so it is carried',
      }),
    )

    fireEvent.change(getByLabelText('Would a destination be stopped?'), {
      target: { value: 'example.com' },
    })
    fireEvent.click(getByText('Check'))
    await settle()

    expect(container.textContent).toContain('example.com: nothing you have named matches this')
  })

  it('shows what the agent refused rather than an answer it never gave', async () => {
    const { getByLabelText, getByText, container } = await renderAgent(
      <Card view={inspecting()} />,
      check(failWith(400, 'name a domain or an address to check')),
    )

    fireEvent.change(getByLabelText('Would a destination be stopped?'), {
      target: { value: 'example.com' },
    })
    fireEvent.click(getByText('Check'))
    await settle()

    expect(container.textContent).toContain('name a domain or an address to check')
  })
})

// The ring is the whole of what a fresh install can show: the activity log is off until
// somebody turns it on, so a card that only linked to it would inspect, match, and display
// nothing.
describe('what has matched recently', () => {
  it('says nothing has been reported rather than showing an empty list', async () => {
    const { container } = await renderAgent(<Card view={inspecting()} />, writable())

    expect(container.textContent).toContain('Nothing has been reported yet')
  })

  it('names what matched, where, and whether it was carried', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ recent: [match()] })} />,
      writable(),
    )

    expect(container.textContent).toContain('bad.example')
    expect(container.textContent).toContain('Recorded and carried on the proxy')
  })

  it('says a match was refused when prevention turned it away', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ mode: 'prevent', recent: [match({ refused: true })] })} />,
      writable(),
    )

    expect(container.textContent).toContain('Refused on the proxy')
  })

  // Inbound is the one path that knows which device asked, and that is the whole reason a
  // match there is worth more than "something reached that address".
  it('names the device that asked for an inbound match', async () => {
    const { container } = await renderAgent(
      <Card
        view={inspecting({
          recent: [match({ where: 'the tailnet', peer: '100.64.0.9' })],
        })}
      />,
      writable(),
    )

    expect(container.textContent).toContain('asked for by 100.64.0.9')
  })

  // The fingerprint is what a match off the wire carries and a match on a name asked for never
  // does. It is enrichment and nothing is matched on it, so it belongs on the line that says
  // what happened rather than anywhere that reads as a rule.
  it('names the software that opened a connection read off the wire', async () => {
    const { container } = await renderAgent(
      <Card
        view={inspecting({
          handshake: true,
          fingerprints: true,
          recent: [
            match({
              signal: 'handshake',
              where: 'the network interface',
              fingerprint: 't13d1516h2_8daaf6152771_b0da82dd1658',
            }),
          ],
        })}
      />,
      writable(),
    )

    expect(container.textContent).toContain(
      'opened by software fingerprinted t13d1516h2_8daaf6152771_b0da82dd1658',
    )
  })

  // A match on a name a program asked app-tail for carries no fingerprint, and a line that
  // trailed off after "opened by software fingerprinted" would be worse than no line.
  it('says nothing about software for a match that carries no fingerprint', async () => {
    const { container } = await renderAgent(
      <Card view={inspecting({ recent: [match()] })} />,
      writable(),
    )

    expect(container.textContent).not.toContain('opened by software fingerprinted')
  })
})

// Switching the module off has to leave the settings reachable: somebody who turned it off
// because it broke a connection comes back to change what is named, not to turn it on blind.
describe('the module switch', () => {
  it('writes the switch and says what off means', async () => {
    const { agent, container, getByLabelText } = await renderAgent(
      <Card view={makeIPS()} />,
      writable({ 'ips.enabled': false }),
    )

    expect(container.textContent).toContain('goes through untouched')

    fireEvent.click(getByLabelText('Inspect the traffic app-tail carries'))
    await settle()

    expect(agent.bodyOf('PUT /api/settings')).toEqual({ 'ips.enabled': true })
  })
})
