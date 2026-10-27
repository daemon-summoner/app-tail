// SPDX-License-Identifier: MIT

import { useState } from 'react'
import {
  api,
  ApiError,
  type IPSCheckView,
  type IPSFeedView,
  type IPSInterceptView,
  type IPSView,
} from '../api'
import { groupByProvider } from '../lib/catalog'
import { BlockLevels } from './BlockLevels'
import { BlocklistGroup } from './BlocklistGroup'
import { InfoList } from './InfoPopover'
import { IpsFeedManager } from './IpsFeedManager'
import { ModuleOff } from './ModuleOff'
import { Panel } from './Panel'
import { CardSettings, ModuleSwitch } from './settings/CardSettings'
import type { SettingsForm } from './settings/useSettingsDraft'
import { CopyButton, Notice, Toggle } from './primitives'

/** The lengths a pause is offered in, the same three blocking offers: long enough to get
 *  the connection that broke through, short enough that nobody finds inspection still off
 *  next week without having chosen that. */
const PAUSE_CHOICES = [5, 15, 60] as const

/** The state inspection is in, as one word and the colour that goes with it. The agent has
 *  already decided this in `capability`; this only names it. Degraded covers a machine
 *  matching nothing, one with a switch on that does nothing, and one opening encrypted
 *  connections, so the label points at the reason under it rather than claiming which. */
export function inspectState(view: IPSView): { tone: string; label: string } {
  if (!view.enabled) return { tone: 'off', label: 'off' }
  if (view.pausedUntil) return { tone: 'pending', label: 'paused' }
  if (view.capability.degraded) return { tone: 'pending', label: 'needs attention' }
  return { tone: 'running', label: view.mode === 'prevent' ? 'refusing' : 'recording' }
}

/** A moment the agent reported, in this machine's own zone. Anything unreadable is left
 *  exactly as it arrived rather than shown as "Invalid Date". */
function when(stamp: string | undefined): string {
  if (stamp === undefined) return ''
  const at = new Date(stamp)
  return Number.isNaN(at.getTime()) ? stamp : at.toLocaleString()
}

/** A gap between connections, in the largest unit it reads cleanly in. A rhythm is only
 *  reported at five seconds and above, so there is no sub-second case to carry. */
function gap(seconds: number): string {
  const say = (value: number, unit: string) =>
    `${Math.round(value)} ${unit}${Math.round(value) === 1 ? '' : 's'}`
  if (seconds < 90) return say(seconds, 'second')
  if (seconds < 90 * 60) return say(seconds / 60, 'minute')
  return say(seconds / 3600, 'hour')
}

/** The watch for unusual patterns, stated separately because it matches against nothing that
 *  was typed: on a machine with an empty list it is the only thing inspection is doing, and a
 *  count folded into the matches above would say a rule caught something. */
function Anomalies({ view }: { view: IPSView }) {
  if (!view.anomaly) return null
  return (
    <p className="hint">
      Unusual patterns are being watched for.{' '}
      {view.anomalies === 0
        ? 'Nothing has looked unusual yet.'
        : `${view.anomalies.toLocaleString()} ${view.anomalies === 1 ? 'run of connections has' : 'runs of connections have'} looked unusual.`}
    </p>
  )
}

/** What reading the start of each connection adds, stated separately because it is the one
 *  signal that reaches traffic nothing asked app-tail about: a program with its own resolver
 *  gave no name to the check that happens before a connection is made. */
function Handshakes({ view }: { view: IPSView }) {
  if (!view.handshake) return null
  return (
    <p className="hint">
      The start of each connection is read, so a connection dialled straight at an address is
      still matched on the name inside it.
      {view.fingerprints
        ? ' Which family of software opened it is noted on each match.'
        : ''}
    </p>
  )
}

/** The user's own byte patterns, stated separately because they are the only thing here
 *  matched against something with no feed behind it, and because what they can do is narrower
 *  than the rest: nothing encrypted, nothing past the opening, and a match stops the rest of a
 *  connection rather than preventing it. */
function Signatures({ view }: { view: IPSView }) {
  if (!view.payload) return null
  if (view.signatures === 0) {
    return (
      <p className="hint">
        Your own byte patterns are switched on; none are written yet, so nothing extra is
        looked for until one is.
      </p>
    )
  }
  return (
    <p className="hint">
      {view.signatures.toLocaleString()}{' '}
      {view.signatures === 1 ? 'byte pattern is' : 'byte patterns are'} looked for in the start
      of each connection, in what is sent in the clear. Nothing encrypted is read, and a match
      stops the rest of that connection rather than preventing it.
    </p>
  )
}

/**
 * Opening encrypted connections: what it is doing, what this machine has to be told to make
 * it work, and how to undo it.
 *
 * It is the one part of this card that describes a change outside app-tail. The certificate
 * has to be installed by hand and removed by hand, so both commands are here whatever state
 * this is in -- somebody who turned this on last month and wants out needs the second one
 * without having to turn the first back on to find it.
 */
function Interception({ view }: { view: IPSView }) {
  const held = view.intercept
  const naming =
    held.mode === 'only'
      ? `only the ${held.destinations.toLocaleString()} ${held.destinations === 1 ? 'destination' : 'destinations'} named below`
      : `everything except the ${held.destinations.toLocaleString()} ${held.destinations === 1 ? 'destination' : 'destinations'} left alone${held.shipped ? ', which is the list app-tail ships' : ''}`

  if (held.mode === 'off') {
    return (
      <>
        <p className="hint">
          Encrypted connections are carried without being opened, so nothing inside them is read.
        </p>
        {held.fingerprint || held.rootError ? <RootCertificate held={held} /> : null}
      </>
    )
  }

  return (
    <div className="field">
      <span className="field-caption">Opening encrypted connections</span>
      {held.running ? (
        <Notice tone="warn">
          app-tail is opening encrypted connections and presenting its own certificate:{' '}
          {naming}. Everything those connections carry is readable here while this is on.
        </Notice>
      ) : (
        <Notice tone="warn">
          Set to open {naming}, and nothing is being opened.{' '}
          {held.agreed
            ? 'Traffic inspection itself is off.'
            : 'Confirm you understand what opening a connection does, in the settings below, to start.'}
        </Notice>
      )}
      {held.approvalError ? (
        <div role="alert">
          <Notice tone="error">{held.approvalError}</Notice>
        </div>
      ) : null}
      {held.awaitingApproval ? (
        <Notice tone="warn">
          Waiting for an administrator&apos;s approval: {held.awaitingApproval}
        </Notice>
      ) : null}

      <p className="hint">
        {held.installed
          ? 'This machine trusts the certificate app-tail presents.'
          : 'This machine does not trust the certificate app-tail presents, so every connection it opens fails until you install it.'}
      </p>
      <RootCertificate held={held} />
      <p className="hint">
        The certificate is written to <code>{held.certPath}</code>. Its private key never leaves
        this machine and is never sent anywhere.
      </p>
      {held.install ? (
        <p className="hint">
          Install it: <code>{held.install}</code>
        </p>
      ) : null}
      {held.remove ? (
        <p className="hint">
          Remove it: <code>{held.remove}</code>
        </p>
      ) : null}
      {held.note ? <p className="hint">{held.note}</p> : null}
      <p className="hint">
        {held.opened.toLocaleString()}{' '}
        {held.opened === 1 ? 'connection has' : 'connections have'} been opened.{' '}
        {held.failed === 0
          ? 'None was stopped because it could not be opened.'
          : `${held.failed.toLocaleString()} ${held.failed === 1 ? 'was' : 'were'} stopped because the real server could not be verified.`}
      </p>
    </div>
  )
}

/** A hex SHA-256 the way certificate viewers and trust stores list one: upper case, in
 *  colon-separated pairs. Anything else is shown exactly as it arrived. */
function formatFingerprint(hex: string): string {
  if (!/^[0-9a-f]{64}$/i.test(hex)) return hex
  return (hex.toUpperCase().match(/../g) ?? []).join(':')
}

/** The root interception signs with, shown whenever one exists, interception on or off: it
 *  stays in the trust store either way, and so does what its key can do. */
function RootCertificate({ held }: { held: IPSInterceptView }) {
  if (held.rootError) {
    return (
      <div role="alert">
        <Notice tone="error">{held.rootError}</Notice>
      </div>
    )
  }
  if (!held.fingerprint) {
    return <p className="hint">No certificate has been generated yet.</p>
  }
  const fingerprint = formatFingerprint(held.fingerprint)
  return (
    <section className="field" aria-labelledby="ips-root-caption">
      <span className="field-caption" id="ips-root-caption">
        Root certificate
      </span>
      <div className="proxy-address">
        <span className="proxy-address-label" id="ips-root-fingerprint">
          SHA-256
        </span>
        <code className="mono" aria-labelledby="ips-root-fingerprint">
          {fingerprint}
        </code>
        <CopyButton text={fingerprint} />
      </div>
      {held.rootScope || held.expires ? (
        <p className="hint">
          {[
            held.rootScope ? `This root can sign for ${held.rootScope}.` : '',
            held.expires ? `It stops being usable ${when(held.expires)}.` : '',
          ]
            .filter(Boolean)
            .join(' ')}
        </p>
      ) : null}
      <Notice tone="warn">
        Anyone who holds this root&apos;s private key can impersonate websites to this machine.
        Keep the key file private, and remove the root when you stop using interception.
      </Notice>
      {held.expiryWarning ? (
        <Notice tone={held.expired ? 'error' : 'warn'}>{held.expiryWarning}</Notice>
      ) : null}
      {held.needsNewRoot && held.newRootReason ? (
        <Notice tone="warn">{held.newRootReason}</Notice>
      ) : null}
      <p className="hint">
        To take it out of this machine&apos;s trust store and delete it, switch interception off
        and run <code>app-tail ips remove-root</code>.
      </p>
    </section>
  )
}

/** What the rules hold and what they have matched. The pair is the difference between rules
 *  that are loaded and rules that are doing something: entries come from what was typed,
 *  and matches only ever come from a connection that was made. */
function Counters({ view }: { view: IPSView }) {
  if (view.rules === 0) {
    return (
      <>
        <p className="hint">
          Nothing has been named yet, so no connection is matched against a list. Switch on a
          feed of known-bad addresses below, or add a domain or an address of your own.
        </p>
        <Handshakes view={view} />
        <Signatures view={view} />
        <Anomalies view={view} />
      </>
    )
  }
  return (
    <>
      <p className="hint">
        {view.rules.toLocaleString()} {view.rules === 1 ? 'entry' : 'entries'} in force
        {view.compiledAt ? `, last built ${when(view.compiledAt)}` : ''}.{' '}
        {view.matched.toLocaleString()}{' '}
        {view.matched === 1 ? 'connection has' : 'connections have'} matched,{' '}
        {view.refused.toLocaleString()} of them refused.
      </p>
      <Handshakes view={view} />
      <Signatures view={view} />
      <Anomalies view={view} />
      {view.skipped > 0 ? (
        <Notice tone="warn">
          {view.skipped.toLocaleString()}{' '}
          {view.skipped === 1 ? 'entry is' : 'entries are'} neither a domain nor an address, so
          nothing is matched against {view.skipped === 1 ? 'it' : 'them'}.
        </Notice>
      ) : null}
    </>
  )
}

/**
 * Pausing and downloading: the two things here that are not settings.
 *
 * A pause is held in memory and never stored, so it cannot outlive the agent, and it takes
 * effect on the next connection rather than on the next reconcile -- inspection somebody
 * cannot un-break in one click is what makes a false positive cost them their machine.
 */
function Controls({ view, onChanged }: { view: IPSView; onChanged: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)

  const run = async (action: () => Promise<unknown>) => {
    setBusy(true)
    setError(undefined)
    try {
      await action()
      onChanged()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="row-actions">
        <button className="btn small" disabled={busy} onClick={() => void run(api.refreshIps)}>
          {busy ? 'Working…' : 'Download now'}
        </button>
        {view.pausedUntil ? (
          <button className="btn small" disabled={busy} onClick={() => void run(api.resumeIps)}>
            Resume inspection
          </button>
        ) : (
          PAUSE_CHOICES.map((minutes) => (
            <button
              key={minutes}
              className="btn ghost small"
              disabled={busy}
              aria-label={`Pause inspection for ${minutes} minutes`}
              onClick={() => void run(() => api.pauseIps(minutes))}
            >
              Pause {minutes}m
            </button>
          ))
        )}
      </div>
      {view.pausedUntil ? (
        <Notice tone="warn">
          Paused until {when(view.pausedUntil)}. Every connection is carried until then, and
          inspection comes back by itself.
        </Notice>
      ) : null}
      {error ? <Notice tone="error">{error}</Notice> : null}
    </>
  )
}

/**
 * What the rules say about one destination.
 *
 * The agent answers it rather than the browser, because the rules live there and the answer
 * has to be the one a connection would actually get -- including the reasons that are not
 * about a rule at all, such as the signal it would match on being switched off.
 */
function CheckDestination() {
  const [dest, setDest] = useState('')
  const [result, setResult] = useState<IPSCheckView | undefined>(undefined)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)

  const check = async () => {
    setBusy(true)
    setError(undefined)
    try {
      setResult(await api.checkIps(dest))
    } catch (cause) {
      setResult(undefined)
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="field">
      <label htmlFor="ips-check">Would a destination be stopped?</label>
      <div className="row-actions">
        <input
          id="ips-check"
          type="text"
          value={dest}
          onChange={(e) => setDest(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && dest.trim() !== '') void check()
          }}
        />
        <button
          className="btn small"
          disabled={busy || dest.trim() === ''}
          onClick={() => void check()}
        >
          {busy ? 'Checking…' : 'Check'}
        </button>
      </div>
      {result ? (
        <p className="hint">
          {result.destination === ''
            ? result.reason
            : `${result.destination}: ${result.reason}.`}
        </p>
      ) : null}
      {error ? <Notice tone="error">{error}</Notice> : null}
    </div>
  )
}

/**
 * What has matched recently.
 *
 * The agent keeps these in memory rather than only in the activity log, because that log is
 * off until somebody turns it on: without this list a fresh install would inspect traffic,
 * match it, and show nothing at all.
 */
function Recent({ view }: { view: IPSView }) {
  const recent = view.recent ?? []
  if (recent.length === 0) {
    return <p className="hint">Nothing has been reported yet.</p>
  }
  return (
    <div className="picker">
      {recent.map((match, at) => (
        // The index is part of the key because two connections to the same destination in
        // the same second are two matches, and both belong on the list.
        <div key={`${match.at}:${at}`} className="picker-item static">
          <span className="title">{match.value}</span>
          <span className="sub">
            {match.reason}. {match.refused ? 'Refused' : 'Recorded and carried'} on{' '}
            {match.where}
            {match.protocol ? ` (${match.protocol})` : ''}
            {match.peer ? `, asked for by ${match.peer}` : ''}
            {match.fingerprint ? `, opened by software fingerprinted ${match.fingerprint}` : ''}.
          </span>
          <span className="spacer" />
          <span className="sub">{when(match.at)}</span>
        </div>
      ))}
    </div>
  )
}

/**
 * Destinations something keeps going back to on a rhythm.
 *
 * These are an observation and never a finding: on an ordinary machine the regular things are
 * chat clients, backup software, certificate checks and app-tail's own list refresh, and no
 * threshold separates those from a program checking in. So they are shown apart from the
 * matches, nothing is refused for being here, and the list says as much.
 */
function Rhythms({ view }: { view: IPSView }) {
  const beacons = view.beacons ?? []
  if (!view.anomaly || beacons.length === 0) return null
  return (
    <div className="field">
      <span className="field-caption">Reached on a rhythm</span>
      <p className="hint">
        Regular check-ins, most regular first. Nothing here is refused or counted as unusual:
        most of what keeps a rhythm is ordinary software doing so on purpose.
      </p>
      <div className="picker">
        {beacons.map((beacon) => (
          <div key={`${beacon.source}:${beacon.addr}`} className="picker-item static">
            <span className="title">{beacon.addr}</span>
            <span className="sub">
              Every {gap(beacon.every)} from {beacon.source}, {beacon.count.toLocaleString()}{' '}
              {beacon.count === 1 ? 'connection' : 'connections'} since {when(beacon.since)}.
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

/** One feed: its switch, what it contributed, and when its copy was last confirmed current.
 *  `skipped` is shown beside the count because these files carry the private, reserved and
 *  tailnet ranges on purpose, and every one of those is dropped rather than applied -- a feed
 *  that looks smaller here than the publisher says is that working, not a download that
 *  half-arrived. */
function FeedRow({
  feed,
  busy,
  onToggle,
}: {
  feed: IPSFeedView
  busy: boolean
  onToggle: (on: boolean) => void
}) {
  return (
    <div className="picker-item static">
      <Toggle
        checked={feed.enabled}
        onChange={onToggle}
        label={`Use ${feed.name}`}
        disabled={busy}
      />
      <span className="title">{feed.name}</span>
      <span className="sub">
        {feed.enabled && feed.rules > 0
          ? `${feed.rules.toLocaleString()} addresses${feed.skipped > 0 ? `, ${feed.skipped.toLocaleString()} left out` : ''}`
          : (feed.note ?? feed.url)}
      </span>
      <span className="spacer" />
      {feed.error ? <span className="sub">{feed.error}</span> : null}
      <span className="sub">
        {feed.updatedAt ? when(feed.updatedAt) : feed.enabled ? 'not downloaded yet' : ''}
      </span>
      {feed.builtIn ? <span className="sub">built-in</span> : null}
    </div>
  )
}

/**
 * The curated ladder, lowest first.
 *
 * Choosing a rung is the whole decision for most people, so each one carries the sentence that
 * says what it adds rather than only its name. A rung switches on exactly the shipped feeds it
 * names and leaves the feeds the user added alone, which is why a machine can sit on a level
 * and still carry its own feed.
 */
function Levels({ view, onChanged }: { view: IPSView; onChanged: () => void }) {
  return (
    <BlockLevels
      levels={view.presets ?? []}
      chosen={view.preset}
      choose={(id) => api.applyIpsPreset(id).then(onChanged)}
      hint={
        view.preset === undefined
          ? 'The feeds switched on are not one of these levels. Choosing one replaces them, and leaves the feeds you added alone.'
          : 'A level switches on exactly the feeds it names, and leaves the feeds you added alone.'
      }
    />
  )
}

/**
 * Traffic inspection, the card.
 *
 * `onChanged` re-reads the view the page polls: pausing and resuming change what this card
 * is reporting without changing a setting, so nothing else would bring the new state back
 * before the next poll.
 */
export function IpsCard({
  view,
  form,
  onChanged,
}: {
  view: IPSView
  form: SettingsForm
  onChanged: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)
  const state = inspectState(view)
  const feeds = view.feeds ?? []

  // The switch on a row writes the whole set of enabled ids, because that is what the
  // setting is: a row's own state has nowhere else to live.
  const toggleFeed = async (id: string, on: boolean) => {
    const wanted = feeds.filter((f) => (f.id === id ? on : f.enabled)).map((f) => f.id)
    setBusy(true)
    setError(undefined)
    try {
      const outcome = await form.applyPatch({ 'ips.lists': wanted })
      if (outcome.stored) onChanged()
      else setError(outcome.reason)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Panel
      title="Traffic inspection"
      wide
      id="ips"
      status={{
        tone: state.tone,
        label: state.label,
        ...(view.enabled && view.rules > 0
          ? { detail: `${view.rules.toLocaleString()} ${view.rules === 1 ? 'entry' : 'entries'}` }
          : {}),
      }}
      info={
        <>
          <p>
            Check every connection app-tail carries against the domains and addresses you name
            and the feeds of known-bad addresses you switch on, and either record what matches
            or refuse it. Feeds are downloaded and kept on this machine, so one that cannot be
            reached keeps matching from the copy already here, and nothing is sent anywhere to
            decide: the check happens on this machine.
          </p>
          <p>
            It can also watch what a run of connections adds up to -- one device reaching many
            ports on another, one reaching a great many addresses at once, data leaving inside
            DNS queries -- which needs no entries at all. That watch is the only part of this
            that keeps a record of where traffic went, held in memory for a minute and never
            written down.
          </p>
          <InfoList items={view.capability.limits ?? []} />
        </>
      }
      controls={<ModuleSwitch form={form} switchKey="ips.enabled" />}
    >
      {!view.enabled ? (
        <ModuleOff>
          Off. Every connection app-tail carries goes through untouched. Switch this on to check
          each one against the domains and addresses you name.
        </ModuleOff>
      ) : (
        <>
          {view.capability.reason ? (
            <Notice tone={view.capability.available ? 'warn' : 'error'}>
              {view.capability.reason}
            </Notice>
          ) : null}

          {/* The agent puts the same sentence in both places when what went wrong is also
              what is holding inspection back, so printing it twice would read as two faults. */}
          {view.error && view.error !== view.capability.reason ? (
            <Notice tone="error">{view.error}</Notice>
          ) : null}

          <Counters view={view} />
          <Interception view={view} />
          <Controls view={view} onChanged={onChanged} />
          <CheckDestination />

          {error ? <Notice tone="error">{error}</Notice> : null}

          <Levels view={view} onChanged={onChanged} />

          <div className="picker">
            {groupByProvider(feeds).map((group) => (
              <BlocklistGroup
                key={group.provider}
                provider={group.provider}
                count={group.items.length}
                noun="feed"
                defaultOpen={group.items.some((feed) => feed.enabled)}
              >
                {group.items.map((feed) => (
                  <FeedRow
                    key={feed.id}
                    feed={feed}
                    busy={busy || form.saving}
                    onToggle={(on) => void toggleFeed(feed.id, on)}
                  />
                ))}
              </BlocklistGroup>
            ))}
          </div>

          {view.nextRefresh ? (
            <p className="hint">
              Every feed is fetched again after {view.refreshHours}{' '}
              {view.refreshHours === 1 ? 'hour' : 'hours'}; the next one is due{' '}
              {when(view.nextRefresh)}.
            </p>
          ) : null}

          <Recent view={view} />
          <Rhythms view={view} />
        </>
      )}

      <IpsFeedManager feeds={feeds} onChanged={onChanged} />

      <CardSettings form={form} groups={['ips']} omit={['ips.enabled', 'ips.lists']} />
    </Panel>
  )
}
