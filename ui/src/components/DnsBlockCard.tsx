// SPDX-License-Identifier: MIT

import { useState } from 'react'
import {
  api,
  ApiError,
  type DNSBlockCheckView,
  type DNSBlockListView,
  type DNSBlockView,
} from '../api'
import { groupByProvider } from '../lib/catalog'
import { BlockLevels } from './BlockLevels'
import { BlocklistGroup } from './BlocklistGroup'
import { DnsBlockListManager } from './DnsBlockListManager'
import { InfoList } from './InfoPopover'
import { ModuleOff } from './ModuleOff'
import { Panel } from './Panel'
import { CardSettings, ModuleSwitch } from './settings/CardSettings'
import type { SettingsForm } from './settings/useSettingsDraft'
import { Notice, Toggle } from './primitives'

/** The lengths a pause is offered in. Long enough to load the site that broke, short
 *  enough that nobody finds blocking still off next week without having chosen that. */
const PAUSE_CHOICES = [5, 15, 60] as const

/** The state blocking is in, as one word and the colour that goes with it. The agent has
 *  already decided this in `capability`; this only names it. */
export function blockState(view: DNSBlockView): { tone: string; label: string } {
  if (!view.enabled) return { tone: 'off', label: 'off' }
  if (view.pausedUntil) return { tone: 'pending', label: 'paused' }
  if (view.capability.degraded) return { tone: 'pending', label: 'blocking nothing' }
  return { tone: 'running', label: 'blocking' }
}

/** A moment the agent reported, in this machine's own zone. Anything unreadable is left
 *  exactly as it arrived rather than shown as "Invalid Date". */
function when(stamp: string | undefined): string {
  if (stamp === undefined) return ''
  const at = new Date(stamp)
  return Number.isNaN(at.getTime()) ? stamp : at.toLocaleString()
}

/** What the lists hold and what they stopped. The pair is the difference between a list
 *  that is loaded and a list that is doing something: names come from the download, and
 *  refusals only ever come from a query that arrived. */
export function BlockCounters({ view }: { view: DNSBlockView }) {
  if (view.rules === 0) {
    // Blocking on with a list chosen means the download is already under way. Told only
    // that nothing is downloaded, a reader goes looking for the button that starts what is
    // already running; a round that failed says why in the notice above rather than here.
    if (view.enabled && (view.lists ?? []).some((list) => list.enabled)) {
      return <p className="hint">Downloading the lists. Nothing is blocked until the first one is in.</p>
    }
    return <p className="hint">No list has been downloaded yet, so nothing is being blocked.</p>
  }
  return (
    <p className="hint">
      {view.rules.toLocaleString()} names in force
      {view.compiledAt ? `, last built ${when(view.compiledAt)}` : ''}. This machine's resolver
      has refused {view.blocked.toLocaleString()}{' '}
      {view.blocked === 1 ? 'lookup' : 'lookups'} so far.
    </p>
  )
}

/**
 * Pausing and downloading: the two things here that are not settings.
 *
 * A pause is held in memory and never stored, so it cannot outlive the agent -- blocking
 * that comes back paused after a restart is the failure this feature must not have -- and
 * the deadline is shown rather than left to be remembered.
 */
function Controls({ view, onChanged }: { view: DNSBlockView; onChanged: () => void }) {
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
        <button className="btn small" disabled={busy} onClick={() => void run(api.refreshDnsBlock)}>
          {busy ? 'Working…' : 'Download now'}
        </button>
        {view.pausedUntil ? (
          <button className="btn small" disabled={busy} onClick={() => void run(api.resumeDnsBlock)}>
            Resume blocking
          </button>
        ) : (
          PAUSE_CHOICES.map((minutes) => (
            <button
              key={minutes}
              className="btn ghost small"
              disabled={busy}
              aria-label={`Pause blocking for ${minutes} minutes`}
              onClick={() => void run(() => api.pauseDnsBlock(minutes))}
            >
              Pause {minutes}m
            </button>
          ))
        )}
      </div>
      {view.pausedUntil ? (
        <Notice tone="warn">
          Paused until {when(view.pausedUntil)}. Every name resolves normally until then, and
          blocking comes back by itself.
        </Notice>
      ) : null}
      {error ? <Notice tone="error">{error}</Notice> : null}
    </>
  )
}

/**
 * The curated ladder, lowest first.
 *
 * Choosing a rung is the whole decision for most people, so each one carries the sentence
 * that says what it adds rather than only its name. A rung switches on exactly the shipped
 * lists it names and leaves the lists the user added alone, which is why a machine can sit
 * on a level and still carry its own list.
 */
export function BlockPresetLevels({ view, onChanged }: { view: DNSBlockView; onChanged: () => void }) {
  return (
    <BlockLevels
      levels={view.presets ?? []}
      chosen={view.preset}
      choose={(id) => api.applyDnsBlockPreset(id).then(onChanged)}
      hint={
        view.preset === undefined
          ? 'The lists switched on are not one of these levels. Choosing one replaces them, and leaves the lists you added alone.'
          : 'A level switches on exactly the lists it names, and leaves the lists you added alone.'
      }
    />
  )
}

/**
 * Why one name is or is not blocked.
 *
 * The agent answers it rather than the browser, because the lists live there and the
 * answer has to be the one the resolver would actually give -- including the reasons that
 * are not about a list at all, such as blocking being paused.
 */
function CheckName() {
  const [name, setName] = useState('')
  const [result, setResult] = useState<DNSBlockCheckView | undefined>(undefined)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)

  const check = async () => {
    setBusy(true)
    setError(undefined)
    try {
      setResult(await api.checkDnsBlock(name))
    } catch (cause) {
      setResult(undefined)
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="field">
      <label htmlFor="dns-block-check">Is a name blocked?</label>
      <div className="row-actions">
        <input
          id="dns-block-check"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && name.trim() !== '') void check()
          }}
        />
        <button
          className="btn small"
          disabled={busy || name.trim() === ''}
          onClick={() => void check()}
        >
          {busy ? 'Checking…' : 'Check'}
        </button>
      </div>
      {result ? (
        <p className="hint">
          {/* A name the agent could make nothing of comes back empty, and the reason says
              so on its own. */}
          {result.name === ''
            ? result.reason
            : `${result.name} is ${result.blocked ? 'blocked' : 'not blocked'}: ${result.reason}`}
        </p>
      ) : null}
      {error ? <Notice tone="error">{error}</Notice> : null}
    </div>
  )
}

/** One list: its switch, what it contributed, and when its copy was last confirmed
 *  current. `skipped` is shown beside the count because a browser filter list carries
 *  mostly rules a resolver cannot express, and one pulling almost no weight is worth
 *  seeing rather than assuming. */
function ListRow({
  list,
  busy,
  onToggle,
}: {
  list: DNSBlockListView
  busy: boolean
  onToggle: (on: boolean) => void
}) {
  return (
    <div className="picker-item static">
      <Toggle
        checked={list.enabled}
        onChange={onToggle}
        label={`Use ${list.name}`}
        disabled={busy}
      />
      <span className="title">{list.name}</span>
      <span className="sub">
        {list.enabled && list.rules > 0
          ? `${list.rules.toLocaleString()} names${list.skipped > 0 ? `, ${list.skipped.toLocaleString()} skipped` : ''}`
          : (list.note ?? list.url)}
      </span>
      <span className="spacer" />
      {list.error ? <span className="sub">{list.error}</span> : null}
      <span className="sub">
        {list.updatedAt ? when(list.updatedAt) : list.enabled ? 'not downloaded yet' : ''}
      </span>
      {list.builtIn ? <span className="sub">built-in</span> : null}
    </div>
  )
}

/**
 * Blocking, the card.
 *
 * `onChanged` re-reads the view the page polls: pausing, resuming and downloading all
 * change what this card is reporting without changing a setting, so nothing else would
 * bring the new state back before the next poll.
 */
export function DnsBlockCard({
  view,
  form,
  onChanged,
}: {
  view: DNSBlockView
  form: SettingsForm
  onChanged: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)
  const [onlyOn, setOnlyOn] = useState(false)
  const state = blockState(view)
  const lists = view.lists ?? []
  const on = lists.filter((list) => list.enabled)
  const shown = onlyOn ? on : lists

  // The switch on a row writes the whole set of enabled ids, because that is what the
  // setting is: a row's own state has nowhere else to live.
  const toggleList = async (id: string, on: boolean) => {
    const wanted = lists.filter((l) => (l.id === id ? on : l.enabled)).map((l) => l.id)
    setBusy(true)
    setError(undefined)
    try {
      const outcome = await form.applyPatch({ 'dnsBlock.lists': wanted })
      if (outcome.stored) onChanged()
      else setError(outcome.reason)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Panel
      title="Blocking"
      wide
      id="dns-block"
      status={{
        tone: state.tone,
        label: state.label,
        ...(view.enabled && view.rules > 0
          ? { detail: `${view.rules.toLocaleString()} names` }
          : {}),
      }}
      info={
        <>
          <p>
            Refuse the names on the lists you pick. Lists are downloaded and kept on this
            machine, so one that cannot be reached keeps blocking from the copy already here,
            and no query ever leaves this device to decide whether a name is blocked.
          </p>
          <InfoList items={view.capability.limits ?? []} />
        </>
      }
      controls={<ModuleSwitch form={form} switchKey="dnsBlock.enabled" />}
    >
      {!view.enabled ? (
        <ModuleOff>
          Off. Every name resolves the way it always did. Switch this on to download the lists
          you choose and refuse the names on them, for what app-tail resolves, for the whole
          machine, or both.
        </ModuleOff>
      ) : (
        <>
          {view.capability.reason ? (
            <Notice tone={view.capability.available ? 'warn' : 'error'}>
              {view.capability.reason}
            </Notice>
          ) : null}

          {/* The agent puts the same sentence in both places when what went wrong is also
              what is holding blocking back, so printing it twice would read as two faults. */}
          {view.error && view.error !== view.capability.reason ? (
            <Notice tone="error">{view.error}</Notice>
          ) : null}

          <BlockCounters view={view} />
          <Controls view={view} onChanged={onChanged} />
          <BlockPresetLevels view={view} onChanged={onChanged} />
          <CheckName />

          {error ? <Notice tone="error">{error}</Notice> : null}

          <div className="row-actions">
            <button
              className="btn ghost small"
              aria-pressed={onlyOn}
              // Never disabled while the filter is on: switching the last list off from
              // inside it would otherwise leave no way back to the catalog.
              disabled={!onlyOn && on.length === 0}
              onClick={() => setOnlyOn((was) => !was)}
            >
              {onlyOn
                ? 'Show every list'
                : `Show only what's on (${on.length} ${on.length === 1 ? 'list' : 'lists'})`}
            </button>
          </div>

          <div className="picker">
            {/* The key carries the mode, so switching it remounts the groups and every one
                that survives the filter opens: the answer to "what is on right now" is the
                whole point of the filtered view, and a group left shut would hide part of
                it. Coming back re-opens whatever holds a list that is on. */}
            {groupByProvider(shown).map((group) => (
              <BlocklistGroup
                key={`${group.provider}${onlyOn ? ':on' : ''}`}
                provider={group.provider}
                count={group.items.length}
                defaultOpen={onlyOn || group.items.some((list) => list.enabled)}
              >
                {group.items.map((list) => (
                  <ListRow
                    key={list.id}
                    list={list}
                    busy={busy || form.saving}
                    onToggle={(on) => void toggleList(list.id, on)}
                  />
                ))}
              </BlocklistGroup>
            ))}
            {onlyOn && on.length === 0 ? (
              <p className="hint">No list is switched on, so nothing is being blocked.</p>
            ) : null}
          </div>

          {view.nextRefresh ? (
            <p className="hint">
              Every list is fetched again after {view.refreshHours}{' '}
              {view.refreshHours === 1 ? 'hour' : 'hours'}; the next one is due{' '}
              {when(view.nextRefresh)}.
            </p>
          ) : null}
        </>
      )}

      <DnsBlockListManager lists={lists} onChanged={onChanged} />

      <CardSettings
        form={form}
        groups={['dnsblock']}
        omit={['dnsBlock.enabled', 'dnsBlock.lists']}
      />
    </Panel>
  )
}
