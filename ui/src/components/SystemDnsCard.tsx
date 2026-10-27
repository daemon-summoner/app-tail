// SPDX-License-Identifier: MIT

import { useState } from 'react'
import { api, ApiError, type DNSSystemView } from '../api'
import { DnsProfileManager } from './DnsProfileManager'
import { Names } from './dnsLists'
import { InfoList } from './InfoPopover'
import { ModuleOff } from './ModuleOff'
import { Panel } from './Panel'
import { DnsProfilePicker, SYSTEM_PROFILE, useDnsProfiles } from './pickers/DnsProfilePicker'
import { CardSettings, ModuleSwitch } from './settings/CardSettings'
import type { SettingsForm } from './settings/useSettingsDraft'
import { Notice } from './primitives'

/** The state the machine is in, as one word and the colour that goes with it. The agent
 *  has already decided this in `capability`; this only names it. */
function systemDnsState(view: DNSSystemView): { tone: string; label: string } {
  if (!view.enabled) return { tone: 'off', label: 'off' }
  if (!view.capability.available) return { tone: 'error', label: 'not in force' }
  // Interception is the one degraded state where the override really did go in: the
  // machine resolves through app-tail and app-tail's queries are answered by this network
  // before they reach the chosen resolver. "Not in force" would send the reader looking for
  // a setup step that has already happened.
  if (view.intercepted && view.applied) return { tone: 'pending', label: 'this network is answering' }
  if (view.capability.degraded) return { tone: 'pending', label: 'not in force' }
  if (view.profile === SYSTEM_PROFILE) return { tone: 'off', label: 'unchanged' }
  return { tone: 'running', label: 'resolving through app-tail' }
}

/** The fix, beside the reason. Pointing this machine at another resolver needs
 *  administrator rights once, obtaining them needs a password, and this raises that prompt
 *  -- so somebody reading a card that says the resolver is not in force does not have to
 *  leave it and find a terminal.
 *
 *  Offered rather than imposed, and offered here rather than on the picker: a password
 *  prompt raised by clicking a radio button is one nobody expects. */
function SystemDnsSetUp({ offered, onDone }: { offered: boolean; onDone: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)

  const setUp = async () => {
    setBusy(true)
    setError(undefined)
    try {
      await api.dnsSetup()
      onDone()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  if (!offered) return null

  return (
    <div className="tun-setup">
      <button className="btn small" disabled={busy} onClick={() => void setUp()}>
        {busy ? 'Waiting for your password…' : 'Set this machine up'}
      </button>
      <p className="hint">
        You are asked for your password once, and app-tail arranges the rights it needs to
        change which resolver this machine uses.
      </p>
      {error ? <Notice tone="error">{error}</Notice> : null}
    </div>
  )
}

/** Whether the last failed override says anything the reason above it does not. A machine
 *  that is not ready cannot install the override, so the failure it reports is the blocker
 *  restated as its consequence; a machine that is ready and still failed is a fault of its
 *  own and has to be shown. */
function failureIsItsOwnFault(view: DNSSystemView): boolean {
  return view.ready || !view.capability.reason
}

/** Where this machine's queries went. It is the one thing on the card that proves the
 *  override is doing something rather than merely being installed. */
function Counters({ view }: { view: DNSSystemView }) {
  const q = view.queries
  if (q.total === 0) {
    return <p className="hint">No name has been looked up through app-tail yet.</p>
  }
  return (
    <p className="hint">
      {q.total} {q.total === 1 ? 'lookup' : 'lookups'} so far: {q.toProfile} to your resolver,{' '}
      {q.toLocal} to this network, {q.answered} answered here, {q.failed} that nobody could
      answer.
    </p>
  )
}

export function SystemDnsCard({ view, form }: { view: DNSSystemView; form: SettingsForm }) {
  const { profiles, error, reload } = useDnsProfiles()

  const state = systemDnsState(view)
  const setUpOffered = view.enabled && view.needsSetup

  return (
    <Panel
      title="System resolver"
      wide
      id="system-dns"
      status={{
        tone: state.tone,
        label: state.label,
        ...(view.enabled && view.profileLabel ? { detail: view.profileLabel } : {}),
      }}
      // What this changes about the machine holds whether or not it is switched on, and it
      // reads the same on every machine, so it sits behind the head's info button rather
      // than above the one line that says what is resolving right now.
      info={
        <>
          <p>
            Point every program on this machine at the resolver you choose. This is one of the
            two things app-tail changes outside itself, and it puts your previous settings back
            when you switch it off.
          </p>
          <InfoList items={view.capability.limits ?? []} />
        </>
      }
      controls={<ModuleSwitch form={form} switchKey="systemDns.enabled" />}
    >
      {/* The picker is on the card whether or not the module is on, which is the one place
          this card departs from every other one here. Choosing a resolver is what turns
          this on -- the write carries the switch with the profile, exactly as the menu and
          the CLI do -- so hiding the choices behind the switch would hide the feature
          itself behind a toggle that names nothing it does. */}
      {!view.enabled ? (
        <ModuleOff>
          Off. Every program on this machine resolves names the way it always did. Pick a
          resolver below to send them through it instead, and switch whenever one breaks a
          site.
        </ModuleOff>
      ) : (
        <>
          {view.capability.reason ? (
            <Notice tone={view.capability.available ? 'warn' : 'error'}>
              {view.capability.reason}
            </Notice>
          ) : null}

          {/* The agent puts a failed override in both places, so printing it twice would
              read as two separate faults. A machine that cannot carry the override at all
              is the same story told twice in different words -- the reason above is why the
              override could not be installed, and the failed install below is that reason
              happening -- so only the cause is printed. */}
          {view.error && view.error !== view.capability.reason && failureIsItsOwnFault(view) ? (
            <Notice tone="error">{view.error}</Notice>
          ) : null}

          <SystemDnsSetUp offered={setUpOffered} onDone={reload} />
        </>
      )}

      <DnsProfilePicker view={view} form={form} profiles={profiles} error={error} />

      {view.enabled && view.profile !== SYSTEM_PROFILE ? (
        <>
          <div className="dns-lists">
            <Names
              title="Resolving through"
              hint="The servers your chosen profile sends names to, in the order they are tried."
              items={view.servers ?? []}
              empty="This profile names no server."
            />
            <Names
              title="This network"
              hint="What this machine resolves with underneath app-tail. Names belonging to this network still go here."
              items={view.base?.nameservers ?? []}
              empty="This network publishes no resolver of its own."
            />
            <Names
              title="Names sent to this network"
              hint="Suffixes looked up through the network you are on rather than through your chosen resolver."
              items={view.localSuffixes ?? []}
              empty="Only single names, .local and private reverse lookups go to this network."
            />
          </div>

          {view.listen ? (
            <p className="hint">
              app-tail answers DNS on <span className="mono">{view.listen}</span>, and this
              machine is pointed there while the override is in force.
            </p>
          ) : null}

          {/* Which resolver turned a hostname into an address chose which server this
              machine is really talking to, so it is stated whichever way it went. A
              fallback to this network's resolvers is that choice having been made by the
              network, which is a warning; the encrypted path is a note. */}
          {view.bootstrap ? (
            view.bootstrapDegraded ? (
              <Notice tone="warn">{view.bootstrap}</Notice>
            ) : (
              <p className="hint">{view.bootstrap}</p>
            )
          ) : null}

          {/* The one setting here that weakens a filtering resolver, reported rather
              than left to be discovered when a blocked domain starts resolving. */}
          {view.retryOnNxdomain ? (
            <Notice tone="warn">
              A name your resolver says does not exist is asked of this network as well, so a
              resolver that blocks a domain no longer blocks it.
            </Notice>
          ) : null}

          <Counters view={view} />
        </>
      ) : null}

      <DnsProfileManager profiles={profiles ?? []} onChanged={reload} />

      <CardSettings
        form={form}
        groups={['systemdns']}
        omit={['systemDns.enabled', 'systemDns.profile']}
        collapseLabel="System resolver settings"
      />
    </Panel>
  )
}
