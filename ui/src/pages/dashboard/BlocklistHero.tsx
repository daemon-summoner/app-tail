// SPDX-License-Identifier: MIT

// Name blocking, as a dashboard card: the switch, the level, and what the lists have
// stopped so far.
//
// The level is the whole decision for most people, so it is the control this card
// carries; the lists themselves, the pause, and the name check are on the blocking page
// behind the gear. The card says what blocking is doing to this machine's queries, and
// says "paused" as something other than a count so nobody reads a paused blocker as a
// working one.

import type { DNSBlockView } from '../../api'
import { BlockCounters, BlockPresetLevels, blockState } from '../../components/DnsBlockCard'
import { ModuleOff } from '../../components/ModuleOff'
import { Notice } from '../../components/primitives'
import { ModuleSwitch } from '../../components/settings/CardSettings'
import type { SettingsForm } from '../../components/settings/useSettingsDraft'
import { HeroCard } from './HeroCard'
import { heroNamed } from './heroes'

const HERO = heroNamed('blocklist')

/** A moment the agent reported, in this machine's own zone. Anything unreadable is left
 *  exactly as it arrived rather than shown as "Invalid Date". */
function when(stamp: string): string {
  const at = new Date(stamp)
  return Number.isNaN(at.getTime()) ? stamp : at.toLocaleString()
}

export function BlocklistHero({
  form,
  view,
  onChanged,
}: {
  form: SettingsForm
  view: DNSBlockView | undefined
  onChanged: () => void
}) {
  if (view === undefined) {
    return (
      <HeroCard hero={HERO} status={{ tone: 'pending', label: 'reading' }}>
        <p className="hint">Reading what blocking is doing.</p>
      </HeroCard>
    )
  }

  const state = blockState(view)
  return (
    <HeroCard
      hero={HERO}
      status={{
        tone: state.tone,
        label: state.label,
        ...(view.enabled && view.rules > 0 ? { detail: `${view.rules.toLocaleString()} names` } : {}),
      }}
      info={
        <p>
          Refuse the names on the lists you pick. Lists are downloaded and kept on this machine,
          and no query ever leaves this device to decide whether a name is blocked.
        </p>
      }
      controls={<ModuleSwitch form={form} switchKey="dnsBlock.enabled" />}
    >
      {!view.enabled ? (
        <ModuleOff>
          Off. Every name resolves the way it always did. Switch this on to refuse the names on
          the lists you choose.
        </ModuleOff>
      ) : (
        <>
          {view.capability.reason ? (
            <Notice tone={view.capability.available ? 'warn' : 'error'}>
              {view.capability.reason}
            </Notice>
          ) : null}
          {/* Paused is said instead of the counts: a count under a pause reads as a blocker
              at work, and nothing is being refused until the pause ends. */}
          {view.pausedUntil ? (
            <p className="hint" data-block="paused">
              Paused until {when(view.pausedUntil)}. Every name resolves normally until then.
            </p>
          ) : (
            <BlockCounters view={view} />
          )}
          {/* Blocking that never reaches the machine-wide resolver refuses names only for
              what app-tail resolves itself, which is invisible from every other card. */}
          {!view.system ? (
            <p className="hint" data-block="own-only">
              Only what app-tail resolves for itself is checked. Switch it on for the whole
              machine from the blocking page.
            </p>
          ) : null}
          <BlockPresetLevels view={view} onChanged={onChanged} />
        </>
      )}
    </HeroCard>
  )
}
