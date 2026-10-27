// SPDX-License-Identifier: MIT

// Traffic inspection, as a dashboard card: the level, and what the engine has matched.
//
// The ladder is the one control here. Its Off rung is the module switch, so the card
// carries no second switch beside the name: two controls for one setting is how the two
// end up disagreeing. Everything else -- the feeds, the entries, the certificate commands
// for Full -- is on the inspection page behind the gear.

import type { IPSView } from '../../api'
import { InspectionLadder } from '../../components/inspection/InspectionLadder'
import { inspectState } from '../../components/IpsCard'
import { Notice } from '../../components/primitives'
import type { SettingsForm } from '../../components/settings/useSettingsDraft'
import { HeroCard } from './HeroCard'
import { heroNamed } from './heroes'

const HERO = heroNamed('inspection')

export function InspectionHero({
  form,
  view,
  onChanged,
}: {
  form: SettingsForm
  view: IPSView | undefined
  onChanged: () => void
}) {
  if (view === undefined) {
    return (
      <HeroCard hero={HERO} status={{ tone: 'pending', label: 'reading' }}>
        <p className="hint">Reading what inspection is doing.</p>
      </HeroCard>
    )
  }

  const state = inspectState(view)
  return (
    <HeroCard
      hero={HERO}
      status={{
        tone: state.tone,
        label: state.label,
        ...(view.enabled && view.rules > 0
          ? { detail: `${view.rules.toLocaleString()} ${view.rules === 1 ? 'entry' : 'entries'}` }
          : {}),
      }}
      info={
        <p>
          Check every connection app-tail carries against the domains, addresses and feeds you
          name, and either record what matches or refuse it. The check happens on this machine
          and nothing is sent anywhere to decide.
        </p>
      }
    >
      {view.enabled && view.capability.reason ? (
        <Notice tone={view.capability.available ? 'warn' : 'error'}>
          {view.capability.reason}
        </Notice>
      ) : null}
      {view.enabled && view.rules > 0 ? (
        <p className="hint" data-inspection="matched">
          {view.matched.toLocaleString()}{' '}
          {view.matched === 1 ? 'connection has' : 'connections have'} matched,{' '}
          {view.refused.toLocaleString()} of them refused.
        </p>
      ) : null}
      <InspectionLadder view={view} form={form} advanced={HERO.route} onChanged={onChanged} />
    </HeroCard>
  )
}
