// SPDX-License-Identifier: MIT

// Where this machine's internet traffic leaves through, as the dashboard's first card.
//
// The picker is the same one the internet page carries, and it is here because it is the
// switch somebody flips most often: a control reached through a page of settings is a
// control nobody flips. The kill switch sits with it for the one arrangement it is read
// in, because what it promises -- traffic held here rather than leaked -- is decided at
// the moment the connection is chosen, not later on its own page.

import type { EgressView } from '../../api'
import { EgressPicker, egressStatus } from '../../components/pickers/EgressPicker'
import { ModuleSwitch } from '../../components/settings/CardSettings'
import type { SettingsForm } from '../../components/settings/useSettingsDraft'
import { HeroCard } from './HeroCard'
import { heroNamed } from './heroes'

const MODE_KEY = 'egress.mode'
const KILL_KEY = 'egress.killSwitch'
/** THROUGH_TUNNEL mirrors config.EgressTunnel: the one mode the kill switch is read in. */
const THROUGH_TUNNEL = 'tunnel'

const HERO = heroNamed('internet')

export function InternetHero({ form, view }: { form: SettingsForm; view: EgressView | undefined }) {
  // The draft rather than the served view, so the switch appears the moment a connection
  // is chosen instead of after the next poll.
  const mode = form.available.find((f) => f.key === MODE_KEY)
  const kill = form.available.find((f) => f.key === KILL_KEY)
  const throughTunnel = mode !== undefined && form.bind(mode).value === THROUGH_TUNNEL

  return (
    <HeroCard
      hero={HERO}
      info={
        <p>
          Traffic to an address none of your connections carries. Send it out of this machine,
          or through one of your connections so it leaves from there instead.
        </p>
      }
      status={egressStatus(view)}
    >
      <EgressPicker view={view} form={form} />
      {throughTunnel && kill !== undefined ? (
        <div className="hero-switch">
          <span className="hero-switch-name">{kill.label}</span>
          <ModuleSwitch form={form} switchKey={KILL_KEY} />
        </div>
      ) : null}
    </HeroCard>
  )
}
