// SPDX-License-Identifier: MIT

// The three ways this machine reaches the tailnet, always all three, each with its switch.
//
// The forwards always run and carry no switch; the proxy and the interface are module
// switches, written the moment they are flipped. What each is doing right now is beside
// its name, decided by accessPaths from the views the agent serves, so a path nobody has
// turned on is still named here: a mode nobody can see is a mode only somebody who already
// knows about it can turn on.

import { useState } from 'react'

import { settingsSchema, type AutoMapView, type FabricView, type Forward, type InterfaceView, type ProxyView } from '../../api'
import { accessPaths, type AccessPath } from '../../components/modes/accessPaths'
import { Toggle } from '../../components/primitives'
import { switchIsOn } from '../../components/settings/CardSettings'
import type { SettingsForm } from '../../components/settings/useSettingsDraft'
import { HeroCard } from './HeroCard'
import { heroNamed } from './heroes'

const HERO = heroNamed('paths')
const PROXY_KEY = 'proxy.enabled'
const INTERFACE_KEY = 'interface.enabled'

interface PathsHeroProps {
  form: SettingsForm
  forwards: readonly Forward[]
  automap: AutoMapView | undefined
  proxy: ProxyView | undefined
  tun: InterfaceView | undefined
  /** What the one interface for every connection is carrying, for the machines arranged
   *  that way: the tailnet's own view above has nothing to say about them. */
  fabric: FabricView | undefined
  /** Called after a switch is written, so the views are re-read rather than waited for. */
  onChanged: () => void
}

export function PathsHero({ form, forwards, automap, proxy, tun, fabric, onChanged }: PathsHeroProps) {
  const [switching, setSwitching] = useState<string | undefined>(undefined)

  // The switches read the stored setting, which is what a switch shows, and the status
  // beside each reads the served views, which are what is in force. The generated schema
  // carries the restart class, because the draft drops a module's fields while it is off
  // and the interface's restart is what the switch has to say before it is turned on.
  const paths = accessPaths(
    { proxyEnabled: switchIsOn(form, PROXY_KEY), interfaceEnabled: switchIsOn(form, INTERFACE_KEY) },
    { forwards, automap, proxy, tun, fabric },
    settingsSchema,
  )

  // A refusal is already the form's notice; re-reading the views after one would only
  // confirm nothing changed.
  const flip = async (path: AccessPath, on: boolean) => {
    if (path.control.kind !== 'switch') return
    setSwitching(path.id)
    try {
      const outcome = await form.applyPatch(on ? path.control.patchOn : path.control.patchOff)
      if (outcome.stored) onChanged()
    } finally {
      setSwitching(undefined)
    }
  }

  return (
    <HeroCard hero={HERO} wide>
      <div className="reach-modes">
        {paths.map((path) => (
          <div className="reach-mode" key={path.id} data-path={path.id}>
            <a className="reach-mode-name" href={path.route}>
              {path.label}
            </a>
            <span className={`status ${path.status.tone}`}>
              <span className="dot" aria-hidden="true" />
              {path.status.label}
            </span>
            {/* A switch reads the stored setting, and before the settings have loaded there
                is none to read: a switch drawn off beside a status saying "listening" would
                be showing a position nobody set. A switch still reading its view has no
                patch to write yet, and waits the same way. */}
            {path.control.kind === 'always' ? (
              <span className="reach-mode-always">always on</span>
            ) : path.control.kind === 'switch' && form.loaded ? (
              <Toggle
                checked={path.control.on}
                onChange={(on) => void flip(path, on)}
                label={path.label}
                disabled={switching !== undefined || form.saving}
              />
            ) : (
              <span className="skeleton switch" aria-hidden="true" />
            )}
            {path.control.kind === 'switch' && path.control.restart === 'node' ? (
              <span className="hint reach-mode-hint">Switching this reconnects the node.</span>
            ) : null}
          </div>
        ))}
      </div>
    </HeroCard>
  )
}
