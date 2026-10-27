// SPDX-License-Identifier: MIT

// What this device accepts from each private network it is on, and what it reports back
// about itself.
//
// Both settings are held by the network's own node, so they belong to a connection rather
// than to this machine -- and they are set on the connection's own page. This card is the
// one place they can be read together, which is the question people come to Security with:
// not "what is this one connection set to" but "is anything on this machine reachable".

import type { TunnelView } from '../api'
import { ModuleOff } from './ModuleOff'
import { Panel } from './Panel'
import { ModuleSwitch, switchIsOn } from './settings/CardSettings'
import type { SettingsForm } from './settings/useSettingsDraft'

const SWITCH = 'security.enabled'
const SHIELDS = 'security.shieldsUp'
const POSTURE = 'security.postureChecking'

/** connectionHref is where a connection's own settings are, which is where either of
 *  these is changed. Built from the type and the id the same way the connections list
 *  builds it. */
function pageOf(tunnel: TunnelView): string {
  return `#/connections/${tunnel.type}/${tunnel.id}`
}

/** isOn reads one of these settings off a connection's stored values. Anything other than
 *  a stored true is off: these are the settings whose safe answer is the one that refuses,
 *  so a value this page cannot read is never reported as protection. */
function isOn(tunnel: TunnelView, key: string): boolean {
  return tunnel.settings[key] === true
}

export function SecurityCard({
  form,
  tunnels,
}: {
  form: SettingsForm
  /** Every connection, so the ones holding these settings can be counted. */
  tunnels: readonly TunnelView[]
}) {
  const on = switchIsOn(form, SWITCH)
  // Only the connections that carry these settings at all: a kind of network with no node
  // preferences has neither, and counting it would make the total say that some connection
  // is accepting traffic it was never asked about.
  const held = tunnels.filter((t) => SHIELDS in t.settings)
  const refusing = held.filter((t) => isOn(t, SHIELDS)).length

  return (
    <Panel
      title="Security"
      wide
      status={on ? { tone: 'running', label: 'on' } : { tone: 'off', label: 'off' }}
      info={
        <>
          <p>
            Refuse incoming connections from a private network, and choose whether this device
            reports posture information about itself back to it.
          </p>
          <p>
            Both are held by the network&rsquo;s own node, so they apply wherever this device
            appears on it rather than only to app-tail. Each one is set on its connection&rsquo;s
            page; this is where they can be read together.
          </p>
        </>
      }
      controls={<ModuleSwitch form={form} switchKey={SWITCH} />}
    >
      {!on ? (
        <ModuleOff>
          Off. This device accepts incoming tailnet connections and reports nothing about itself,
          which is what a device that has never been given a security setting does.
        </ModuleOff>
      ) : held.length === 0 ? (
        <p className="hint">
          No connection here holds these settings. They belong to a network whose node keeps
          preferences of its own, which today means a Tailscale connection.
        </p>
      ) : (
        <>
          <p className="hint">
            Incoming connections are refused on {refusing} of {held.length}{' '}
            {held.length === 1 ? 'connection' : 'connections'}.
          </p>

          <dl className="proxy-counters">
            {held.map((tunnel) => (
              <div key={tunnel.id}>
                <dt>
                  <a href={pageOf(tunnel)}>{tunnel.name}</a>
                </dt>
                <dd>
                  {isOn(tunnel, SHIELDS)
                    ? 'Refuses incoming connections'
                    : 'Accepts incoming connections'}
                  {isOn(tunnel, POSTURE) ? '; reports its posture' : ''}
                </dd>
              </div>
            ))}
          </dl>
        </>
      )}
    </Panel>
  )
}
