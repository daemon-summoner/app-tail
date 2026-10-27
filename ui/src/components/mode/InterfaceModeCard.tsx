// SPDX-License-Identifier: MIT

import { useState } from 'react'
import { api, ApiError, type InterfaceView } from '../../api'
import { InfoList } from '../InfoPopover'
import { ModuleOff } from '../ModuleOff'
import { Panel } from '../Panel'
import { RestartButton } from '../RestartButton'
import { CardSettings, ModuleSwitch } from '../settings/CardSettings'
import type { SettingsForm } from '../settings/useSettingsDraft'
import { CodeBlock, Notice } from '../primitives'

/** The mode the node is really on, as one word and the colour that goes with it.
 *  `inForce` is the agent's own answer, so this only names it. */
function interfaceState(tun: InterfaceView): { tone: string; label: string } {
  if (tun.inForce) return { tone: 'running', label: 'in force' }
  // The configured mode is what the switch turns on, so while the module is off it is a
  // memory and not something waiting.
  if (!tun.enabled) return { tone: 'off', label: 'inside app-tail only' }
  if (tun.fallback) return { tone: 'error', label: 'fell back' }
  if (tun.configured === 'tun') return { tone: 'pending', label: 'waiting for a restart' }
  return { tone: 'off', label: 'inside app-tail only' }
}

/** helperLine is the state of the privileged side in one sentence. The mode needs a
 *  process running as root to create the interface, and every failure to reach it is a
 *  different fix, so the row says which one this machine is in. */
function helperLine(tun: InterfaceView): string {
  const helper = tun.helper
  if (!helper.design) return 'This platform needs no separate helper.'
  if (helper.running) {
    return helper.version ? `Running, version ${helper.version}.` : 'Running.'
  }
  if (helper.problem) return helper.problem
  if (helper.installed) return 'Installed, but it has not answered.'
  return 'Not installed.'
}

/** Whether the helper this machine is missing is one app-tail can install for itself.
 *  A platform that has no helper by design has nothing to offer, and one that cannot
 *  install it has only a command to be run as root -- offering a button for either is
 *  offering something that does nothing. */
function canBeSetUpFromHere(tun: InterfaceView): boolean {
  return tun.helper.design && tun.helper.installable && !tun.helper.running
}

/** The fix, beside the reason. The mode needs a process running as root, obtaining one
 *  needs a password, and this raises that prompt -- which is the entire point: somebody
 *  reading a card that says the mode is not working should not have to leave it and find
 *  a terminal to get the mode working.
 *
 *  app-tail replaces a helper left behind by an earlier build of itself as it starts,
 *  unasked, because that one is unambiguous and an upgrade is what caused it. The states
 *  reachable here are the others -- a machine that never had a helper, or one whose
 *  helper answers to another account -- and those are offered rather than imposed,
 *  because a prompt raised at every login is one people learn to dismiss. */
function InterfaceSetUp({ offered }: { offered: boolean }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)
  const [done, setDone] = useState(false)

  const setUp = async () => {
    setBusy(true)
    setError(undefined)
    try {
      await api.tunSetup()
      setDone(true)
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  // Checked before `offered`, and deliberately: the setup that just succeeded is what
  // stops the machine needing one, so the next poll withdraws the offer. Reading the offer
  // first would take this notice off the screen seconds after it appeared, which reads as
  // the fix having been undone.
  //
  // The helper is installed but the running node was built without one, so the mode
  // arrives with the node that replaces it. Saying so beside the button that does it is
  // what stops this reading as a fix that did not work.
  if (done) {
    return (
      <Notice tone="info">
        <p>
          This machine is set up. The tailnet moves onto the network interface when app-tail
          restarts.
        </p>
        <RestartButton />
      </Notice>
    )
  }

  if (!offered) return null

  return (
    <div className="tun-setup">
      <button className="btn small" disabled={busy} onClick={() => void setUp()}>
        {busy ? 'Waiting for your password…' : 'Set this machine up'}
      </button>
      <p className="hint">
        You are asked for your password, and app-tail installs the privileged helper this
        mode needs. Nothing else on the machine changes.
      </p>
      {error ? <Notice tone="error">{error}</Notice> : null}
    </div>
  )
}

export function InterfaceModeCard({ tun, form }: { tun: InterfaceView; form: SettingsForm }) {
  const state = interfaceState(tun)

  return (
    <Panel
      title="Network interface"
      wide
      id="interface"
      status={{
        tone: state.tone,
        label: state.label,
        ...(tun.interface ? { detail: tun.interface } : {}),
      }}
      // What the mode does to the machine holds whether or not it is working. Stacked
      // inline it was three paragraphs of unchanging text above the one line that says
      // whether the interface is actually up.
      info={
        <>
          <p>
            Put the tailnet on a network interface, so every program on this machine reaches tailnet
            addresses and names directly. This and the System resolver are the two parts of app-tail
            that change the machine rather than only itself.
          </p>
          <InfoList items={tun.capability.limits ?? []} />
        </>
      }
      controls={<ModuleSwitch form={form} switchKey="interface.enabled" />}
    >
      {!tun.enabled ? (
        <ModuleOff>
          Off. Turn this on to put the tailnet on a network interface every program can reach.
        </ModuleOff>
      ) : (
        <>
          <div className="tun-body">
            {tun.fallback ? (
              <Notice tone="error">
                This machine is not on a network interface, so only app-tail&rsquo;s forwards and
                proxy reach the tailnet: {tun.fallback}
              </Notice>
            ) : null}

            {tun.conflict ? <Notice tone="error">{tun.conflict}</Notice> : null}
            {tun.missing ? <Notice tone="warn">{tun.missing}</Notice> : null}

            {/* The helper's own complaint is already the Privileged helper row below, and
                the agent sends the same sentence for both. Printing it twice reads as two
                faults rather than one. */}
            {tun.capability.reason && tun.capability.reason !== helperLine(tun) ? (
              <Notice tone={tun.capability.available ? 'warn' : 'error'}>
                {tun.capability.reason}
              </Notice>
            ) : null}

            <InterfaceSetUp offered={canBeSetUpFromHere(tun)} />

            <dl className="tun-facts">
              <div>
                <dt>Privileged helper</dt>
                <dd>{helperLine(tun)}</dd>
              </div>
              {tun.helper.socket ? (
                <div>
                  <dt>Helper socket</dt>
                  <dd className="mono">{tun.helper.socket}</dd>
                </div>
              ) : null}
            </dl>

            {/* The case this is for is the one where app-tail is not the thing that will do
            the cleaning, so each leftover is named and the command that removes it is
            beside it to run by hand. */}
            {(tun.leftovers ?? []).length > 0 ? (
              <div className="tun-leftovers">
                <h3>Left behind by an earlier run</h3>
                <ul>
                  {(tun.leftovers ?? []).map((leftover) => (
                    <li key={leftover}>{leftover}</li>
                  ))}
                </ul>
                {(tun.undo ?? []).map((command) => (
                  <CodeBlock key={command} text={command} />
                ))}
              </div>
            ) : null}
          </div>
        </>
      )}

      <CardSettings
        form={form}
        groups={['interface']}
        omit={['interface.enabled']}
        collapseLabel="Interface settings"
      />
    </Panel>
  )
}
