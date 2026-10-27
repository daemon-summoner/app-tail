// SPDX-License-Identifier: MIT

import { useState } from 'react'
import { api, ApiError, type AutoMapView } from '../api'
import { ModuleOff } from './ModuleOff'
import { Panel } from './Panel'
import { CardSettings, ModuleSwitch } from './settings/CardSettings'
import type { SettingsForm } from './settings/useSettingsDraft'
import { Notice } from './primitives'

/** How the module describes what it opens, in one sentence. The port list is the whole
 *  configuration, so it is stated rather than summarised as a count. */
function mapping(view: AutoMapView): string {
  if (view.ports.length === 0) {
    return 'No ports are configured, so nothing is opened.'
  }
  const ports = view.ports.join(', ')
  return `Port ${ports} on every device is opened on this machine, up to ${view.limit} at once.`
}

export function AutoMapCard({
  view,
  onChanged,
  form,
}: {
  view: AutoMapView
  onChanged: () => void
  form: SettingsForm
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)
  const [result, setResult] = useState<string | undefined>(undefined)

  const forget = async () => {
    setBusy(true)
    setError(undefined)
    setResult(undefined)
    try {
      const { removed } = await api.forgetAutoMappings()
      setResult(
        removed === 0
          ? 'Every remembered port belongs to a device still on the tailnet.'
          : `Forgot ${removed} port ${removed === 1 ? 'assignment' : 'assignments'}.`,
      )
      onChanged()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Panel
      title="Automatic ports"
      wide
      info={
        <>
          <p>
            Every device on your tailnet gets a fixed local port, so a peer&rsquo;s SSH or web port
            is reachable at localhost without configuring anything per device.
          </p>
          <p>
            A port stays with its device across restarts. That is what makes a bookmark worth
            keeping, and it is why forgetting an assignment renumbers that device the next time it
            appears.
          </p>
        </>
      }
      controls={<ModuleSwitch form={form} switchKey="automap.enabled" />}
      actions={
        <button
          className="btn ghost small"
          disabled={busy || view.stored === 0}
          // Deliberate, not part of the reconcile: an assignment is what keeps a port
          // stable across restarts, so dropping one renumbers that device next time it
          // appears and breaks every bookmark that named the old port.
          title="Drop the remembered ports for devices that are no longer on the tailnet"
          onClick={() => void forget()}
        >
          Forget devices that are gone
        </button>
      }
    >
      {!view.enabled ? (
        <ModuleOff>
          Off. Turn this on to give every device on your tailnet a fixed local port.
        </ModuleOff>
      ) : (
        <>
          <p className="hint">{mapping(view)}</p>

          <dl className="proxy-counters">
            <div>
              <dt>Open now</dt>
              <dd>{view.mapped}</dd>
            </div>
            <div>
              <dt title="Includes devices that are not currently reachable, so their port is the same when they come back">
                Remembered
              </dt>
              <dd>{view.stored}</dd>
            </div>
          </dl>

          {view.truncated > 0 ? (
            <Notice tone="warn">
              {view.reason ??
                `${view.truncated} more device-and-port pairs were left out by the limit of ${view.limit}.`}
            </Notice>
          ) : view.reason ? (
            <Notice tone="info">{view.reason}</Notice>
          ) : null}

          {error ? <Notice tone="error">{error}</Notice> : null}
          {result ? <Notice tone="info">{result}</Notice> : null}
        </>
      )}

      <CardSettings
        form={form}
        groups={['automap']}
        omit={['automap.enabled']}
        collapseLabel="Port mapping settings"
      />
    </Panel>
  )
}
