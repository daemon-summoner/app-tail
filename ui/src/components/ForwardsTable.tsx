// SPDX-License-Identifier: MIT

import { useState } from 'react'
import { api, ApiError, type Forward, type TunnelView } from '../api'
import { Panel } from './Panel'
import { CardSettings } from './settings/CardSettings'
import { PresetManager } from './PresetManager'
import type { SettingsForm } from './settings/useSettingsDraft'
import {
  DirectionBadge,
  Notice,
  ProtocolBadge,
  Route,
  StatusDot,
  Toggle,
  formatBytes,
} from './primitives'

// derived reports a forward a module created rather than a user. What the module derived
// -- the name, the port, what it reaches -- is rebuilt from the tailnet on every
// reconcile, so the controls that would edit any of it are left off the row rather than
// offered and then refused. The switch stays: not opening one port is a choice the module
// keeps, and its absence would make the module's own switch the only lever.
function derived(forward: Forward): boolean {
  return forward.source === 'auto'
}

// activeCount is the number of live connections to show: a both-protocol forward
// carries TCP connections and UDP sessions at once, so its count is the sum.
function activeCount(forward: Forward): number {
  if (forward.protocol === 'udp') return forward.activeUdp
  if (forward.protocol === 'both') return forward.activeTcp + forward.activeUdp
  return forward.activeTcp
}

export function ForwardsTable({
  forwards,
  tunnels,
  onChanged,
  onEdit,
  onAdd,
  nodeRunning,
  form,
}: {
  forwards: Forward[]
  /** Every connection a forward could cross, used to name the one each row does. */
  tunnels: TunnelView[]
  onChanged: () => void
  onEdit: (forward: Forward) => void
  onAdd: () => void
  nodeRunning: boolean
  form: SettingsForm
}) {
  // With one connection every row would carry the same word, which is a column of noise.
  // The question only exists once there is more than one network to be on.
  const showConnection = tunnels.length > 1
  const connectionName = (forward: Forward) =>
    tunnels.find((t) => t.id === forward.tunnelId)?.name ?? forward.tunnelId
  const [error, setError] = useState<string | undefined>(undefined)
  const [busyId, setBusyId] = useState<string | undefined>(undefined)

  const act = async (id: string, fn: () => Promise<unknown>) => {
    setBusyId(id)
    setError(undefined)
    try {
      await fn()
      onChanged()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setBusyId(undefined)
    }
  }

  const remove = (forward: Forward) => {
    const label = forward.name || forward.endpoint
    // A forward is cheap to recreate but its loss is silent, so confirm first.
    if (!window.confirm(`Delete the forward "${label}"? Any open connections are closed.`)) {
      return
    }
    void act(forward.id, () => api.deleteForward(forward.id))
  }

  return (
    <Panel
      title="Forwards"
      // The strip above already carries "Port forwards", and two regions answering to
      // one name is as confusing to query as it is to hear read aloud.
      regionLabel="Port forwards"
      id="forwards"
      wide
      bare
      info={
        <p>
          A forward maps a port on this machine to a service on your tailnet, so you can reach it
          without putting the whole machine on the VPN. Nothing on this machine changes: each
          forward is one address you point a program at.
        </p>
      }
      actions={
        <button className="btn primary small" onClick={onAdd}>
          Add forward
        </button>
      }
    >
      {error ? (
        <div className="table-notice">
          <Notice tone="error">{error}</Notice>
        </div>
      ) : null}

      {forwards.length === 0 ? (
        <div className="empty">
          <strong>No forwards yet</strong>
          <p>
            A forward maps a port on this machine to a service on your tailnet, so you can reach it
            without putting the whole machine on the VPN. Add one to get started.
          </p>
          <button className="btn primary" onClick={onAdd}>
            Add your first forward
          </button>
        </div>
      ) : (
        <table className="forwards">
          <thead>
            <tr>
              <th scope="col">
                <span className="sr-only">Enabled</span>
              </th>
              <th scope="col">Name</th>
              {showConnection ? <th scope="col">Connection</th> : null}
              <th scope="col">Route</th>
              <th scope="col">Status</th>
              <th scope="col" className="numeric optional">
                Conns
              </th>
              <th scope="col" className="numeric optional">
                Up
              </th>
              <th scope="col" className="numeric optional">
                Down
              </th>
              <th scope="col" />
            </tr>
          </thead>
          <tbody>
            {forwards.map((forward) => (
              <tr key={forward.id} className={forward.enabled ? '' : 'disabled'}>
                <td>
                  <Toggle
                    checked={forward.enabled}
                    disabled={busyId === forward.id}
                    label={`${forward.enabled ? 'Disable' : 'Enable'} ${forward.name || forward.endpoint}`}
                    onChange={(next) =>
                      void act(forward.id, () => api.toggleForward(forward.id, next))
                    }
                  />
                </td>
                <td>
                  <span className="forward-name">{forward.name || 'Unnamed'}</span>
                  <div className="forward-badges">
                    <ProtocolBadge protocol={forward.protocol} />
                    <DirectionBadge direction={forward.direction} />
                    {derived(forward) ? (
                      <span
                        className="badge"
                        title="Opened by the automatic ports module. The switch closes this one port; turn the module off to take the port over."
                      >
                        automatic
                      </span>
                    ) : null}
                  </div>
                </td>
                {showConnection ? <td>{connectionName(forward)}</td> : null}
                <td>
                  <Route forward={forward} />
                  {forward.error ? <span className="forward-error">{forward.error}</span> : null}
                  {/* A forward listening beyond this machine, or one the node is refusing
                      connections for, is running exactly as configured -- the only place
                      either fact can be seen is here, on the row it is about. */}
                  {forward.warning ? (
                    <span className="forward-warning">{forward.warning}</span>
                  ) : null}
                </td>
                <td>
                  <StatusDot forward={forward} />
                  {forward.enabled && forward.state !== 'running' && !nodeRunning ? (
                    <div className="forward-waiting">
                      waiting for the tailnet
                    </div>
                  ) : null}
                </td>
                <td className="numeric optional">{activeCount(forward)}</td>
                <td className="numeric optional">{formatBytes(forward.bytesUp)}</td>
                <td className="numeric optional">{formatBytes(forward.bytesDown)}</td>
                <td className="actions">
                  {derived(forward) ? null : (
                    <>
                      <button className="btn ghost small" onClick={() => onEdit(forward)}>
                        Edit
                      </button>
                      <button
                        className="btn ghost small"
                        disabled={busyId === forward.id}
                        onClick={() => remove(forward)}
                      >
                        Delete
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="panel-body">
        <CardSettings form={form} groups={['forwarding']} collapseLabel="Forwarding defaults" />
        <PresetManager />
      </div>
    </Panel>
  )
}
