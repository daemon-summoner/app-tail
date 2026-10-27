// SPDX-License-Identifier: MIT

import { useState } from 'react'
import {
  api,
  ApiError,
  type ExitNodeCandidate,
  type ExitNodeSuggestion,
  type ExitNodeView,
} from '../api'
import { ModuleOff } from './ModuleOff'
import { Panel } from './Panel'
import { CardSettings, ModuleSwitch } from './settings/CardSettings'
import type { EntityForm } from './settings/useEntityDraft'
import { Notice } from './primitives'

/** The state the module is in, as one word plus the colour that goes with it. The agent
 *  has already decided this in `capability`; this only names it. */
function exitNodeState(view: ExitNodeView): { tone: string; label: string } {
  // Off is a state, not a fault: a module nobody switched on and a module that could not
  // start both arrive as unavailable, and only the switch tells them apart.
  if (!view.enabled) return { tone: 'off', label: 'off' }
  if (!view.capability.available) return { tone: 'error', label: 'off' }
  if (view.capability.degraded) return { tone: 'pending', label: 'not carrying traffic' }
  return { tone: 'running', label: 'carrying traffic' }
}

/** When the schedule moves on, as a clock time in the reader's own zone. A bare RFC 3339
 *  string is not something a person reads off a card. */
function nextChangeAt(when: string): string | undefined {
  const at = new Date(when)
  if (Number.isNaN(at.getTime())) return undefined
  return at.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
}

/** The recommendation as a sentence. An empty answer carries its own reason, which is the
 *  ordinary case on a tailnet whose exit nodes are all self-hosted. */
function suggestionText(suggestion: ExitNodeSuggestion): string {
  if (!suggestion.id) {
    return suggestion.reason ?? 'Your tailnet has no exit node to suggest.'
  }
  const place = [suggestion.city, suggestion.country].filter(Boolean).join(', ')
  const named = suggestion.label ?? suggestion.id
  return place
    ? `Your tailnet suggests ${named} (${place}). Choose it in the settings below to use it.`
    : `Your tailnet suggests ${named}. Choose it in the settings below to use it.`
}

/** One device the tailnet offers, as a row. Reachable and in-use are separate facts: a
 *  device can be the current exit node and offline at the same time, which is exactly the
 *  state someone opens this card to understand. */
function Candidate({ candidate }: { candidate: ExitNodeCandidate }) {
  return (
    <li className={candidate.current ? 'current' : undefined}>
      <span className="exit-node-name">{candidate.display}</span>
      <span className={`status ${candidate.online ? 'running' : 'stopped'}`}>
        <span className="dot" aria-hidden="true" />
        {candidate.online ? 'online' : 'offline'}
      </span>
      {candidate.current ? <span className="exit-node-inuse">in use</span> : null}
    </li>
  )
}

/** `form` holds this connection's settings and `app` the switch that turns the module on
 *  for the installation, for the reason RoutesCard takes both: the switch governs every
 *  connection, so it is not one connection's setting. */
export function ExitNodeCard({
  view,
  form,
  app,
}: {
  view: ExitNodeView
  form: EntityForm
  app: EntityForm
}) {
  const [asking, setAsking] = useState(false)
  const [suggestion, setSuggestion] = useState<ExitNodeSuggestion | undefined>(undefined)
  const [error, setError] = useState<string | undefined>(undefined)

  const suggest = async () => {
    setAsking(true)
    setError(undefined)
    setSuggestion(undefined)
    try {
      setSuggestion(await api.suggestExitNode())
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setAsking(false)
    }
  }

  const state = exitNodeState(view)
  const candidates = view.candidates ?? []
  const nextChange = view.nextChange ? nextChangeAt(view.nextChange) : undefined

  return (
    <Panel
      title="Exit node"
      wide
      status={{
        tone: state.tone,
        label: state.label,
        ...(view.currentLabel ? { detail: view.currentLabel } : {}),
      }}
      info={
        <p>
          Send this device&rsquo;s other traffic out through a device on your tailnet, so it leaves
          from there instead of from here. app-tail routes in userspace, so this applies to what
          goes through its proxy and its forwards rather than to every program on this machine.
        </p>
      }
      controls={<ModuleSwitch form={app} switchKey="exitNode.enabled" />}
      actions={
        <button className="btn ghost small" disabled={asking} onClick={() => void suggest()}>
          {asking ? 'Asking…' : 'Ask my tailnet'}
        </button>
      }
    >
      {!view.enabled ? (
        <ModuleOff>
          Off. Turn this on to send this device's other traffic out through a device on your
          tailnet.
        </ModuleOff>
      ) : (
        <>
          {view.reason ? <p className="hint">{view.reason}</p> : null}

          {/* Separate from the reason above: the reason says what is happening now, and
          this says what happens the moment anyone changes it. */}
          <Notice tone="warn">{view.warning}</Notice>

          {view.capability.reason && view.capability.reason !== view.reason ? (
            <Notice tone={view.capability.available ? 'warn' : 'info'}>
              {view.capability.reason}
            </Notice>
          ) : null}

          {view.rotating ? (
            <p className="hint">
              {nextChange
                ? `Rotation is on; the next change is around ${nextChange}.`
                : 'Rotation is on.'}
            </p>
          ) : null}

          {/* The device app-tail asked for and the one the tailnet reports carrying traffic
          are different facts, and the gap between them is the whole diagnosis when an
          exit node is not working. */}
          {view.current && view.liveId !== view.current ? (
            <Notice tone="warn">
              {view.liveId
                ? `Your tailnet reports traffic leaving through ${view.liveId} rather than the device app-tail asked for.`
                : 'Your tailnet reports no exit node carrying traffic yet.'}
            </Notice>
          ) : null}

          {candidates.length > 0 ? (
            <ul className="exit-node-candidates">
              {candidates.map((candidate) => (
                <Candidate key={candidate.id} candidate={candidate} />
              ))}
            </ul>
          ) : view.capability.reason ? null : (
            // Only when the agent said nothing about why the list is empty. It usually
            // does, in almost these words, and printing both reads as two separate
            // findings about one empty list.
            <p className="hint">
              Your tailnet is offering no approved exit node. A device has to advertise itself as
              one and an admin has to approve it before it can be chosen here.
            </p>
          )}

          {error ? <Notice tone="error">{error}</Notice> : null}
          {suggestion ? <Notice tone="info">{suggestionText(suggestion)}</Notice> : null}
        </>
      )}

      <CardSettings form={form} groups={['exitnode']} collapseLabel="Exit node settings" />
    </Panel>
  )
}
