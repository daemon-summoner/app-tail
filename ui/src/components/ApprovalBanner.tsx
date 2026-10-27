// SPDX-License-Identifier: MIT

import { useId, useState } from 'react'

import { api, ApiError, type ApprovalNeed, type Approvals } from '../api'
import { CodeBlock, Notice } from './primitives'

/** How the last approval ended when it did not approve anything. A cancelled prompt is the
 *  person's own choice, and 501 is a platform with no prompt the dashboard can raise; only
 *  the rest are failures. */
type Outcome =
  | { kind: 'cancelled'; message: string }
  | { kind: 'unsupported'; message: string }
  | { kind: 'failed'; message: string }

function outcomeOf(cause: unknown): Outcome {
  if (cause instanceof ApiError) {
    if (cause.status === 409) return { kind: 'cancelled', message: cause.message }
    if (cause.status === 501) return { kind: 'unsupported', message: cause.message }
    return { kind: 'failed', message: cause.message }
  }
  return { kind: 'failed', message: String(cause) }
}

/**
 * The network changes the root helper refuses until an administrator approves them, and the
 * button that asks for that approval.
 *
 * With `feature`, it shows only when that part of app-tail is among those waiting, and leads
 * with its changes. The approval itself still covers everything pending -- the agent decides
 * that, not this page -- so the rest is listed too rather than approved unseen.
 */
export function ApprovalBanner({
  approvals,
  feature,
  onApproved,
}: {
  approvals: Approvals | undefined
  feature?: string
  onApproved: () => void
}) {
  const headingId = useId()
  const [busy, setBusy] = useState(false)
  const [outcome, setOutcome] = useState<Outcome | undefined>(undefined)
  // The agent's answer to the last approval, kept only while the status it answered is the one
  // still shown: the next poll is a newer account of what is waiting and replaces it.
  const [answered, setAnswered] = useState<{ to: Approvals | undefined; with: Approvals }>()

  const current = answered !== undefined && answered.to === approvals ? answered.with : approvals
  const needs = current?.needs ?? []
  const asked = (need: ApprovalNeed) => feature === undefined || need.features.includes(feature)
  const mine = needs.filter(asked)
  const others = needs.filter((need) => !asked(need))

  if (current === undefined || mine.length === 0) return null

  const approve = async () => {
    setBusy(true)
    setOutcome(undefined)
    try {
      setAnswered({ to: approvals, with: await api.approveNetworkChanges() })
      onApproved()
    } catch (cause) {
      setOutcome(outcomeOf(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section aria-labelledby={headingId}>
      <Notice tone="warn">
        <div className="notice-stack">
          <strong id={headingId}>Needs your approval</strong>
          <span>
            app-tail needs an administrator&apos;s OK before it changes these things on this
            machine:
          </span>
          <ul className="notice-list">
            {mine.map((need) => (
              <li key={needKey(need)}>{need.reason}</li>
            ))}
          </ul>
          {others.length > 0 ? (
            <>
              <span>The same approval also covers:</span>
              <ul className="notice-list">
                {others.map((need) => (
                  <li key={needKey(need)}>{need.reason}</li>
                ))}
              </ul>
            </>
          ) : null}
          <div className="notice-row">
            <button
              className="btn primary small"
              disabled={busy}
              aria-busy={busy}
              onClick={() => void approve()}
            >
              {busy ? 'Waiting for approval…' : 'Approve…'}
            </button>
          </div>
          {current.command !== '' ? (
            <details className="advanced">
              <summary>Prefer the terminal?</summary>
              <div className="advanced-body">
                <CodeBlock text={current.command} />
              </div>
            </details>
          ) : null}
        </div>
      </Notice>
      {outcome?.kind === 'cancelled' ? (
        <div role="status">
          <Notice tone="info">{outcome.message}</Notice>
        </div>
      ) : outcome !== undefined ? (
        <div role="alert">
          {outcome.kind === 'failed' ? (
            <Notice tone="error">Could not approve: {outcome.message}</Notice>
          ) : (
            <Notice tone="warn">{outcome.message}</Notice>
          )}
        </div>
      ) : null}
    </section>
  )
}

/** Two needs of one kind differ by their value (two ranges, two domains) or, for one
 *  OpenVPN server, by the certificate authorities it is pinned to. */
function needKey(need: ApprovalNeed): string {
  return `${need.kind} ${need.value ?? ''} ${need.caSha256?.join(',') ?? ''}`
}
