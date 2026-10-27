// SPDX-License-Identifier: MIT

// "Would this program be allowed to reach that?", answered without dialling anything.
//
// A permission model nobody can question is one nobody trusts. Rule order is the whole
// difficulty of this model, and an answer of "refused" that does not say which line refused
// it leaves somebody editing rules and guessing which one they are changing -- so the
// result names the rule and its position, which is what the rules table numbers its rows by.

import { useState } from 'react'
import {
  api,
  ApiError,
  type AccessProtocol,
  type ProxyInstanceView,
  type ProxyTestResult,
} from '../../api'
import { Notice } from '../primitives'

export function ProxyTester({
  instance,
  protocols,
}: {
  instance: ProxyInstanceView
  /** The transports the agent will accept, served rather than listed here so this box
   *  cannot offer one the agent refuses the moment it is asked. */
  protocols: readonly AccessProtocol[]
}) {
  const [address, setAddress] = useState('')
  const [protocol, setProtocol] = useState<AccessProtocol>('tcp')
  const [asking, setAsking] = useState(false)
  const [result, setResult] = useState<ProxyTestResult | undefined>(undefined)
  const [error, setError] = useState<string | undefined>(undefined)

  const ask = async () => {
    setAsking(true)
    setResult(undefined)
    setError(undefined)
    try {
      setResult(await api.testProxy(instance.id, address.trim(), protocol))
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setAsking(false)
    }
  }

  const addressId = `proxy-test-address-${instance.id}`
  const protocolId = `proxy-test-protocol-${instance.id}`
  const formatId = `proxy-test-format-${instance.id}`

  return (
    <div className="proxy-test">
      <form
        className="proxy-probe"
        onSubmit={(e) => {
          e.preventDefault()
          void ask()
        }}
      >
        <label htmlFor={addressId}>Can {instance.name} reach</label>
        <input
          id={addressId}
          className="mono"
          aria-describedby={formatId}
          value={address}
          onChange={(e) => setAddress(e.target.value)}
        />
        <label className="sr-only" htmlFor={protocolId}>
          over which transport
        </label>
        <select
          id={protocolId}
          value={protocol}
          onChange={(e) => setProtocol(e.target.value as AccessProtocol)}
        >
          {protocols.map((p) => (
            <option key={p} value={p}>
              {p === '' ? 'any transport' : p.toUpperCase()}
            </option>
          ))}
        </select>
        <button className="btn small" type="submit" disabled={asking || address.trim() === ''}>
          {asking ? 'Asking…' : 'Ask'}
        </button>
        {/* The format stays visible while typing, which is when it is needed; a greyed
            sample inside the box disappears at the first keystroke. */}
        <span className="hint" id={formatId}>
          A name or address with its port, such as db.corp.internal:5432. Nothing is dialled:
          this is the rules being read.
        </span>
      </form>

      {error ? <Notice tone="error">{error}</Notice> : null}
      {result ? <TestVerdict result={result} /> : null}
    </div>
  )
}

/**
 * What the agent decided, and what decided it.
 *
 * A refusal is never the error tone: this is the model working, and colouring it red would
 * make a correctly narrow grant read as a fault every time somebody checked it.
 */
function TestVerdict({ result }: { result: ProxyTestResult }) {
  // A destination nothing could place is a third answer rather than a refusal -- the rules
  // were never consulted -- which is why the resolved address is reported only when there
  // is one instead of being shown empty.
  const placed = result.resolved !== undefined && result.resolved !== ''

  return (
    <Notice tone={result.allowed ? 'info' : 'warn'}>
      <p>
        <strong>{result.allowed ? 'Yes' : 'No'}</strong> — {result.reason}
      </p>
      <dl className="test-facts">
        <div>
          <dt>Destination</dt>
          <dd className="mono">{result.address}</dd>
        </div>
        {placed ? (
          <div>
            <dt>Resolves to</dt>
            <dd className="mono">{result.resolved}</dd>
          </div>
        ) : null}
        {result.tunnelName ? (
          <div>
            <dt>Carried by</dt>
            <dd>{result.tunnelName}</dd>
          </div>
        ) : null}
        <div>
          <dt>Decided by</dt>
          <dd>
            {result.rule === undefined || result.rule === ''
              ? 'no rule — anything no rule allows is refused'
              : `rule ${result.ruleIndex ?? 0} (${result.rule})`}
          </dd>
        </div>
      </dl>
    </Notice>
  )
}
