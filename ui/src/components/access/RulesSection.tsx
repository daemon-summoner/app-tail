// SPDX-License-Identifier: MIT

// The rules that decide what one proxy carries.
//
// It is the last of the three access pages deliberately. What each proxy reaches is a list
// of sentences on the first page, the proxies themselves are the second, and this is where
// somebody comes only when the sentences do not say what they want them to.

import { useEffect, useState } from 'react'
import { api, ApiError, type AccessAction, type AccessProtocol } from '../../api'
import { usePolled } from '../../data/StoreProvider'
import { href } from '../../lib/router'
import { Panel } from '../Panel'
import { Notice } from '../primitives'
import { instanceState } from './instance'
import { RulesTable } from './RulesTable'

export function RulesSection({ id }: { id: string | undefined }) {
  const proxies = usePolled('proxies')
  const tunnels = usePolled('tunnels')
  const [actions, setActions] = useState<readonly AccessAction[]>([])
  const [protocols, setProtocols] = useState<readonly AccessProtocol[]>([])
  const [schemaError, setSchemaError] = useState<string | undefined>(undefined)
  const held = proxies.data

  // The words a rule may be written in are the agent's answer to give, asked once because
  // they cannot change while the page is open.
  useEffect(() => {
    const ctrl = new AbortController()
    api
      .proxySchema()
      .then((served) => {
        if (ctrl.signal.aborted) return
        setActions(served.actions)
        setProtocols(served.protocols)
      })
      .catch((cause: unknown) => {
        // Said out loud: with no vocabulary the table has nothing to offer in its pickers,
        // and a row whose verdict cannot be chosen reads as a broken editor.
        if (!ctrl.signal.aborted) {
          setSchemaError(cause instanceof ApiError ? cause.message : String(cause))
        }
      })
    return () => ctrl.abort()
  }, [])

  if (held === undefined) {
    return (
      <section className="panel" aria-label="Rules">
        <div className="panel-body">
          <p className="module-off">{proxies.error ?? 'Reading the proxies set up here…'}</p>
        </div>
      </section>
    )
  }

  if (id === undefined) return <PickAProxy proxies={held} />

  const instance = held.find((p) => p.id === id)
  if (instance === undefined) {
    return (
      <section className="panel" aria-label="No such proxy">
        <div className="panel-body">
          <p>There is no proxy at that address.</p>
          <p>
            <a href={href('connections', 'rules')}>Back to the proxies</a>
          </p>
        </div>
      </section>
    )
  }

  const state = instanceState(instance)

  return (
    <div className="deck">
      {schemaError !== undefined ? (
        <Notice tone="error">Could not read what a rule may say: {schemaError}</Notice>
      ) : null}

      <Panel
        title={`What ${instance.name} may reach`}
        wide
        status={{
          tone: state.tone,
          label: state.label,
          ...(instance.listening ? { detail: instance.listening } : {}),
        }}
        info={
          <>
            <p>
              The rules are matched from the top. The first one that fits a destination
              decides it, and a destination no rule fits is refused rather than sent direct.
            </p>
            <p>
              A deny is written above the grant it carves an exception out of. Below it, it
              never runs.
            </p>
          </>
        }
        actions={
          <a className="btn ghost small" href={href('connections', 'grants')}>
            What this amounts to
          </a>
        }
      >
        <RulesTable
          instance={instance}
          tunnels={tunnels.data ?? []}
          actions={actions}
          protocols={protocols}
          onSaved={proxies.refresh}
        />
      </Panel>
    </div>
  )
}

/** Whose rules? Rules belong to one proxy, so arriving at this page without naming one is
 *  a question rather than an error. */
function PickAProxy({ proxies }: { proxies: readonly { id: string; name: string }[] }) {
  return (
    <Panel title="Rules" wide>
      {proxies.length === 0 ? (
        <>
          <p className="module-off">
            Rules belong to a proxy, and there are none set up here yet.
          </p>
          <p>
            <a href={href('connections', 'proxies')}>Add one</a>
          </p>
        </>
      ) : (
        <>
          <p className="hint">Rules belong to one proxy. Which one?</p>
          <div className="reach-modes">
            {proxies.map((p) => (
              <a className="reach-mode" key={p.id} href={href('connections', 'rules', p.id)}>
                <span className="reach-mode-name">{p.name}</span>
              </a>
            ))}
          </div>
        </>
      )}
    </Panel>
  )
}
