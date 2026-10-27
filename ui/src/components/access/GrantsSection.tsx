// SPDX-License-Identifier: MIT

// What each program pointed at this app is allowed to reach, in sentences.
//
// It is the first page of Access and the only one somebody has to read. The sentences are
// written by the agent, so the dashboard, the menu bar and the command line cannot describe
// one instance's permissions differently -- and a reader who never opens the rules table
// still learns exactly what they have granted.

import type { ProxyInstanceView } from '../../api'
import { usePolled } from '../../data/StoreProvider'
import { href } from '../../lib/router'
import { Panel } from '../Panel'
import { addressesOf, instanceState, rulesHref } from './instance'

export function GrantsSection() {
  const proxies = usePolled('proxies')
  const held = proxies.data

  if (held === undefined) {
    return (
      <section className="panel" aria-label="What can reach what">
        <div className="panel-body">
          <p className="module-off">{proxies.error ?? 'Reading what each proxy is allowed to reach…'}</p>
        </div>
      </section>
    )
  }

  if (held.length === 0) {
    return (
      <Panel title="What can reach what" wide>
        <p className="module-off">
          There are no proxies set up here yet. A proxy is what a program is pointed at, and
          its rules are what that program may reach.
        </p>
        <p>
          <a href={href('connections', 'proxies')}>Add one</a>
        </p>
      </Panel>
    )
  }

  return (
    <div className="deck">
      <Panel
        title="What can reach what"
        wide
        info={
          <>
            <p>
              One entry per proxy: what a program pointed at it may reach, and nothing else.
              Anything no rule allows is refused rather than sent direct.
            </p>
            <p>
              These sentences are the rules read back. To change what one reaches, change its
              rules.
            </p>
          </>
        }
      >
        <p className="hint">
          Each list is in the order the rules are matched: the first line that fits a
          destination decides it.
        </p>
      </Panel>

      {held.map((instance) => (
        <GrantCard key={instance.id} instance={instance} />
      ))}
    </div>
  )
}

function GrantCard({ instance }: { instance: ProxyInstanceView }) {
  const state = instanceState(instance)
  // Where a program is pointed. One line rather than the whole address block the instance
  // card carries: this page is about what is granted, and the address is here only so the
  // sentence has a subject somebody recognises.
  const at = instance.listening ?? instance.configuredAddr

  return (
    <Panel
      title={instance.name}
      wide
      status={{ tone: state.tone, label: state.label, ...(at ? { detail: at } : {}) }}
      actions={
        <>
          <a className="btn small" href={rulesHref(instance)}>
            Change what it reaches
          </a>
          <a className="btn ghost small" href={href('connections', 'proxies')}>
            Its settings
          </a>
        </>
      }
    >
      {instance.error ? <p className="module-off">{instance.error}</p> : null}

      <ol className="grant-list">
        {instance.reach.map((sentence, at) => (
          // Keyed by position because that is what a sentence here is: the rules are an
          // ordered list, two of them may read alike, and the order is the meaning.
          <li key={`${at}-${sentence}`}>{sentence}</li>
        ))}
      </ol>

      {addressesOf(instance).length > 0 ? (
        <p className="hint">
          Point a program at {addressesOf(instance)[0]?.value} to give it exactly this.
        </p>
      ) : null}
    </Panel>
  )
}
