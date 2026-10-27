// SPDX-License-Identifier: MIT

// The proxies a program can be pointed at: one card each, plus what this machine's own
// proxy settings are doing.
//
// The module switch is not here. It governs every instance at once, so it lives with the
// other things that decide how app-tail runs on this machine -- and a switch on one card
// that silently turned off the card beside it would be the worst place to put it.

import { useEffect, useState } from 'react'
import {
  api,
  ApiError,
  type AccessProtocol,
  type ProxyInstanceView,
  type ProxySchemaView,
} from '../../api'
import { usePolled, useStore } from '../../data/StoreProvider'
import { href } from '../../lib/router'
import { ModuleOff } from '../ModuleOff'
import { Panel } from '../Panel'
import { CardSettings, switchIsOn } from '../settings/CardSettings'
import type { SettingsForm } from '../settings/useSettingsDraft'
import { Notice } from '../primitives'
import { SystemProxySection } from '../SystemProxySection'
import { AddProxyDialog } from './AddProxyDialog'
import { ProxyInstanceCard } from './ProxyInstanceCard'

/** The proxy module's switch, as the settings document keys it. Every instance is off while
 *  it is off, which is a state rather than a fault. */
const PROXY_SWITCH = 'proxy.enabled'

export function ProxiesSection({ form }: { form: SettingsForm }) {
  const proxies = usePolled('proxies')
  const store = useStore()
  const [protocols, setProtocols] = useState<readonly AccessProtocol[]>([])
  const [schemaError, setSchemaError] = useState<string | undefined>(undefined)
  const [adding, setAdding] = useState(false)
  const held = proxies.data
  const moduleOn = switchIsOn(form, PROXY_SWITCH)

  // Which transports a rule may name is a fact about the agent this page is talking to, not
  // about this bundle, so it is asked for rather than listed here -- and asked once, because
  // it cannot change while the page is open.
  useEffect(() => {
    const ctrl = new AbortController()
    api
      .proxySchema()
      .then((served: ProxySchemaView) => {
        if (!ctrl.signal.aborted) setProtocols(served.protocols)
      })
      .catch((cause: unknown) => {
        // Said out loud: without an answer the tester has no transport to offer, and a
        // control that silently does nothing reads as a build with a broken tester.
        if (!ctrl.signal.aborted) {
          setSchemaError(cause instanceof ApiError ? cause.message : String(cause))
        }
      })
    return () => ctrl.abort()
  }, [])

  const added = (instance: ProxyInstanceView) => {
    setAdding(false)
    store.refreshAll()
    // Straight to its rules. It was added with nothing granted, and granting it something
    // is the only thing that makes it useful.
    window.location.hash = href('connections', 'rules', instance.id)
  }

  if (held === undefined) {
    return (
      <section className="panel" aria-label="Proxies">
        <div className="panel-body">
          <p className="module-off">{proxies.error ?? 'Reading the proxies set up here…'}</p>
        </div>
      </section>
    )
  }

  return (
    <div className="deck">
      {schemaError !== undefined ? (
        <Notice tone="error">Could not read what a rule may say: {schemaError}</Notice>
      ) : null}

      <Panel
        title="Proxies"
        wide
        info={
          <p>
            One loopback proxy per program you want to give a particular reach. Each carries
            exactly what its rules allow and refuses everything else, so pointing a program at
            one is how it gets access to what it needs and nothing more.
          </p>
        }
        actions={
          <button className="btn primary small" onClick={() => setAdding(true)}>
            Add proxy
          </button>
        }
      >
        {!moduleOn ? (
          <ModuleOff>
            Off. Every proxy below keeps its settings and its rules, and none of them is
            listening. The switch that runs them is on the dashboard and on the paths page.
          </ModuleOff>
        ) : (
          <p className="hint">
            {held.length === 1
              ? 'One proxy is set up here.'
              : `${held.length} proxies are set up here.`}{' '}
            A program reaches only what the proxy it is pointed at allows.
          </p>
        )}

        {/* Whether this machine still points at a proxy is a question about the machine
            rather than about any one instance, so it is on the section rather than on a
            card -- and it stays visible while the module is off, which is exactly when
            somebody needs to see it. */}
        <SystemProxySection />

        {/* What is left in the settings document's proxy group once the per-instance fields
            moved onto the instances: whatever governs them together. */}
        <CardSettings
          form={form}
          groups={['proxy']}
          omit={[PROXY_SWITCH]}
          collapseLabel="Settings for all proxies"
        />
      </Panel>

      {held.map((instance) => (
        <ProxyInstanceCard
          key={instance.id}
          instance={instance}
          protocols={protocols}
          app={form}
        />
      ))}

      {adding ? <AddProxyDialog onClose={() => setAdding(false)} onAdded={added} /> : null}
    </div>
  )
}
