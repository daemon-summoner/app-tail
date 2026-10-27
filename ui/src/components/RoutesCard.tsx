// SPDX-License-Identifier: MIT

import { useState } from 'react'
import { api, ApiError, type RouteCheckResult, type RoutesView } from '../api'
import { InfoList, InfoPopover } from './InfoPopover'
import { ModuleOff } from './ModuleOff'
import { Panel } from './Panel'
import { CardSettings, ModuleSwitch } from './settings/CardSettings'
import type { EntityForm } from './settings/useEntityDraft'
import { Notice, formatBytes } from './primitives'

/** The state the module is in, as one word plus the colour that goes with it. The agent
 *  has already decided this in `capability`; this only names it. */
function routesState(view: RoutesView): { tone: string; label: string } {
  // Off is a state, not a fault: a module nobody switched on and a module that could not
  // start both arrive as unavailable, and only the switch tells them apart.
  if (!view.enabled) return { tone: 'off', label: 'off' }
  if (!view.capability.available) return { tone: 'error', label: 'off' }
  if (view.capability.degraded) return { tone: 'pending', label: 'not carrying traffic' }
  return { tone: 'running', label: 'carrying traffic' }
}

/** One list of networks with what it means, or the sentence that says it is empty. The
 *  empty case is the one that matters: three blank columns look like a page that failed
 *  to load, and each of these is empty for a different, actionable reason. */
function Networks({
  title,
  hint,
  prefixes,
  empty,
}: {
  title: string
  hint: string
  prefixes: string[]
  empty: string
}) {
  return (
    <div className="routes-list">
      <div className="list-head">
        <h3>{title}</h3>
        {/* What the column means never changes; which prefixes are in it is the answer.
            The hint sat between the two and pushed the answer down three columns. */}
        <InfoPopover label={title}>
          <p>{hint}</p>
        </InfoPopover>
      </div>
      {prefixes.length > 0 ? (
        <ul>
          {prefixes.map((prefix) => (
            <li key={prefix} className="mono">
              {prefix}
            </li>
          ))}
        </ul>
      ) : (
        <p className="routes-empty">{empty}</p>
      )}
    </div>
  )
}

/** What a probe found, as sentences. A device carrying a route it cannot reach reads as
 *  a working route everywhere else on this page, so the negative result is spelled out
 *  rather than left as an absent entry. */
function CheckResult({ result }: { result: RouteCheckResult }) {
  if (result.routes.length === 0) {
    return <Notice tone="info">{result.reason ?? 'Nothing was checked.'}</Notice>
  }
  return (
    <ul className="routes-check">
      {result.routes.map((entry) => (
        <li key={entry.prefix}>
          <span className="mono">{entry.prefix}</span>
          <span className={`status ${entry.reachable ? 'running' : 'stopped'}`}>
            <span className="dot" aria-hidden="true" />
            {entry.reachable
              ? `carried by ${(entry.via ?? []).join(', ')}`
              : 'no device answered for it'}
          </span>
        </li>
      ))}
    </ul>
  )
}

/**
 * The two forms are two different things, which is why they are two arguments: `form`
 * holds this connection's own settings, and `app` holds the switch that turns subnet
 * routing on for the installation. The switch is not a property of one network -- turning
 * it off stops every connection routing -- so it cannot live on the connection's form.
 */
export function RoutesCard({
  view,
  form,
  app,
}: {
  view: RoutesView
  form: EntityForm
  app: EntityForm
}) {
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState<RouteCheckResult | undefined>(undefined)
  const [error, setError] = useState<string | undefined>(undefined)

  const check = async () => {
    setChecking(true)
    setError(undefined)
    setResult(undefined)
    try {
      setResult(await api.checkRoutes())
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setChecking(false)
    }
  }

  const state = routesState(view)

  return (
    <Panel
      title="Subnet routes"
      wide
      status={{ tone: state.tone, label: state.label }}
      // Every one of these limits is otherwise filed as a bug against a router working
      // exactly as far as it can. They hold whether or not anything is being carried, so
      // they belong with what the module always is rather than with what is wrong now.
      info={
        <>
          <p>
            Reach the private networks other devices on your tailnet advertise, such as a home LAN
            behind a subnet router.
          </p>
          <InfoList items={view.capability.limits ?? []} />
        </>
      }
      controls={<ModuleSwitch form={app} switchKey="routes.enabled" />}
      actions={
        <button className="btn ghost small" disabled={checking} onClick={() => void check()}>
          {checking ? 'Checking…' : 'Check reachability'}
        </button>
      }
    >
      {!view.enabled ? (
        <ModuleOff>
          Off. Turn this on to reach the private networks other devices on your tailnet advertise.
        </ModuleOff>
      ) : (
        <>
          {view.capability.reason ? (
            <Notice tone={view.capability.available ? 'warn' : 'info'}>
              {view.capability.reason}
            </Notice>
          ) : null}

          <div className="routes-lists">
            <Networks
              title="Reaching"
              hint="Networks this device can reach through its peers."
              prefixes={view.reaching ?? []}
              empty={
                view.accepting
                  ? 'No device on your tailnet is advertising a network to this one.'
                  : 'This device is not accepting the networks its peers advertise.'
              }
            />
            <Networks
              title="Offering"
              hint="Networks this device asks to carry for the rest of the tailnet."
              prefixes={view.advertised ?? []}
              empty="This device offers no network of its own."
            />
            <Networks
              title="Approved"
              hint="What your tailnet actually routes here. Advertising is only a request."
              prefixes={view.approved ?? []}
              empty="Nothing this device offers has been approved yet."
            />
          </div>

          {/* Only once something is being carried: before then every number is zero and a
          row of zeroes reads as a router that is failing rather than one nobody has
          asked to do anything. */}
          {view.serving ? (
            <dl className="proxy-counters">
              <div>
                <dt>Carried</dt>
                <dd>{view.carried}</dd>
              </div>
              <div>
                <dt title="Connections to an address outside every network the tailnet approved">
                  Refused
                </dt>
                <dd>{view.refused}</dd>
              </div>
              <div>
                <dt>In</dt>
                <dd>{formatBytes(view.bytesIn)}</dd>
              </div>
              <div>
                <dt>Out</dt>
                <dd>{formatBytes(view.bytesOut)}</dd>
              </div>
            </dl>
          ) : null}

          {/* Separate from the capability reason, which explains the module as a whole: this
          is the last thing that stopped this device carrying traffic it was asked to. */}
          {view.error ? <Notice tone="error">{view.error}</Notice> : null}

          {error ? <Notice tone="error">{error}</Notice> : null}
          {result ? <CheckResult result={result} /> : null}
        </>
      )}

      <CardSettings form={form} groups={['routing']} collapseLabel="Route settings" />
    </Panel>
  )
}
