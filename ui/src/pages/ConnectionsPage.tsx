// SPDX-License-Identifier: MIT

// The private networks this app is attached to: what each one is, what it is doing, and
// what it is configured with.
//
// It is a subject section rather than a page of Settings, for the reason DNS and Forwards
// already are: what a reader comes here to find out is what is connected, and the fields
// that decide it are the second question. Settings holds what the app does; this holds
// what it is attached to.

import { useEffect, useState } from 'react'

import { AddConnectionDialog } from '../components/connections/AddConnectionDialog'
import { AddressConflicts } from '../components/connections/AddressConflicts'
import { ApprovalBanner } from '../components/ApprovalBanner'
import { CardSettings, switchIsOn } from '../components/settings/CardSettings'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { fieldsInGroup } from '../components/settings/fieldState'
import { ExitNodeCard } from '../components/ExitNodeCard'
import { formatBytes, Notice } from '../components/primitives'
import { formatElapsed } from '../components/charts/scale'
import { Panel } from '../components/Panel'
import { RoutesCard } from '../components/RoutesCard'
import { ImportConfigDialog } from '../components/connections/ImportConfigDialog'
import { canImportConfig, connectionHref, toneOf } from '../components/connections/tunnel'
import type { SettingsForm } from '../components/settings/useSettingsDraft'
import { useTunnelDraft } from '../components/settings/useTunnelDraft'
import { usePolled, useStore } from '../data/StoreProvider'
import { href } from '../lib/router'
import {
  api,
  ApiError,
  featureModules,
  type TunnelSchemaView,
  type TunnelHealth,
  type TunnelType,
  type TunnelTypeInfo,
  type TunnelView,
} from '../api'

/** The type headings, in the order the section lists them. Fixed rather than taken from
 *  the connections themselves, so the list does not reorder as connections come and go. */
const TYPE_ORDER: readonly TunnelType[] = ['tailscale', 'wireguard', 'openvpn']

export function ConnectionsPage({
  params,
  form,
}: {
  params: readonly string[]
  /** The installation's own settings, for the module switches on this page. A connection
   *  form cannot carry them: one switch governs every connection. */
  form: SettingsForm
}) {
  const id = params[1]
  return id === undefined ? <ConnectionList /> : <ConnectionDetail id={id} app={form} />
}

function ConnectionList() {
  const tunnels = usePolled('tunnels')
  // Which ranges are contested is a fact about the connections together, so it belongs on
  // the list rather than on any one of them: the connection holding a range has nothing to
  // report, and it is the other one that reaches nothing.
  const fabric = usePolled('fabric')
  const store = useStore()
  const [offered, setOffered] = useState<readonly TunnelTypeInfo[]>([])
  const [offerError, setOfferError] = useState<string | undefined>(undefined)
  const [adding, setAdding] = useState<TunnelTypeInfo | undefined>(undefined)
  const held = tunnels.data

  // Which kinds can be added is a fact about the agent this page is talking to, not about
  // this bundle, so it is asked for rather than listed here -- and asked once, because it
  // cannot change while the page is open.
  useEffect(() => {
    const ctrl = new AbortController()
    api
      .tunnelSchema()
      .then((served: TunnelSchemaView) => {
        if (!ctrl.signal.aborted) setOffered(served.types)
      })
      .catch((cause: unknown) => {
        // Said out loud: with no answer there is no Add button anywhere on this page, and
        // a page with nothing to press and no explanation reads as a build that cannot add
        // connections at all.
        if (!ctrl.signal.aborted) {
          setOfferError(cause instanceof ApiError ? cause.message : String(cause))
        }
      })
    return () => ctrl.abort()
  }, [])

  const added = (tunnel: TunnelView) => {
    setAdding(undefined)
    store.refreshAll()
    // Straight to the new connection. It was added with nothing but a name, and the things
    // that make it reach a network are on its own page.
    window.location.hash = connectionHref(tunnel)
  }

  if (held === undefined) {
    return (
      <section className="panel" aria-label="Connections">
        <div className="panel-body">
          <p className="module-off">
            {tunnels.error ?? 'Reading the connections this app is attached to…'}
          </p>
        </div>
      </section>
    )
  }

  // A type is listed when something is connected with it or when one can be added. An
  // empty heading with an Add button is a feature that has not been used yet; an empty
  // heading without one would be an offer this build cannot honour, which reads as a fault.
  const groups = TYPE_ORDER.flatMap((type) => {
    const offer = offered.find((o) => o.value === type)
    const rows = held.filter((t) => t.type === type)
    const label = offer?.label ?? rows[0]?.typeLabel
    return label === undefined ? [] : [{ type, label, offer, rows }]
  })

  return (
    <div className="deck">
      {offerError !== undefined ? (
        <Notice tone="error">Could not read what kinds of connection can be added: {offerError}</Notice>
      ) : null}

      <AddressConflicts view={fabric.data} />

      {groups.map(({ type, label, offer, rows }) => (
        <Panel
          key={type}
          title={label}
          wide
          actions={
            offer ? (
              <button className="btn primary small" onClick={() => setAdding(offer)}>
                Add {label}
              </button>
            ) : null
          }
        >
          {rows.length === 0 ? (
            <p className="module-off">No {label} networks are set up here yet.</p>
          ) : (
            <div className="reach-modes">
              {rows.map((tunnel) => (
                <ConnectionRow key={tunnel.id} tunnel={tunnel} />
              ))}
            </div>
          )}
        </Panel>
      ))}

      {adding ? (
        <AddConnectionDialog
          offer={adding}
          onClose={() => setAdding(undefined)}
          onAdded={added}
        />
      ) : null}
    </div>
  )
}

function ConnectionRow({ tunnel }: { tunnel: TunnelView }) {
  return (
    <a className="reach-mode" href={connectionHref(tunnel)}>
      <span className="reach-mode-name">{tunnel.name}</span>
      <span className={`status ${toneOf(tunnel.state)}`}>
        <span className="dot" aria-hidden="true" />
        {tunnel.stateLabel}
      </span>
    </a>
  )
}

/**
 * One connection: what it is doing above, what it is configured with below.
 *
 * The form is rendered from the schema the agent serves, so a field added to the
 * connection registry appears here under its own section with its label, its help and its
 * validation, and nothing in this file changes.
 */
function ConnectionDetail({ id, app }: { id: string; app: SettingsForm }) {
  const tunnels = usePolled('tunnels')
  const store = useStore()
  // Several of a connection's settings are gated on a module switched on the installation
  // rather than on the connection -- the switch in the head of the routes card is one. The
  // connection form has no way to read them, so this is where their live values reach it:
  // without them, turning a module on here reveals nothing until the page is reloaded.
  const gates = Object.fromEntries(
    featureModules.map((m) => [m.switchKey, switchIsOn(app, m.switchKey)]),
  )
  // Bumped when a configuration file is read in, which rewrites every field at once behind
  // the form's back.
  const [imported, setImported] = useState(0)
  const draft = useTunnelDraft(id, gates, imported)
  const routes = usePolled('routes')
  const exitNode = usePolled('exitNode')
  const status = usePolled('status')
  const tunnel = tunnels.data?.find((t) => t.id === id)
  const [confirming, setConfirming] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [removeError, setRemoveError] = useState<string | undefined>(undefined)
  const [importing, setImporting] = useState(false)
  const [retrying, setRetrying] = useState(false)
  const [retryError, setRetryError] = useState<string | undefined>(undefined)

  const remove = async () => {
    setRemoving(true)
    setRemoveError(undefined)
    try {
      await api.deleteTunnel(id)
      setConfirming(false)
      store.refreshAll()
      // Back to the list, because the page this is on describes a connection that is no
      // longer there.
      window.location.hash = href('connections')
    } catch (cause) {
      // Onto the page rather than into the dialog: the dialog closes with the attempt, and
      // the reason a connection could not be removed belongs beside the connection.
      setRemoveError(cause instanceof ApiError ? cause.message : String(cause))
      setConfirming(false)
    } finally {
      setRemoving(false)
    }
  }

  // Building the connection again, which is the only lever for one that is up and carrying
  // nothing: nothing about it has changed, so no save would rebuild it.
  const retry = async () => {
    setRetrying(true)
    setRetryError(undefined)
    try {
      await api.retryTunnel(id)
      // Everything on the page reads the connection: its state, its addresses, what it
      // routes. The rebuild replaced all of it.
      store.refreshAll()
    } catch (cause) {
      setRetryError(cause instanceof ApiError ? cause.message : String(cause))
    } finally {
      setRetrying(false)
    }
  }

  // Each view names the connection it is about, so a card appears here only on that
  // connection's page. `owned` is which sections a card is already showing, so the fields
  // below are not drawn a second time under a heading of their own.
  const routesHere = routes.data?.tunnelId === id ? routes.data : undefined
  const exitNodeHere = exitNode.data?.tunnelId === id ? exitNode.data : undefined
  const owned = new Set<string>()
  if (routesHere) owned.add('routing')
  if (exitNodeHere) owned.add('exitnode')

  if (tunnels.data !== undefined && tunnel === undefined) {
    return (
      <section className="panel" aria-label="No such connection">
        <div className="panel-body">
          <p>There is no connection at that address.</p>
          <p>
            <a href={href('connections')}>Back to the connections</a>
          </p>
        </div>
      </section>
    )
  }

  return (
    <div className="deck">
      <ApprovalBanner
        approvals={status.data?.approvals}
        feature={`openvpn:${id}`}
        onApproved={() => store.refreshAll()}
      />

      {tunnel ? (
        <ConnectionOverview
          tunnel={tunnel}
          error={removeError ?? retryError}
          onRemove={tunnel.removable ? () => setConfirming(true) : undefined}
          onImport={canImportConfig(tunnel.type) ? () => setImporting(true) : undefined}
          onRetry={tunnel.retryable ? () => void retry() : undefined}
          retrying={retrying}
        />
      ) : null}

      {draft.error !== undefined ? (
        <section className="panel" aria-label="Connection settings">
          <div className="panel-body">
            <p className="module-off">{draft.error}</p>
          </div>
        </section>
      ) : null}

      {/* What each of these is doing, above the fields that decide it. A card is shown for
          the connection it describes and no other: what one network routes and where its
          traffic leaves are that network's answers, and showing them under a second
          connection would attribute them to a tailnet that never gave them. */}
      {routesHere ? <RoutesCard view={routesHere} form={draft} app={app} /> : null}
      {exitNodeHere ? <ExitNodeCard view={exitNodeHere} form={draft} app={app} /> : null}

      {draft.groups
        .filter((group) => !owned.has(group.id))
        // A section whose every field is gated off for this connection has nothing to
        // draw, and CardSettings renders nothing for it: without this the page shows a
        // heading and a description over an empty card, which reads as a feature that
        // failed to load rather than one this connection does not have.
        .filter((group) => fieldsInGroup(draft.available, group.id, true).length > 0)
        .map((group) => (
          <Panel key={group.id} title={group.label} info={<p>{group.description}</p>}>
            <CardSettings form={draft} groups={[group.id]} />
          </Panel>
        ))}

      {importing && tunnel ? (
        <ImportConfigDialog
          tunnel={tunnel}
          onClose={() => setImporting(false)}
          onImported={() => {
            setImporting(false)
            setImported((n) => n + 1)
            store.refreshAll()
          }}
        />
      ) : null}

      {confirming && tunnel ? (
        <ConfirmDialog
          title={`Remove ${tunnel.name}?`}
          confirmLabel="Remove connection"
          destructive
          busy={removing}
          busyLabel="Removing…"
          onConfirm={() => void remove()}
          onClose={() => setConfirming(false)}
        >
          <p>
            This stops the connection and deletes everything configured for it, including the
            credentials it enrolled with.
          </p>
          <p>
            To stop it without losing any of that, switch off “Connect to this network”
            instead.
          </p>
        </ConfirmDialog>
      ) : null}
    </div>
  )
}

/**
 * What the connection says about itself, beside what it says it is.
 *
 * The state word reads "connected" both for a connection carrying traffic and for one that
 * agreed keys an hour ago and has moved nothing since. These are the figures that tell those
 * apart, and until now the app knew them and showed them nowhere.
 */
function HealthFacts({ health }: { health: TunnelHealth }) {
  return (
    <>
      <div>
        <dt>Carried</dt>
        <dd>
          {formatBytes(health.up)} sent, {formatBytes(health.down)} received
        </dd>
      </div>
      {/* Absent rather than "never": a kind with no handshake at all and one that has not
          completed its first are different facts, and neither is served as a moment. */}
      {health.lastHandshake ? (
        <div>
          <dt>Last handshake</dt>
          <dd>{sinceThen(health.lastHandshake)}</dd>
        </div>
      ) : null}
      {health.since ? (
        <div>
          <dt>Up for</dt>
          <dd>{elapsedSince(health.since)}</dd>
        </div>
      ) : null}
    </>
  )
}

/** elapsedSince is how long ago a served moment was, as a duration. A moment in the future --
 *  a machine whose clock moved while the connection was up -- reads as no time at all rather
 *  than as a negative one. */
function elapsedSince(at: string): string {
  const ms = Date.now() - Date.parse(at)
  return formatElapsed(Number.isFinite(ms) && ms > 0 ? ms / 1000 : 0)
}

/** sinceThen is the same duration said as a moment in the past, which is how a handshake
 *  reads: "2m ago", not "2m". */
function sinceThen(at: string): string {
  return `${elapsedSince(at)} ago`
}

function ConnectionOverview({
  tunnel,
  onRemove,
  onImport,
  onRetry,
  retrying,
  error,
}: {
  tunnel: TunnelView
  /** Absent when this connection may not be removed, which the agent decides. */
  onRemove: (() => void) | undefined
  /** Absent for a kind of connection that is not configured from a file. */
  onImport: (() => void) | undefined
  /** Absent when the agent would refuse to build this connection again -- switched off, or
   *  a kind this build does not start. */
  onRetry: (() => void) | undefined
  retrying: boolean
  error: string | undefined
}) {
  return (
    <Panel
      title={tunnel.name}
      wide
      status={{
        tone: toneOf(tunnel.state),
        label: tunnel.stateLabel,
        ...(tunnel.detail === undefined ? {} : { detail: tunnel.detail }),
      }}
      actions={
        <>
          {tunnel.authUrl ? (
            // A login is finished at the control plane's own page, so the only thing this
            // can do is take the reader there.
            <a className="btn primary small" href={tunnel.authUrl} target="_blank" rel="noreferrer">
              Sign in
            </a>
          ) : null}
          {onRetry ? (
            // Offered whether or not the connection is up: the state this is for is a
            // connection that says it is connected and carries nothing, and a button that
            // hid itself in exactly that case would be missing when it is needed.
            <button className="btn small" onClick={onRetry} disabled={retrying}>
              {retrying ? 'Reconnecting…' : 'Reconnect'}
            </button>
          ) : null}
          {onImport ? (
            <button className="btn small" onClick={onImport}>
              Import configuration
            </button>
          ) : null}
          {onRemove ? (
            <button className="btn danger small" onClick={onRemove}>
              Remove
            </button>
          ) : null}
        </>
      }
    >
      {error !== undefined ? <Notice tone="error">{error}</Notice> : null}

      <dl className="tunnel-facts">
        <div>
          <dt>Type</dt>
          <dd>{tunnel.typeLabel}</dd>
        </div>
        <div>
          <dt>Short name</dt>
          <dd className="mono">{tunnel.slug}</dd>
        </div>
        {tunnel.health ? <HealthFacts health={tunnel.health} /> : null}
        {tunnel.addrs?.length ? (
          <div>
            <dt>Addresses</dt>
            <dd className="mono">{tunnel.addrs.join(', ')}</dd>
          </div>
        ) : null}
        {tunnel.names?.length ? (
          <div>
            <dt>Names</dt>
            <dd className="mono">{tunnel.names.join(', ')}</dd>
          </div>
        ) : null}
      </dl>

      {/* Stated up front, and never cleared: these are things this kind of connection
          does not carry at all, so meeting one later as a fault would cost someone an
          afternoon looking for a break that was never there. */}
      {tunnel.limits?.length ? (
        <ul className="tunnel-limits">
          {tunnel.limits.map((limit) => (
            <li key={limit}>{limit}</li>
          ))}
        </ul>
      ) : null}
    </Panel>
  )
}
