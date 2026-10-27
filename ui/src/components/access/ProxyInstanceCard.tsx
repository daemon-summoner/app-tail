// SPDX-License-Identifier: MIT

// One proxy instance: where a program points at it, what it has carried, and what it is
// configured with.
//
// The form is rendered from the schema the agent serves, so a field added to the instance
// registry appears here under its label, its help and its validation with nothing in this
// file changing. The permissions are deliberately not in it: a rule is a tuple matched in
// order rather than a field with a value, so it has a table of its own.

import { useMemo, useState } from 'react'
import {
  api,
  ApiError,
  featureModules,
  type AccessProtocol,
  type ProxyInstanceView,
} from '../../api'
import { usePolled, useStore } from '../../data/StoreProvider'
import { ConfirmDialog } from '../ConfirmDialog'
import { Panel } from '../Panel'
import { CardSettings, switchIsOn } from '../settings/CardSettings'
import type { SettingsForm } from '../settings/useSettingsDraft'
import { useProxyDraft } from '../settings/useProxyDraft'
import { CodeBlock, CopyButton, Notice, formatBytes } from '../primitives'
import { addressesOf, instanceState, rulesHref } from './instance'
import { ProxyTester } from './ProxyTester'

export function ProxyInstanceCard({
  instance,
  protocols,
  app,
}: {
  instance: ProxyInstanceView
  protocols: readonly AccessProtocol[]
  /** The installation's own settings. Most of an instance's fields are gated on the proxy
   *  module, which is a switch on the installation rather than on the instance, so without
   *  the live values turning it on would reveal nothing until the page was reloaded. */
  app: SettingsForm
}) {
  const store = useStore()
  const proxies = usePolled('proxies')
  const gates = Object.fromEntries(
    featureModules.map((m) => [m.switchKey, switchIsOn(app, m.switchKey)]),
  )
  const draft = useProxyDraft(instance.id, gates)
  // A save is read back into the card as well as into the form: half of what this card
  // shows above the form -- where it is listening, what it has carried, what its rules
  // amount to -- is the polled instance rather than the draft, and waiting a poll for a
  // rename to appear reads as a save that did not take.
  const form = useMemo(
    () => ({
      ...draft,
      saveGroup: async (groups: readonly string[]) => {
        await draft.saveGroup(groups)
        proxies.refresh()
      },
    }),
    [draft, proxies],
  )
  const [confirming, setConfirming] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [removeError, setRemoveError] = useState<string | undefined>(undefined)

  const remove = async () => {
    setRemoving(true)
    setRemoveError(undefined)
    try {
      await api.deleteProxy(instance.id)
      setConfirming(false)
      store.refreshAll()
    } catch (cause) {
      // Onto the card rather than into the dialog: the dialog closes with the attempt, and
      // the reason an instance could not be removed belongs beside the instance.
      setRemoveError(cause instanceof ApiError ? cause.message : String(cause))
      setConfirming(false)
    } finally {
      setRemoving(false)
    }
  }

  const state = instanceState(instance)
  const published = addressesOf(instance)

  return (
    <Panel
      title={instance.name}
      wide
      status={{
        tone: state.tone,
        label: state.label,
        ...(instance.listening ? { detail: instance.listening } : {}),
      }}
      info={
        <>
          <p>
            A loopback proxy that carries exactly what its rules allow. Anything they do not
            is refused rather than sent direct.
          </p>
          <p>Short name: {instance.slug}.</p>
        </>
      }
      actions={
        <>
          <a className="btn small" href={rulesHref(instance)}>
            Rules <span className="count">{instance.rules.length}</span>
          </a>
          {instance.removable ? (
            <button className="btn danger small" onClick={() => setConfirming(true)}>
              Remove
            </button>
          ) : null}
        </>
      }
    >
      {removeError !== undefined ? <Notice tone="error">{removeError}</Notice> : null}
      {instance.error ? <Notice tone="error">{instance.error}</Notice> : null}

      {/* Said out loud, because a snippet naming one port while the card shows another is
          otherwise a mystery: a port conflict moved the listener. */}
      {instance.movedFromConfig ? (
        <Notice tone="warn">
          This asked for {instance.configuredAddr} and that port was taken, so it is
          listening on {instance.listening} instead.
        </Notice>
      ) : null}

      {instance.capability.reason ? (
        <Notice tone={instance.capability.available ? 'warn' : 'error'}>
          {instance.capability.reason}
        </Notice>
      ) : null}

      <div className="proxy-body">
        {published.length > 0 ? (
          <div className="proxy-addresses">
            {published.map((address) => (
              <div className="proxy-address" key={address.label}>
                <span className="proxy-address-label">{address.label}</span>
                <code className="mono">{address.value}</code>
                <CopyButton text={address.value} />
                <span className="proxy-address-hint">{address.hint}</span>
              </div>
            ))}
          </div>
        ) : null}

        {instance.requiresPassword ? (
          <p className="hint">
            This instance demands a password, with the username app-tail. An
            auto-configuration file has nowhere to put one, so a browser configured that way
            cannot use it.
          </p>
        ) : null}

        <dl className="proxy-counters">
          <div>
            <dt>Open</dt>
            <dd>{instance.counters.active}</dd>
          </div>
          <div>
            <dt>Total</dt>
            <dd>{instance.counters.opened}</dd>
          </div>
          <div>
            <dt title="Destinations no rule allows, which are refused rather than sent direct">
              Refused
            </dt>
            <dd>{instance.counters.refused}</dd>
          </div>
          <div>
            <dt title="Destinations a rule allows that could not be reached">Failed</dt>
            <dd>{instance.counters.failed}</dd>
          </div>
          <div>
            <dt>Up</dt>
            <dd>{formatBytes(instance.counters.bytesUp)}</dd>
          </div>
          <div>
            <dt>Down</dt>
            <dd>{formatBytes(instance.counters.bytesDown)}</dd>
          </div>
        </dl>

        {/* Folded away, because a card is read to find out what an instance reaches far more
            often than to copy a command. What is offered differs per instance: the ways that
            go back through app-tail itself address the instance the command line reaches, and
            are served only for it. */}
        {instance.snippets.length > 0 ? (
          <details className="advanced">
            <summary>Ways to point something at it</summary>
            <div className="advanced-body">
              {instance.snippets.map((snippet) => (
                <div className="field" key={snippet.id}>
                  <span className="field-caption">{snippet.label}</span>
                  <CodeBlock text={snippet.command} />
                  <span className="hint">{snippet.description}</span>
                </div>
              ))}
            </div>
          </details>
        ) : null}

        <ProxyTester instance={instance} protocols={protocols} />
      </div>

      {draft.error !== undefined ? <Notice tone="error">{draft.error}</Notice> : null}

      <CardSettings
        form={form}
        groups={draft.groups.map((g) => g.id)}
        collapseLabel={`${instance.name} settings`}
      />

      {confirming ? (
        <ConfirmDialog
          title={`Remove ${instance.name}?`}
          confirmLabel="Remove proxy"
          destructive
          busy={removing}
          busyLabel="Removing…"
          onConfirm={() => void remove()}
          onClose={() => setConfirming(false)}
        >
          <p>
            This stops the listener and deletes its rules. Anything pointed at{' '}
            {instance.listening ?? instance.configuredAddr} stops working.
          </p>
          <p>
            To stop it without losing how it was set up, switch “Run this proxy” off instead.
          </p>
        </ConfirmDialog>
      ) : null}
    </Panel>
  )
}
