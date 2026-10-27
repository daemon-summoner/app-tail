// SPDX-License-Identifier: MIT

import { useEffect, useMemo, useState } from 'react'
import { api, ApiError, type PolicyBootstrapRequest, type PolicyPlanView, type Settings } from '../api'
import { CodeBlock, Notice, Scrim } from './primitives'
import { CloseIcon } from './shell/icons'

// The Tailscale control plane an empty controlURL resolves to. Any other value is a
// self-hosted control server (Headscale), whose ACLs the one-click path cannot edit.
const TAILSCALE_CONTROL_URL = 'https://controlplane.tailscale.com'
const DEFAULT_TAG = 'tag:app-tail'

// Deep link to the page the click-path starts on, so finding Access controls in the
// admin console collapses into one click.
const ACCESS_CONTROLS_URL = 'https://login.tailscale.com/admin/acls'

/** bareName strips the tag: prefix. The admin console's Create tag field takes the
 *  name alone and renders the prefix itself. */
function bareName(tag: string): string {
  return tag.replace(/^tag:/, '')
}

/** buildSnippet renders the tagOwners (and an example grant) the fleet needs, in the
 *  HuJSON the Tailscale admin console accepts. It mirrors what the one-click apply
 *  writes, so the two paths agree. The grant's dst is illustrative: the admin scopes it. */
function buildSnippet(tags: string[]): string {
  const owners = tags.map((t) => `    ${JSON.stringify(t)}: ["autogroup:admin"],`).join('\n')
  const srcs = tags.map((t) => JSON.stringify(t)).join(', ')
  return [
    '{',
    "  // Let this fleet's devices self-assign their app-tail tag.",
    '  "tagOwners": {',
    owners,
    '  },',
    '  // Let tagged devices reach one another. Edit "dst" to scope access.',
    '  "grants": [',
    `    { "src": [${srcs}], "dst": [${srcs}], "ip": ["*"] },`,
    '  ],',
    '}',
  ].join('\n')
}

/** buildCli renders the equivalent bootstrap-policy command, one per tag (the flag is
 *  single-valued). The secret is passed by file, never in argv. */
function buildCli(tags: string[]): string {
  return tags
    .map(
      (t) =>
        `app-tail bootstrap-policy \\\n  --client-id YOUR_CLIENT_ID \\\n  --client-secret-file ./policy-secret.txt \\\n  --tag ${t}`,
    )
    .join('\n\n')
}

/** TagList renders the configured tags inline, comma separated. */
function TagList({ tags, bare }: { tags: string[]; bare?: boolean }) {
  return (
    <>
      {tags.map((t, i) => (
        <span key={t}>
          {i > 0 ? ', ' : ''}
          <span className="mono">{bare ? bareName(t) : t}</span>
        </span>
      ))}
    </>
  )
}

/** PlanSummary shows what a preview or apply reported. */
function PlanSummary({ plan, applied }: { plan: PolicyPlanView; applied: boolean }) {
  return (
    <Notice tone={applied || plan.changed ? 'warn' : 'info'}>
      <div className="notice-stack">
        <strong>
          {applied
            ? plan.changed
              ? `Applied: ${plan.summary}.`
              : 'The policy already allowed this fleet; nothing changed.'
            : plan.changed
              ? `Will ${plan.summary}.`
              : 'The policy already allows this fleet; nothing to do.'}
        </strong>
        {plan.notes?.map((note) => (
          <span key={note} className="hint">
            {note}
          </span>
        ))}
      </div>
    </Notice>
  )
}

export function TagSetupDialog({ onClose }: { onClose: () => void }) {
  const [settings, setSettings] = useState<Settings | undefined>(undefined)
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [preview, setPreview] = useState<PolicyPlanView | undefined>(undefined)
  const [applied, setApplied] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)

  // Escape closes, matching every other dialog.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  useEffect(() => {
    const ctrl = new AbortController()
    api
      .settings()
      .then((s) => {
        if (!ctrl.signal.aborted) setSettings(s)
      })
      .catch(() => {
        if (!ctrl.signal.aborted) setSettings(undefined)
      })
    return () => ctrl.abort()
  }, [])

  const tags = useMemo(() => {
    const configured = settings?.tags ?? []
    return configured.length > 0 ? configured : [DEFAULT_TAG]
  }, [settings])

  // A self-hosted control server manages its own ACLs; the copy-paste snippet is the
  // only path we can offer there.
  const controlURL = settings?.controlURL?.trim() ?? ''
  const customControl = controlURL !== '' && controlURL !== TAILSCALE_CONTROL_URL

  const snippet = useMemo(() => buildSnippet(tags), [tags])
  const cli = useMemo(() => buildCli(tags), [tags])
  const plural = tags.length > 1

  const runPolicy = async (apply: boolean) => {
    if (clientId.trim() === '' || clientSecret.trim() === '') {
      setError('Enter both the OAuth client id and secret.')
      return
    }
    setBusy(true)
    setError(undefined)
    try {
      const req: PolicyBootstrapRequest = { clientId: clientId.trim(), clientSecret, tags }
      const view = apply ? await api.policyApply(req) : await api.policyPreview(req)
      setPreview(view)
      setApplied(apply)
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
      // A failed apply invalidates the shown preview; force a fresh one before retry.
      if (apply) setPreview(undefined)
    } finally {
      setBusy(false)
    }
  }

  // Re-previewing after an apply, or editing the credentials, should retract the
  // stale summary so the Apply button reflects the current inputs.
  const onCredentialChange = () => {
    if (preview) setPreview(undefined)
    setApplied(false)
  }

  return (
    <Scrim onClose={onClose}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label="Tag setup"
      >
        <div className="overlay-head">
          <h2>Tag setup</h2>
          <span className="spacer" />
          <button className="btn ghost small square" onClick={onClose} aria-label="Close">
            <CloseIcon />
          </button>
        </div>

        <div className="overlay-body">
          <p className="hint">
            app-tail devices share the tag{plural ? 's' : ''} <TagList tags={tags} />. Your tailnet
            has to define {plural ? 'them' : 'it'} before a device can use{' '}
            {plural ? 'them' : 'it'} — signing in with tags fails until then.
          </p>

          {customControl ? (
            <Notice>
              A custom control server is configured, so the admin console steps and the one-click
              apply don&apos;t apply here. Add the snippet below to your control server&apos;s
              policy.
            </Notice>
          ) : (
            <div className="field">
              <span className="field-caption">Create the tag</span>
              <ol className="howto">
                <li>
                  Open{' '}
                  <a href={ACCESS_CONTROLS_URL} target="_blank" rel="noreferrer">
                    Access controls
                  </a>{' '}
                  in the Tailscale admin console.
                </li>
                <li>
                  Make sure the <strong>Visual editor</strong> is selected, not the JSON editor.
                </li>
                <li>
                  In the left menu, under <strong>Definitions</strong>, click <strong>Tags</strong>.
                </li>
                <li>
                  Click <strong>Create tag</strong>.
                </li>
                <li>
                  Set the tag name to <TagList tags={tags} bare /> and the owner to{' '}
                  <span className="mono">autogroup:admin</span>, then click <strong>Save</strong>.
                </li>
                <li>Come back here and sign in.</li>
              </ol>
              <span className="hint">
                A tagged device is owned by the tag rather than by you, and its key stops expiring.
              </span>
            </div>
          )}

          <details className="advanced">
            <summary>Edit the policy file instead</summary>
            <div className="advanced-body">
              <div className="field">
                <span className="field-caption">Paste into your policy file</span>
                <span className="hint">
                  The same tag owner in the JSON editor, plus a grant letting tagged devices reach
                  one another. It leaves the rest of the policy untouched.
                </span>
                <CodeBlock text={snippet} />
              </div>

              {customControl ? null : (
                <>
                  <div className="field">
                    <span className="field-caption">Run the CLI</span>
                    <span className="hint">
                      For headless installs. The secret is read from a file, never passed on the
                      command line.
                    </span>
                    <CodeBlock text={cli} />
                  </div>

                  <div className="field">
                    <span className="field-caption">Apply it from here</span>
                    <span className="hint">
                      Needs an OAuth client with the <span className="mono">policy_file</span> scope
                      (Settings → Keys in the admin console; both parts start with{' '}
                      <span className="mono">tskey-client-</span>). It is used once and never
                      stored.
                    </span>
                  </div>

                  <div className="form-grid">
                    <div className="field">
                      <label htmlFor="pol-client-id">OAuth client id</label>
                      <input
                        id="pol-client-id"
                        type="text"
                        value={clientId}
                        autoComplete="off"
                        onChange={(e) => {
                          setClientId(e.target.value)
                          onCredentialChange()
                        }}
                      />
                    </div>
                    <div className="field">
                      <label htmlFor="pol-client-secret">OAuth client secret</label>
                      <input
                        id="pol-client-secret"
                        type="password"
                        value={clientSecret}
                        autoComplete="off"
                        onChange={(e) => {
                          setClientSecret(e.target.value)
                          onCredentialChange()
                        }}
                      />
                    </div>
                  </div>

                  {error ? <Notice tone="error">{error}</Notice> : null}
                  {preview ? <PlanSummary plan={preview} applied={applied} /> : null}

                  <div className="advanced-actions">
                    <button className="btn" disabled={busy} onClick={() => void runPolicy(false)}>
                      {busy && !applied ? 'Checking…' : 'Preview'}
                    </button>
                    <button
                      className="btn primary"
                      disabled={busy || !preview || applied || !preview.changed}
                      onClick={() => void runPolicy(true)}
                    >
                      {busy ? 'Applying…' : 'Apply'}
                    </button>
                  </div>
                </>
              )}
            </div>
          </details>
        </div>

        <div className="overlay-foot">
          <span className="spacer" />
          <button className="btn primary" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </Scrim>
  )
}
