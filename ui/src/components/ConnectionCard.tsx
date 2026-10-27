// SPDX-License-Identifier: MIT

import { useEffect, useState } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { api, ApiError, type Status } from '../api'
import { Panel } from './Panel'
import { Notice } from './primitives'

/** stateTone maps a backend state to the visual weight it deserves. */
function stateTone(status: Status): string {
  if (status.running) return 'running'
  if (status.backendState === 'Starting') return 'pending'
  return 'error'
}

function stateLabel(status: Status): string {
  switch (status.backendState) {
    case 'Running':
      return 'Connected'
    case 'Starting':
      return 'Connecting'
    case 'NeedsLogin':
      return 'Not signed in'
    case 'NeedsMachineAuth':
      return 'Waiting for device approval'
    case 'Stopped':
      return 'Stopped'
    default:
      return status.backendState || 'Unknown'
  }
}

export function ConnectionCard({
  status,
  onChanged,
  onSetupTags,
}: {
  status: Status
  onChanged: () => void
  onSetupTags: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)
  const [authUrl, setAuthUrl] = useState<string | undefined>(undefined)

  // The status says only that a login is waiting. The URL that completes it enrolls this
  // machine on a tailnet, so it is asked for by a request of its own rather than carried
  // on a read anything that reaches the agent may make.
  useEffect(() => {
    if (!status.authPending) return
    // Cleared by the cleanup below, so a reply that arrives after the card is gone or
    // after the login finished does not write into a card nobody is looking at.
    const asking = { current: true }
    void api.loginUrl().then(
      (pending) => {
        if (asking.current) setAuthUrl(pending.authURL)
      },
      (cause) => {
        if (asking.current) setError(cause instanceof ApiError ? cause.message : String(cause))
      },
    )
    return () => {
      asking.current = false
    }
  }, [status.authPending])

  // run performs one action, reporting a failure on the card instead of letting it pass
  // unseen, and hands back what it produced -- undefined when it did not get through.
  const run = async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true)
    setError(undefined)
    try {
      const done = await fn()
      onChanged()
      return done
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause))
      return undefined
    } finally {
      setBusy(false)
    }
  }

  // Signing in mints a fresh URL, and the one on screen is the one the user is about to
  // scan: it comes from this reply rather than from the next poll.
  const signIn = async () => {
    const started = await run(api.login)
    if (started) setAuthUrl(started.authURL)
  }

  // Signing out ends the login the code on screen belongs to, so the code goes with it: the
  // node comes back to the state that shows one, and a link that outlived its login sends
  // whoever scans it to a dead page. A sign-out that failed changed nothing, and the code
  // it did not end stays.
  const signOut = async () => {
    if (await run(api.logout)) setAuthUrl(undefined)
  }

  const showLogin = !status.running && status.backendState !== 'Starting'
  const ips = status.tailscaleIps ?? []

  return (
    <Panel
      title="Tailnet connection"
      bare
      primary
      status={{ tone: stateTone(status), label: stateLabel(status) }}
      info={
        <p>
          How this device is enrolled on your tailnet: the name and addresses it answers
          to, the account or tags that own it, and how it authenticated.
        </p>
      }
      actions={
        <>
          {/* The name, the credentials and everything else this device enrolled with are
              the connection's own settings, and they live on its page. This card says
              what the connection is doing; that page says what it is set to. */}
          <a className="btn small" href={`#/connections/tailscale/${status.tunnelId}`}>
            Settings
          </a>
          <button className="btn small" onClick={onSetupTags}>
            Tag setup
          </button>

          {status.running ? (
            <button className="btn" disabled={busy} onClick={() => void signOut()}>
              Sign out
            </button>
          ) : (
            <button className="btn primary" disabled={busy} onClick={() => void signIn()}>
              {authUrl ? 'New sign-in link' : 'Sign in to tailnet'}
            </button>
          )}
        </>
      }
    >
      <div className="connection">
        <div className="identity">
          <span className="detail">
            {status.dnsName ? <span className="mono">{status.dnsName}</span> : null}
            {ips.length > 0 ? <span className="mono">{ips.join('  ')}</span> : null}
            {status.loginName ? <span>{status.loginName}</span> : null}
            {status.tags && status.tags.length > 0 ? (
              <span className="mono">{status.tags.join(' ')}</span>
            ) : null}
            <span>auth: {status.authMode}</span>
          </span>
        </div>
      </div>

      {status.problem && !status.running ? (
        <div className="connection-notice">
          <Notice tone="warn">{status.problem}</Notice>
        </div>
      ) : null}

      {error ? (
        <div className="connection-notice">
          <Notice tone="error">{error}</Notice>
        </div>
      ) : null}

      {showLogin && authUrl ? (
        <div className="login">
          <div className="qr">
            {/* Encoded client-side so the login URL never leaves this machine to
                reach a QR service. */}
            <QRCodeSVG value={authUrl} size={132} level="M" />
          </div>
          <div className="instructions">
            <p>
              Scan the code with your phone, or open the link below, to approve this device on
              your tailnet.
            </p>
            <a className="auth-url" href={authUrl} target="_blank" rel="noreferrer">
              {authUrl}
            </a>
          </div>
        </div>
      ) : null}
    </Panel>
  )
}
