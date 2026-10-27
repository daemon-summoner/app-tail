// SPDX-License-Identifier: MIT

// Restarting the whole agent, from the dashboard the agent is serving.
//
// The page it is pressed on goes away with the process and comes back with it, so the
// button holds a waiting state and lets the polls reconnect rather than reporting a
// result it cannot observe: the request that starts a restart is answered before the
// restart happens, and nothing after that point is on the old process to answer.

import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../api'
import { ConfirmDialog } from './ConfirmDialog'

/** How often to ask whether the new process is serving yet. Short, because this is the
 *  one moment the user is watching the page do nothing. */
const PROBE_INTERVAL_MS = 700

/** Reloads the page once a restarted agent is serving again, from the moment `restarting`
 *  turns true. Nothing here reaches the old process: it is gone by the time the first probe
 *  lands. The reload is what gets the page off a build that may no longer match the binary. */
export function useReloadWhenBack(restarting: boolean) {
  // Set once the agent has answered again, so the interval can be torn down from inside
  // its own callback without the effect re-running on every tick.
  const done = useRef(false)

  useEffect(() => {
    if (!restarting) return undefined
    done.current = false

    const timer = window.setInterval(() => {
      void api.reachable().then((up) => {
        // Any answer at all means the replacement is serving: /healthz reports 503
        // whenever the tailnet node is down, and a node that is down is the ordinary
        // state of a machine nobody has signed in yet.
        if (!up || done.current) return
        done.current = true
        window.location.reload()
      })
    }, PROBE_INTERVAL_MS)

    return () => window.clearInterval(timer)
  }, [restarting])
}

export function RestartButton() {
  const [asking, setAsking] = useState(false)
  const [restarting, setRestarting] = useState(false)
  const [error, setError] = useState<string | undefined>(undefined)
  useReloadWhenBack(restarting)

  const restart = useCallback(async () => {
    setError(undefined)
    try {
      await api.restartApp()
      setAsking(false)
      setRestarting(true)
    } catch (cause) {
      // A refusal is the one outcome worth reporting: it means the process is still up
      // and still serving this page, so the dialog stays and says why.
      setError(cause instanceof ApiError ? cause.message : String(cause))
    }
  }, [])

  return (
    <>
      <button className="btn small" disabled={restarting} onClick={() => setAsking(true)}>
        {restarting ? 'Restarting…' : 'Restart app-tail'}
      </button>

      {asking ? (
        <ConfirmDialog
          title="Restart app-tail?"
          confirmLabel="Restart"
          destructive
          onConfirm={() => void restart()}
          onClose={() => setAsking(false)}
        >
          <p>
            Every forward and every proxy connection is closed, and the tailnet node
            disconnects and rejoins. Anything running through app-tail right now is
            interrupted.
          </p>
          <p>This page reconnects on its own once the agent is serving again.</p>
          {error ? <p className="hint bad">{error}</p> : null}
        </ConfirmDialog>
      ) : null}
    </>
  )
}
