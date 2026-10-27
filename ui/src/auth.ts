// SPDX-License-Identifier: MIT

// The dashboard's session with the agent.
//
// The agent answers nothing under /api/ without a session token. The menu bar and
// `app-tail dashboard` open the page with a one-time launch token in the query string;
// startSession trades it for a session, which is kept in this browser and sent with every
// request. Whether the page holds a session the agent accepts is shared state the whole
// app renders from, so it lives here rather than in any one component.

import { useSyncExternalStore } from 'react'

const SESSION_KEY = 'app-tail.session'
const SESSION_PATH = '/api/auth/session'

/** Access is whether this page can talk to the agent at all. */
export type Access =
  | { readonly state: 'open' }
  /** The agent refused the page's session, or the launch token it arrived with. */
  | { readonly state: 'signed-out'; readonly reason: string }
  /** The browser refused to keep the session, so signing in again could not help. */
  | { readonly state: 'no-storage'; readonly reason: string }

const OPEN: Access = { state: 'open' }

let access: Access = OPEN
const listeners = new Set<() => void>()

function settleAccess(next: Access) {
  access = next
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

/** currentAccess is the state as it stands, for code outside React. */
export function currentAccess(): Access {
  return access
}

/** useAccess re-renders when the page is signed out or signed back in. */
export function useAccess(): Access {
  return useSyncExternalStore(subscribe, currentAccess)
}

/**
 * markSignedOut records that the agent refused this page. The first reason is kept: once
 * one request is refused every poll after it is too, and none of them says more. A
 * browser that will not keep the session stays on that screen, because the refusal is
 * only its symptom.
 */
export function markSignedOut(reason: string): void {
  if (access.state !== 'open') return
  settleAccess({ state: 'signed-out', reason })
}

function storageFailed(cause: unknown) {
  settleAccess({
    state: 'no-storage',
    reason: cause instanceof Error ? cause.message : String(cause),
  })
}

/**
 * sessionToken is the session request() sends, or undefined when the browser holds none.
 * Storage that cannot be read moves the whole app onto the screen explaining it, rather
 * than letting every request go out bare and be refused for a reason nobody is shown.
 */
export function sessionToken(): string | undefined {
  try {
    return window.localStorage.getItem(SESSION_KEY) ?? undefined
  } catch (cause) {
    storageFailed(cause)
    return undefined
  }
}

/** storeSession keeps a session the agent issued and opens the page with it. A browser
 *  that refuses to keep it lands on the screen explaining that instead. */
export function storeSession(token: string): void {
  try {
    window.localStorage.setItem(SESSION_KEY, token)
  } catch (cause) {
    storageFailed(cause)
    return
  }
  settleAccess(OPEN)
}

/**
 * startSession trades the launch token in the address for a session, before the first
 * render. Run from the entry point rather than an effect: a token is good for one trade,
 * and React's development mode runs effects twice.
 *
 * The token leaves the address before the trade is attempted, so a reload or a second
 * call never offers it again and a refused token is not left in the history. Every other
 * parameter stays, because the router reads the menu bar's settings and section from the
 * same query string. A failed trade signs the page out with the reason; this never
 * rejects for one.
 */
export async function startSession(): Promise<void> {
  const url = new URL(window.location.href)
  const launch = url.searchParams.get('launch')
  if (launch === null) return
  url.searchParams.delete('launch')
  window.history.replaceState(window.history.state, '', `${url.pathname}${url.search}${url.hash}`)

  let response: Response
  try {
    response = await fetch(SESSION_PATH, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ launch }),
    })
  } catch (cause) {
    markSignedOut(`cannot reach the app-tail agent (${String(cause)})`)
    return
  }

  const text = await response.text()
  let body: { session?: unknown; error?: unknown } | undefined
  try {
    body = text.length > 0 ? (JSON.parse(text) as typeof body) : undefined
  } catch {
    markSignedOut(`the agent answered the sign-in with something other than JSON (${response.status})`)
    return
  }

  if (!response.ok) {
    const said = typeof body?.error === 'string' ? body.error : `status ${response.status}`
    markSignedOut(`the link this page was opened with could not be used: ${said}`)
    return
  }
  if (typeof body?.session !== 'string' || body.session === '') {
    markSignedOut('the agent accepted the sign-in but sent no session')
    return
  }
  storeSession(body.session)
}
