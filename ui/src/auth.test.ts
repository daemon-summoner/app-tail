// SPDX-License-Identifier: MIT

import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError, api } from './api'
import { currentAccess, startSession } from './auth'
import { failWith, netFail, stubAgent } from './test/agent'

/** The key the session is kept under. Written out rather than imported: a page from an
 *  older build reads the same key, so renaming it signs every open dashboard out. */
const SESSION_KEY = 'app-tail.session'

/** arrive puts the document where the menu bar's link lands: the launch token beside
 *  whatever else the link asked for. */
function arrive(address: string) {
  window.history.replaceState(null, '', address)
}

/** freshBrowser is a browser that has never held a session, which is what the first
 *  launch from the menu bar meets. */
function freshBrowser() {
  window.localStorage.removeItem(SESSION_KEY)
}

/** storagePrototype is where the browser's storage methods live. Spying there rather than
 *  on the object: a property set on a Storage object is stored as an item. */
function storagePrototype(): Storage {
  return Object.getPrototypeOf(window.localStorage) as Storage
}

afterEach(() => {
  window.history.replaceState(null, '', '/')
})

describe('opening the dashboard from the menu bar', () => {
  it('trades the launch token for a session and keeps it', async () => {
    const agent = stubAgent({}, { session: 'session-from-agent' })
    freshBrowser()
    arrive('/?launch=one-time-token')

    await startSession()

    expect(agent.bodyOf('POST /api/auth/session')).toEqual({ launch: 'one-time-token' })
    expect(window.localStorage.getItem(SESSION_KEY)).toBe('session-from-agent')
    expect(currentAccess()).toEqual({ state: 'open' })
  })

  // The router reads settings and section to pick the first page, so the link from
  // "Settings…" in the menu has to still say so once the token is gone.
  it('takes the launch token out of the address and leaves everything else', async () => {
    stubAgent()
    arrive('/?launch=one-time-token&settings=1&section=dns#/connections')

    await startSession()

    expect(window.location.search).toBe('?settings=1&section=dns')
    expect(window.location.hash).toBe('#/connections')
  })

  it('leaves an address with no launch token alone and asks the agent nothing', async () => {
    const agent = stubAgent()
    arrive('/?section=dns')

    await startSession()

    expect(agent.countOf('POST /api/auth/session')).toBe(0)
    expect(window.location.search).toBe('?section=dns')
  })

  // React's development mode runs effects twice, and a second trade of a single-use token
  // would be refused and sign the page straight back out.
  it('trades the token once however many times it is started', async () => {
    const agent = stubAgent()
    arrive('/?launch=one-time-token')

    await Promise.all([startSession(), startSession()])

    expect(agent.countOf('POST /api/auth/session')).toBe(1)
  })

  it('sends the session it was given with the next request', async () => {
    const agent = stubAgent({}, { session: 'session-from-agent' })
    freshBrowser()
    arrive('/?launch=one-time-token')

    await startSession()
    await api.status()

    expect(agent.calls.at(-1)?.headers.Authorization).toBe('Bearer session-from-agent')
  })
})

describe('when the launch token is refused', () => {
  it('keeps no session and says the page is signed out, with the agent\'s reason', async () => {
    stubAgent({
      'POST /api/auth/session': failWith(401, 'this launch token has expired'),
    })
    freshBrowser()
    arrive('/?launch=stale-token&settings=1')

    await startSession()

    expect(window.localStorage.getItem(SESSION_KEY)).toBeNull()
    const access = currentAccess()
    expect(access.state).toBe('signed-out')
    expect(access.state === 'open' ? '' : access.reason).toContain('this launch token has expired')
    // A token that was refused once is refused on every reload too.
    expect(window.location.search).toBe('?settings=1')
  })

  it('says the page is signed out when the agent cannot be reached', async () => {
    stubAgent({ 'POST /api/auth/session': netFail() })
    freshBrowser()
    arrive('/?launch=one-time-token')

    await startSession()

    const access = currentAccess()
    expect(access.state).toBe('signed-out')
    expect(access.state === 'open' ? '' : access.reason).toContain('cannot reach the app-tail agent')
  })

  it('says the page is signed out when the agent answers without a session', async () => {
    stubAgent({ 'POST /api/auth/session': {} })
    freshBrowser()
    arrive('/?launch=one-time-token')

    await startSession()

    expect(window.localStorage.getItem(SESSION_KEY)).toBeNull()
    expect(currentAccess().state).toBe('signed-out')
  })
})

describe('when the agent stops accepting the session', () => {
  // `app-tail auth rotate`, or a session older than its thirty days.
  it('signs the page out and still fails the request with the agent\'s words', async () => {
    stubAgent({}, { unauthorized: true })

    const failure = await api.status().catch((cause: unknown) => cause)

    expect(failure).toBeInstanceOf(ApiError)
    expect((failure as ApiError).status).toBe(401)
    expect((failure as ApiError).message).toContain('app-tail dashboard')
    expect(currentAccess().state).toBe('signed-out')
  })

  it('sends no Authorization header when the browser holds no session', async () => {
    const agent = stubAgent()
    freshBrowser()

    await api.status().catch(() => undefined)

    expect(agent.calls.at(-1)?.headers.Authorization).toBeUndefined()
    expect(currentAccess().state).toBe('signed-out')
  })
})

describe('when the browser will not keep the session', () => {
  // Private windows and strict privacy settings refuse site storage. Carrying on without
  // the session would sign the page out on every reload with no hint of why.
  it('says storage is the problem when the session cannot be written', async () => {
    stubAgent()
    freshBrowser()
    vi.spyOn(storagePrototype(), 'setItem').mockImplementation(() => {
      throw new DOMException('the storage is blocked', 'SecurityError')
    })
    arrive('/?launch=one-time-token')

    await startSession()

    const access = currentAccess()
    expect(access.state).toBe('no-storage')
    expect(access.state === 'open' ? '' : access.reason).toContain('the storage is blocked')
  })

  it('says storage is the problem when the session cannot be read, even after a 401', async () => {
    stubAgent()
    vi.spyOn(storagePrototype(), 'getItem').mockImplementation(() => {
      throw new DOMException('the storage is blocked', 'SecurityError')
    })

    await api.status().catch(() => undefined)

    // The request went out bare and was refused, but the refusal is the symptom: telling
    // the user to reopen the dashboard would send them round the same loop.
    expect(currentAccess().state).toBe('no-storage')
  })
})
