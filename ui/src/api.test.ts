// SPDX-License-Identifier: MIT

import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError, api } from './api'

type FetchCall = (input: string, init?: RequestInit) => Response | Promise<Response>

/** stubFetch replaces the one external boundary these tests have. Everything below
 *  it -- status mapping, envelope unwrapping, conflict plumbing -- is the code under
 *  test and is never substituted. */
function stubFetch(respond: () => Response | Promise<Response> | never) {
  const spy = vi.fn<FetchCall>(respond)
  vi.stubGlobal('fetch', spy)
  return spy
}

/** headersOf reads the headers the client sent on the nth call, failing the test
 *  rather than returning a default if that call never happened. */
function headersOf(spy: ReturnType<typeof stubFetch>, call: number): Record<string, string> {
  const args = spy.mock.calls[call]
  if (args === undefined) {
    throw new Error(`fetch was never called a ${call + 1}. time`)
  }
  return (args[1]?.headers ?? {}) as Record<string, string>
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('api request handling', () => {
  it('returns the decoded body on success', async () => {
    stubFetch(() => jsonResponse(200, { backendState: 'Running', running: true }))

    await expect(api.status()).resolves.toMatchObject({ backendState: 'Running' })
  })

  // A dead agent is the most common failure and looks nothing like a rejected
  // request. Status 0 is what lets the dashboard say "agent not running" instead of
  // showing a bare network error.
  it('turns an unreachable agent into status 0', async () => {
    stubFetch(() => {
      throw new TypeError('Failed to fetch')
    })

    const err = await api.status().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).status).toBe(0)
    expect((err as ApiError).message).toContain('cannot reach the app-tail agent')
  })

  // Delete answers 204. Whichever path gets there, an empty body must resolve --
  // parsing it as JSON would turn a successful delete into an error the user sees.
  it('treats 204 as success with no body', async () => {
    stubFetch(() => new Response(null, { status: 204 }))

    await expect(api.deleteForward('fwd-1')).resolves.toBeUndefined()
  })

  it("surfaces the agent's own error message, not a generic one", async () => {
    stubFetch(() => jsonResponse(400, { error: 'listenPort 70000 is out of range' }))

    const err = (await api.status().catch((e: unknown) => e)) as ApiError
    expect(err.status).toBe(400)
    expect(err.isValidation).toBe(true)
    expect(err.message).toBe('listenPort 70000 is out of range')
  })

  // The conflict envelope is what drives the "port already in use" recovery UI, so
  // it has to survive the error path rather than being flattened to a string.
  it('carries a conflict envelope through to the caller', async () => {
    stubFetch(() =>
      jsonResponse(409, {
        error: 'port 2222 is already in use',
        conflict: { kind: 'port', suggestedPort: 2223 },
      }),
    )

    const err = (await api.status().catch((e: unknown) => e)) as ApiError
    expect(err.isConflict).toBe(true)
    expect(err.conflict).toEqual({ kind: 'port', suggestedPort: 2223 })
  })

  // A proxy or captive portal answering with HTML must not read as a parse bug in
  // the dashboard; the raw text is the only clue the user has.
  it('reports a non-JSON error body verbatim', async () => {
    stubFetch(() => new Response('<html>502 Bad Gateway</html>', { status: 502 }))

    const err = (await api.status().catch((e: unknown) => e)) as ApiError
    expect(err.status).toBe(502)
    expect(err.message).toContain('502 Bad Gateway')
  })

  it('reports a non-JSON success body as an error rather than returning garbage', async () => {
    stubFetch(() => new Response('not json', { status: 200 }))

    const err = (await api.status().catch((e: unknown) => e)) as ApiError
    expect(err.message).toContain('non-JSON response')
  })

  // Sending a body without the header makes the agent reject it as a bad request.
  it('sets a JSON content type only when there is a body', async () => {
    const spy = stubFetch(() => jsonResponse(200, {}))

    await api.restart()
    expect(headersOf(spy, 0)['Content-Type']).toBeUndefined()

    await api.createForward({ name: 'ssh', listenPort: 2222 })
    expect(headersOf(spy, 1)['Content-Type']).toBe('application/json')
  })

  // The rejected key is what lets a settings form put the complaint on the control that
  // caused it. Losing it demotes every refusal to a banner above a section the reader
  // may have folded shut.
  it('carries the field the agent names with a refusal', async () => {
    stubFetch(() => jsonResponse(400, { error: 'hostname: too long', field: 'hostname' }))

    const err = (await api.updateSettings({ hostname: 'x' }).catch((e: unknown) => e)) as ApiError
    expect(err.field).toBe('hostname')
    expect(err.message).toBe('hostname: too long')
  })

  it('leaves the field unset when the agent names none', async () => {
    stubFetch(() => jsonResponse(400, { error: 'the document is not valid' }))

    const err = (await api.updateSettings({ hostname: 'x' }).catch((e: unknown) => e)) as ApiError
    expect(err.field).toBeUndefined()
  })

  // A refusal of the caller rather than of the input is neither a validation error nor a
  // conflict: treating it as one would put "fix the field" or "pick another port" UI on
  // a request nobody may make from here. The agent's own words still reach the reader.
  it.each([401, 403])('keeps a %d as a plain refusal carrying the agent\'s words', async (status) => {
    stubFetch(() => jsonResponse(status, { error: 'this address may not change settings' }))

    const err = (await api.updateSettings({ hostname: 'x' }).catch((e: unknown) => e)) as ApiError
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(status)
    expect(err.isValidation).toBe(false)
    expect(err.isConflict).toBe(false)
    expect(err.message).toBe('this address may not change settings')
  })

  // A 500 with no envelope still has to say something. Without the fallback the
  // dashboard renders an empty error notice and the user has nothing to report.
  it('names the status when the agent sends no message with its failure', async () => {
    stubFetch(() => jsonResponse(500, {}))

    const err = (await api.status().catch((e: unknown) => e)) as ApiError
    expect(err.message).toBe('request failed with status 500')
  })

  // An HTML error page can run to megabytes. Pasting one into a Notice would push
  // every control in the dashboard off the screen.
  it('truncates an enormous non-JSON error body', async () => {
    stubFetch(() => new Response('x'.repeat(5000), { status: 502 }))

    const err = (await api.status().catch((e: unknown) => e)) as ApiError
    expect(err.message).toHaveLength(300)
  })
})

// The verb and path are the contract with the agent's router. A wrong verb reaches
// it as a 405 and a wrong path as a 404 -- both long after the dashboard reported
// the action as done, because these are fire-and-forget from the UI's point of view.
describe('every endpoint the dashboard calls', () => {
  // One body satisfying every unwrap, so the table only has to say verb and path.
  const anyBody = {
    peers: [],
    forwards: [],
    presets: [],
    port: 41000,
    enabled: true,
    backendState: 'Running',
    authURL: 'https://login.tailscale.com/a/abc',
  }

  it.each([
    ['status', () => api.status(), 'GET', '/api/status'],
    ['login', () => api.login(), 'POST', '/api/login'],
    ['logout', () => api.logout(), 'POST', '/api/logout'],
    ['restart', () => api.restart(), 'POST', '/api/restart'],
    ['peers', () => api.peers(), 'GET', '/api/peers'],
    ['forwards', () => api.forwards(), 'GET', '/api/forwards'],
    ['createForward', () => api.createForward({ name: 'ssh' }), 'POST', '/api/forwards'],
    ['updateForward', () => api.updateForward('f1', { name: 'ssh' }), 'PUT', '/api/forwards/f1'],
    ['deleteForward', () => api.deleteForward('f1'), 'DELETE', '/api/forwards/f1'],
    ['toggleForward', () => api.toggleForward('f1', true), 'POST', '/api/forwards/f1/toggle'],
    [
      'suggestPort',
      () => api.suggestPort('tcp', 'gpu-box:22'),
      'GET',
      '/api/forwards/suggest-port?protocol=tcp&target=gpu-box%3A22',
    ],
    ['presets', () => api.presets(), 'GET', '/api/presets'],
    [
      'createPreset',
      () => api.createPreset({ name: 'SSH', protocol: 'tcp', remotePort: 22 }),
      'POST',
      '/api/presets',
    ],
    ['deletePreset', () => api.deletePreset('p1'), 'DELETE', '/api/presets/p1'],
    ['settings', () => api.settings(), 'GET', '/api/settings'],
    ['updateSettings', () => api.updateSettings({ hostname: 'box' }), 'PUT', '/api/settings'],
    ['autostart', () => api.autostart(), 'GET', '/api/autostart'],
    ['setAutostart', () => api.setAutostart(true), 'POST', '/api/autostart'],
    [
      'policyPreview',
      () => api.policyPreview({ clientId: 'id', clientSecret: 'secret' }),
      'POST',
      '/api/policy/preview',
    ],
    [
      'policyApply',
      () => api.policyApply({ clientId: 'id', clientSecret: 'secret' }),
      'POST',
      '/api/policy/apply',
    ],
  ])('%s issues %s %s', async (_name, invoke, method, path) => {
    const spy = stubFetch(() => jsonResponse(200, anyBody))

    await invoke()

    const call = spy.mock.calls[0]
    if (call === undefined) throw new Error('the client never called fetch')
    expect(call[0]).toBe(path)
    expect(call[1]?.method ?? 'GET').toBe(method)
  })

  // These four hand back the value inside the envelope, not the envelope. Returning
  // the wrapper renders an empty table with no error anywhere: the dashboard would
  // hold an object where it expects an array.
  it.each([
    ['peers', () => api.peers(), { peers: [{ id: 'peer-1' }] }, [{ id: 'peer-1' }]],
    ['forwards', () => api.forwards(), { forwards: [{ id: 'f1' }] }, [{ id: 'f1' }]],
    ['presets', () => api.presets(), { presets: [{ id: 'p1' }] }, [{ id: 'p1' }]],
    ['suggestPort', () => api.suggestPort('tcp', 'h:1'), { port: 41000 }, 41000],
  ])('%s unwraps its envelope', async (_name, invoke, body, want) => {
    stubFetch(() => jsonResponse(200, body))

    await expect(invoke()).resolves.toEqual(want)
  })

  // An id is agent-minted but travels through a URL path. A slash or a space in one
  // silently retargets the request at a different route, so a delete would either
  // 404 or, worse, address something else entirely.
  it.each([
    ['deleteForward', (id: string) => api.deleteForward(id), '/api/forwards/'],
    ['deletePreset', (id: string) => api.deletePreset(id), '/api/presets/'],
  ])('%s escapes the id it puts in the path', async (_name, invoke, prefix) => {
    const spy = stubFetch(() => new Response(null, { status: 204 }))

    await invoke('a/b c')

    expect(spy.mock.calls[0]?.[0]).toBe(`${prefix}a%2Fb%20c`)
  })

  // The bind address narrows which port is actually free; dropping it from the query
  // makes the agent suggest a port that is taken on the interface being bound.
  it('carries the bind address in the suggest-port query only when there is one', async () => {
    const spy = stubFetch(() => jsonResponse(200, { port: 41000 }))

    await api.suggestPort('udp', 'gpu-box:53', '192.168.1.50')
    expect(spy.mock.calls[0]?.[0]).toBe(
      '/api/forwards/suggest-port?protocol=udp&target=gpu-box%3A53&bindAddr=192.168.1.50',
    )

    await api.suggestPort('udp', 'gpu-box:53')
    expect(spy.mock.calls[1]?.[0]).not.toContain('bindAddr')
  })

  it.each([
    ['createForward', () => api.createForward({ name: 'ssh', listenPort: 2222 }), { name: 'ssh', listenPort: 2222 }],
    ['toggleForward', () => api.toggleForward('f1', false), { enabled: false }],
    ['setAutostart', () => api.setAutostart(true), { enabled: true }],
    ['updateSettings', () => api.updateSettings({ tags: ['tag:app-tail'] }), { tags: ['tag:app-tail'] }],
  ])('%s sends its arguments as the request body', async (_name, invoke, want) => {
    const spy = stubFetch(() => jsonResponse(200, { enabled: true }))

    await invoke()

    const body = spy.mock.calls[0]?.[1]?.body
    if (typeof body !== 'string') throw new Error('the request carried no JSON body')
    expect(JSON.parse(body)).toEqual(want)
  })
})

// The probe a page waits on while the agent restarts. /healthz answers 503 whenever the
// tailnet node is down, which is the ordinary state of a machine that is not signed in,
// so only fetch itself failing may read as "nothing is listening yet".
describe('asking whether the agent is answering at all', () => {
  it.each([200, 503])('reads a %d as answering', async (status) => {
    const spy = stubFetch(() => new Response('', { status }))

    await expect(api.reachable()).resolves.toBe(true)
    expect(spy.mock.calls[0]?.[0]).toBe('/healthz')
  })

  it('reads a refused connection as not answering', async () => {
    stubFetch(() => {
      throw new TypeError('Failed to fetch')
    })

    await expect(api.reachable()).resolves.toBe(false)
  })
})

// The filter is the whole query string the agent parses. A word it does not know is
// refused there rather than ignored, so every field has to land under the name the agent
// reads, and a page's cursor has to travel with the filter that produced it.
describe('asking for a page of the log', () => {
  function pathOf(spy: ReturnType<typeof stubFetch>): string {
    const path = spy.mock.calls[0]?.[0]
    if (path === undefined) throw new Error('the client never called fetch')
    return path
  }

  it('asks for the whole log with no query at all', async () => {
    const spy = stubFetch(() => jsonResponse(200, { events: [] }))

    await api.telemetryEvents()

    expect(pathOf(spy)).toBe('/api/telemetry/events')
  })

  it('repeats a multi-valued filter once per value under the name the agent reads', async () => {
    const spy = stubFetch(() => jsonResponse(200, { events: [] }))

    await api.telemetryEvents({
      categories: ['dns', 'proxy'],
      severities: ['warn'],
      codes: ['dns.blocked'],
      text: 'nas box',
      limit: 50,
    })

    const query = new URL(pathOf(spy), 'http://agent').searchParams
    expect(query.getAll('category')).toEqual(['dns', 'proxy'])
    expect(query.getAll('severity')).toEqual(['warn'])
    expect(query.getAll('code')).toEqual(['dns.blocked'])
    expect(query.get('q')).toBe('nas box')
    expect(query.get('limit')).toBe('50')
    expect(query.has('cursor')).toBe(false)
  })

  it('carries the cursor of the next page beside the filter that produced it', async () => {
    const spy = stubFetch(() => jsonResponse(200, { events: [] }))

    await api.telemetryEvents({ categories: ['dns'], cursor: 'ev_1200' })

    const query = new URL(pathOf(spy), 'http://agent').searchParams
    expect(query.get('cursor')).toBe('ev_1200')
    expect(query.getAll('category')).toEqual(['dns'])
  })

  // An empty cursor is the first page and an empty search is no search; either one sent
  // as a key would be a filter the agent refuses or matches nothing against.
  it('leaves an empty cursor and an empty search out of the query', async () => {
    const spy = stubFetch(() => jsonResponse(200, { events: [] }))

    await api.telemetryEvents({ cursor: '', text: '', limit: 0 })

    const query = new URL(pathOf(spy), 'http://agent').searchParams
    expect(query.has('cursor')).toBe(false)
    expect(query.has('q')).toBe(false)
    expect(query.get('limit')).toBe('0')
  })
})
