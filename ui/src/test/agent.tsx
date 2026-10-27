// SPDX-License-Identifier: MIT

// The shared dashboard test harness. It stubs the agent at the fetch boundary --
// never the api module -- so the real request, envelope and error mapping stay under
// test in every suite that uses it.

import type { BoundFunctions, queries } from '@testing-library/dom'
import { act, fireEvent, render, within } from '@testing-library/react'
import type { ReactElement } from 'react'
import { onTestFinished, vi } from 'vitest'
import type { Mock } from 'vitest'

import {
  featureModules,
  settingsGroups,
  settingsSchema,
  type ApprovalNeed,
  type Approvals,
  type FeatureModuleInfo,
  type Forward,
  type Peer,
  type Preset,
  type ProxyInstanceView,
  type ProxySchemaView,
  type ProxyView,
  type SystemProxyView,
  type AutoMapView,
  type DeferredSetting,
  type DNSBlockView,
  type DNSProfile,
  type DNSSystemView,
  type DNSView,
  type ExitNodeCandidate,
  type ExitNodeView,
  type EgressView,
  type FabricView,
  type InterfaceView,
  type IPSView,
  type LockView,
  type PrefFieldView,
  type PrefsView,
  type RoutesView,
  type RoutingRule,
  type RoutingView,
  type SettingFieldSchema,
  type SettingGroupInfo,
  type Settings,
  type Status,
  type TrafficView,
  type TrafficPoint,
  type TrafficPeer,
  type TrafficBreakdown,
  type TrafficSeries,
  type TelemetryEvent,
  type TelemetryPage,
  type TelemetryView,
  type TunnelSchemaView,
  type TunnelView,
} from '../api'
import { storeSession } from '../auth'
import type { SettingsForm } from '../components/settings/useSettingsDraft'
import { StoreProvider } from '../data/StoreProvider'
import { PollStore } from '../data/store'

// ---------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------

const REPLY = Symbol('app-tail.agent-reply')

/** A fully specified reply. Build one with reply/failWith/rejectField/noContent. */
export interface AgentReply {
  readonly [REPLY]: true
  readonly status: number
  readonly body: string | undefined
}

function isReply(value: unknown): value is AgentReply {
  return typeof value === 'object' && value !== null && REPLY in value
}

/** reply sends body as JSON under an explicit status. */
export function reply(status: number, body?: unknown): AgentReply {
  return {
    [REPLY]: true,
    status,
    body: body === undefined ? undefined : JSON.stringify(body),
  }
}

/** failWith sends the agent's error envelope, the shape ApiError is built from. */
export function failWith(
  status: number,
  message: string,
  conflict?: { endpoint: string; forwardId: string; name?: string },
): AgentReply {
  return reply(status, conflict === undefined ? { error: message } : { error: message, conflict })
}

/** rejectField is the 400 the agent answers when one named setting is refused: the
 *  sentence begins with the key, and the key is also sent on its own so a form can put
 *  the complaint on the control that caused it. */
export function rejectField(field: string, reason: string): AgentReply {
  return reply(400, { error: `${field}: ${reason}`, field })
}

/** noContent is the 204 a successful DELETE answers with. */
export function noContent(): AgentReply {
  return { [REPLY]: true, status: 204, body: undefined }
}

/** netFail is a route for an agent that is not running: fetch itself rejects, which
 *  is a different code path from any HTTP status. */
export function netFail(message = 'Failed to fetch'): () => never {
  return () => {
    throw new TypeError(message)
  }
}

/**
 * A route's answer. A bare value is sent as a 200 JSON body; wrap it in reply(),
 * failWith(), rejectField() or noContent() to control the status. A function is called
 * with the request, so a route can answer from the body it was sent, count its own
 * calls, or return a pending promise to hold the request open.
 */
export type Route = unknown

/** Routes maps "METHOD /path" to the agent's answer. The path is a prefix, so
 *  "DELETE /api/forwards" covers every id. */
export type Routes = Record<string, Route>

// ---------------------------------------------------------------------------
// The stub
// ---------------------------------------------------------------------------

/** One request the dashboard made. */
export interface AgentCall {
  readonly method: string
  /** The path as requested, query string included. */
  readonly url: string
  readonly body: string | undefined
  readonly headers: Record<string, string>
}

export interface AgentStub {
  readonly fetch: Mock<(input: string, init?: RequestInit) => Promise<Response>>
  /** Every request, in order. */
  readonly calls: AgentCall[]
  /** Replaces or adds a route mid-test, e.g. to make a retry succeed. */
  set(key: string, route: Route): void
  /** How many times "METHOD /path" was requested. */
  countOf(key: string): number
  /** The requested path of the nth matching call. Throws when it never happened,
   *  because an assertion against a silently absent call proves nothing. */
  urlOf(key: string, index?: number): string
  /** The parsed JSON body of the nth matching call. Throws when it never happened. */
  bodyOf<T = unknown>(key: string, index?: number): T
}

/** The session every stub seeds and accepts unless a test names another. */
export const TEST_SESSION = 'test-session'

/** What the agent says to a request without a session it accepts, word for word. */
export const UNAUTHORIZED_MESSAGE =
  'open the dashboard from the app-tail menu or run `app-tail dashboard`'

export interface AgentOptions {
  /** session is the one the browser holds before the test starts and the agent accepts.
   *  A launch token traded through POST /api/auth/session is answered with it too. */
  session?: string
  /** unauthorized is an agent that accepts no session at all -- after
   *  `app-tail auth rotate`, or once a session has expired: every /api/ call, the launch
   *  trade included, is answered with the 401 the real agent sends. */
  unauthorized?: boolean
  /** storageRefused is a browser that will not keep site data -- a private window, or
   *  strict privacy settings: every read and write of localStorage throws, from the
   *  moment the stub is installed. */
  storageRefused?: boolean
}

const SESSION_ROUTE = 'POST /api/auth/session'

interface CompiledRoute {
  method: string
  path: string
  route: Route
}

function compile(routes: Routes): CompiledRoute[] {
  return Object.entries(routes)
    .map(([key, route]) => {
      const at = key.indexOf(' ')
      if (at < 0) {
        throw new Error(`route key ${JSON.stringify(key)} must read "METHOD /path"`)
      }
      return { method: key.slice(0, at).toUpperCase(), path: key.slice(at + 1), route }
    })
    // Longest path first: "/api/forwards" would otherwise shadow
    // "/api/forwards/suggest-port" whenever it happened to be declared earlier.
    .sort((a, b) => b.path.length - a.path.length)
}

function headersOf(init: RequestInit | undefined): Record<string, string> {
  const raw = init?.headers
  if (raw === undefined) return {}
  if (raw instanceof Headers) return Object.fromEntries(raw.entries())
  if (Array.isArray(raw)) return Object.fromEntries(raw)
  return { ...raw }
}

/** refuseStorage makes every localStorage call throw the way a browser blocking site data
 *  does. Spied on the prototype: a property set on the Storage object itself would be
 *  stored as an item rather than replace the method. */
function refuseStorage() {
  const proto = Object.getPrototypeOf(window.localStorage) as Storage
  const refuse = () => {
    throw new DOMException('the browser is blocking site data', 'SecurityError')
  }
  vi.spyOn(proto, 'getItem').mockImplementation(refuse)
  vi.spyOn(proto, 'setItem').mockImplementation(refuse)
  vi.spyOn(proto, 'removeItem').mockImplementation(refuse)
}

/** authorized is the agent's own rule: everything under /api/ needs the session it
 *  accepts, except the trade that issues one. Static files and /healthz need nothing. */
function authorized(call: AgentCall, accepted: string | undefined): boolean {
  if (!call.url.startsWith('/api/')) return true
  if (`${call.method} ${call.url}` === SESSION_ROUTE) return accepted !== undefined
  const header = Object.entries(call.headers).find(([name]) => name.toLowerCase() === 'authorization')
  return accepted !== undefined && header?.[1] === `Bearer ${accepted}`
}

async function toResponse(route: Route, call: AgentCall): Promise<Response> {
  const answer: unknown =
    typeof route === 'function' ? await (route as (c: AgentCall) => unknown)(call) : route
  if (isReply(answer)) {
    return new Response(answer.body ?? null, {
      status: answer.status,
      ...(answer.body === undefined ? {} : { headers: { 'Content-Type': 'application/json' } }),
    })
  }
  return new Response(JSON.stringify(answer ?? {}), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

/**
 * stubAgent replaces fetch with a routing table over the agent's API. A request no
 * route covers fails the test at its end rather than answering with an empty body:
 * several components swallow their own fetch errors on purpose, so a silently
 * unanswered call would otherwise leave a test asserting nothing.
 *
 * Like the real agent it refuses any /api/ call that does not carry the session it
 * accepts, so every suite proves the dashboard sends one. The browser is seeded with that
 * session first, which also opens a page an earlier test in the file signed out.
 */
export function stubAgent(overrides: Routes = {}, options: AgentOptions = {}): AgentStub {
  const session = options.session ?? TEST_SESSION
  const accepted = options.unauthorized === true ? undefined : session
  const routesWith = (extra: Routes): Routes => ({
    ...defaultRoutes(),
    // A trade without a launch token is the agent's 400; any other is good for the
    // session this stub accepts.
    [SESSION_ROUTE]: (call: AgentCall) => {
      const sent = call.body === undefined ? undefined : (JSON.parse(call.body) as { launch?: unknown })
      if (typeof sent?.launch !== 'string') return failWith(400, 'the body must name a launch token')
      return { session }
    },
    ...extra,
  })
  const compiled = compile(routesWith(overrides))
  const calls: AgentCall[] = []
  const unrouted: string[] = []
  if (options.storageRefused === true) refuseStorage()
  storeSession(session)

  const fetchMock = vi.fn(async (input: string, init?: RequestInit): Promise<Response> => {
    const url = String(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    const body = typeof init?.body === 'string' ? init.body : undefined
    const call: AgentCall = { method, url, body, headers: headersOf(init) }
    calls.push(call)

    if (!authorized(call, accepted)) {
      return toResponse(failWith(401, UNAUTHORIZED_MESSAGE), call)
    }

    const match = compiled.find((r) => r.method === method && url.startsWith(r.path))
    if (match === undefined) {
      unrouted.push(`${method} ${url}`)
      throw new TypeError(`the test agent has no route for ${method} ${url}`)
    }
    return toResponse(match.route, call)
  })

  vi.stubGlobal('fetch', fetchMock)

  onTestFinished(() => {
    if (unrouted.length > 0) {
      throw new Error(
        `the dashboard called ${unrouted.length} route(s) the test never declared: ${unrouted.join(', ')}. ` +
          'Add them to the routes argument, or use netFail() if the failure is the point.',
      )
    }
  })

  const matching = (key: string): AgentCall[] => {
    const at = key.indexOf(' ')
    if (at < 0) throw new Error(`route key ${JSON.stringify(key)} must read "METHOD /path"`)
    const method = key.slice(0, at).toUpperCase()
    const path = key.slice(at + 1)
    return calls.filter((c) => c.method === method && c.url.startsWith(path))
  }

  const nth = (key: string, index: number): AgentCall => {
    const found = matching(key)[index]
    if (found === undefined) {
      const made = calls.map((c) => `${c.method} ${c.url}`).join(', ') || 'none'
      throw new Error(`the dashboard never made call #${index + 1} to ${key}; it made: ${made}`)
    }
    return found
  }

  return {
    fetch: fetchMock,
    calls,
    set(key, route) {
      compiled.length = 0
      compiled.push(...compile(routesWith({ ...overrides, [key]: route })))
      overrides = { ...overrides, [key]: route }
    },
    countOf: (key) => matching(key).length,
    urlOf: (key, index = 0) => nth(key, index).url,
    bodyOf<T>(key: string, index = 0): T {
      const raw = nth(key, index).body
      if (raw === undefined) throw new Error(`the request to ${key} carried no body`)
      return JSON.parse(raw) as T
    },
  }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
//
// Every factory takes a Partial of the real interface. Under
// exactOptionalPropertyTypes an override must OMIT an optional field rather than
// pass undefined for it -- `makeForward({ error: undefined })` is a type error, and
// `makeForward({})` is the way to say "no error".

export function makeForward(overrides: Partial<Forward> = {}): Forward {
  return {
    id: 'fwd-ssh',
    name: 'ssh',
    tunnelId: 'tn_primary',
    direction: 'to_local',
    protocol: 'tcp',
    bindAddr: '127.0.0.1',
    exposeToNetwork: false,
    listenPort: 2222,
    target: 'gpu-box.tail1234.ts.net:22',
    enabled: true,
    udpTimeoutSec: 0,
    state: 'running',
    activeTcp: 0,
    activeUdp: 0,
    bytesUp: 0,
    bytesDown: 0,
    endpoint: 'tcp 127.0.0.1:2222',
    ...overrides,
  }
}

export function makePeer(overrides: Partial<Peer> = {}): Peer {
  return {
    id: 'peer-1',
    hostName: 'gpu-box',
    dnsName: 'gpu-box.tail1234.ts.net',
    ips: ['100.64.0.5'],
    online: true,
    os: 'linux',
    ...overrides,
  }
}

export function makePreset(overrides: Partial<Preset> = {}): Preset {
  return { id: 'preset-ssh', name: 'SSH', protocol: 'tcp', remotePort: 22, builtIn: true, ...overrides }
}

/** makeProxy defaults to the module switched off, which is how a fresh install
 *  answers -- so a test that wants the card has to say so, and no other suite grows a
 *  dependency on a feature that is not on by default. */
export function makeProxy(overrides: Partial<ProxyView> = {}): ProxyView {
  return {
    enabled: false,
    nodeUp: false,
    scope: 'tailnet',
    scopeCarries: 'only destinations the tailnet routes; anything else is refused rather than sent direct',
    resolveVia: 'netmap',
    resolveExplains:
      "tailnet device names come from the netmap; every other name goes to this machine's resolver",
    requiresPassword: false,
    configuredAddr: '127.0.0.1:1080',
    movedFromConfig: false,
    counters: { opened: 0, active: 0, refused: 0, failed: 0, bytesUp: 0, bytesDown: 0 },
    capability: { available: false, degraded: false, reason: 'the proxy module is switched off' },
    snippets: [],
    ...overrides,
  }
}

/** makeProxyInstance is the instance every install has: the one the migration carried
 *  forward, granted the whole of the primary connection. Tests that care about a second
 *  instance, a narrower grant or one that could not bind supply their own. */
export function makeProxyInstance(overrides: Partial<ProxyInstanceView> = {}): ProxyInstanceView {
  // Read before the spread, so a test naming any of the derived members explicitly still
  // wins. A fixture given another id stands in for a second instance, which really does
  // offer different actions and a shorter list of ways to be pointed at.
  const isDefault = overrides.id === undefined || overrides.id === 'px_default'
  const held: ProxyInstanceView = {
    id: 'px_default',
    name: 'Default',
    slug: 'default',
    enabled: true,
    removable: !isDefault,
    settings: {},
    rules: [{ id: 'ar_connection', action: 'allow', tunnel: 'tn_primary' }],
    reach: ['everything on Tailnet'],
    listening: '127.0.0.1:1080',
    configuredAddr: '127.0.0.1:1080',
    movedFromConfig: false,
    requiresPassword: false,
    socksUrl: 'socks5h://127.0.0.1:1080',
    httpUrl: 'http://127.0.0.1:1080',
    // The auto-configuration script and the ways that go back through app-tail itself
    // answer for the one instance the command line reaches, so the agent serves them for
    // that instance only. A fixture that offered them everywhere would let a card pass its
    // tests while telling a second instance's user to run the first instance's commands.
    ...(isDefault ? { pacUrl: 'http://127.0.0.1:8377/proxy.pac' } : {}),
    snippets: isDefault
      ? [
          {
            id: 'exec',
            label: 'Run a command through the tailnet',
            description: 'Sets every proxy variable for one command and nothing else.',
            command: 'app-tail exec -- curl http://peer.your-tailnet.ts.net:8080/',
          },
          {
            id: 'curl',
            label: 'curl',
            description: '--socks5-hostname leaves the name for the proxy to resolve.',
            command: 'curl --socks5-hostname 127.0.0.1:1080 http://peer:8080/',
          },
        ]
      : [
          {
            id: 'curl',
            label: 'curl',
            description: '--socks5-hostname leaves the name for the proxy to resolve.',
            command: 'curl --socks5-hostname 127.0.0.1:1081 http://peer:8080/',
          },
        ],
    counters: { opened: 0, active: 0, refused: 0, failed: 0, bytesUp: 0, bytesDown: 0 },
    capability: { available: true, degraded: false },
    ...overrides,
  }
  // The stored half of the view is what the instance form is rendered from, so a test that
  // renames an instance must not have to restate the settings map to match.
  return {
    ...held,
    settings: { name: held.name, slug: held.slug, enabled: held.enabled, ...held.settings },
  }
}

/**
 * makeProxySchema is what GET /api/proxies/schema answers.
 *
 * Authored rather than generated, for the reason the connection schema is: a client renders
 * whatever the agent serves, and the pages under test read the served fields rather than
 * naming any. The vocabulary is the real one, because a fixture offering a verdict or a
 * transport the agent refuses would let a page pass its tests while writing something that
 * cannot be saved.
 */
export function makeProxySchema(fields?: readonly SettingFieldSchema[]): ProxySchemaView {
  const served = [...(fields ?? [proxyField('name', 'Name'), proxyField('slug', 'Short name')])]
  return {
    fields: served,
    groups: [
      {
        id: 'proxy',
        label: 'Proxy',
        description: 'A loopback proxy that carries exactly what its rules allow.',
      },
    ],
    modules: featureModules.filter((m) => served.some((f) => f.module === m.id)),
    actions: ['allow', 'deny'],
    protocols: ['', 'tcp', 'udp'],
  }
}

/** proxyField is one field of an instance form, in the ordinary shape of a text field. */
export function proxyField(
  key: string,
  label: string,
  overrides: Partial<SettingFieldSchema> = {},
): SettingFieldSchema {
  return {
    key,
    viewKey: key,
    kind: 'string',
    secret: false,
    readOnly: false,
    derived: false,
    restart: 'none',
    write: 'patch',
    label,
    group: 'proxy',
    tier: 'basic',
    module: 'core',
    help: `What this proxy's ${label.toLowerCase()} is.`,
    ...overrides,
  }
}

/** proxyRoutes answers both instance reads from one list, because a page that renders an
 *  instance form reads the schema and the values together. */
export function proxyRoutes(
  proxies: readonly ProxyInstanceView[] = [makeProxyInstance()],
): Routes {
  return {
    'GET /api/proxies': { proxies: [...proxies] },
    'GET /api/proxies/schema': makeProxySchema(),
  }
}

/** makeSystemProxy defaults to a platform app-tail will not write the setting on, which
 *  is what every machine running this suite except Windows actually is -- so a test that
 *  wants the applied case has to say so rather than inherit it. */
export function makeSystemProxy(overrides: Partial<SystemProxyView> = {}): SystemProxyView {
  return {
    enabled: false,
    platform: 'darwin',
    supported: false,
    applied: false,
    managed: false,
    manual: [],
    capability: {
      available: false,
      degraded: false,
      reason:
        "changing this Mac's proxy settings needs an administrator, and applies to one network service at a time -- so app-tail shows the command instead of running it",
      limits: ['macOS applies a proxy per network service.'],
    },
    ...overrides,
  }
}

/** makeInterface defaults to the mode switched off on a machine that could carry it,
 *  which is what a fresh install on a supported platform reports. A test that wants an
 *  unusable machine, or the mode actually in force, has to say so. */
export function makeInterface(overrides: Partial<InterfaceView> = {}): InterfaceView {
  return {
    enabled: false,
    mode: 'userspace',
    configured: 'userspace',
    inForce: false,
    ready: true,
    interface: 'utun9',
    helper: { design: true, installable: true, installed: true, running: true, version: 'dev' },
    capability: {
      available: false,
      degraded: false,
      reason: 'the network-interface module is switched off',
    },
    ...overrides,
  }
}

/** makePrefs defaults to nothing kept on the node, which is what a fresh install
 *  reports: every module owning a node preference is off. */
export function makePrefs(overrides: Partial<PrefsView> = {}): PrefsView {
  return {
    nodeUp: true,
    known: true,
    fields: [],
    capability: {
      available: false,
      degraded: false,
      reason: 'No settings are kept on the tailnet node in this configuration.',
    },
    ...overrides,
  }
}

/** makePrefField is one setting held on the node, in force unless told otherwise. Passing
 *  `live: undefined` is the state before the node has reported its own value, which the
 *  card renders differently from either value the node can report. */
export function makePrefField(
  // live is taken out of the Partial and given back explicitly: under
  // exactOptionalPropertyTypes an optional member cannot be passed as undefined, and
  // "the node has not reported this one" is exactly what a test needs to say.
  overrides: Omit<Partial<PrefFieldView>, 'live'> & { live?: PrefFieldView['live'] | undefined } = {},
): PrefFieldView {
  const { live, ...rest } = { live: true as PrefFieldView['live'], ...overrides }
  const field: PrefFieldView = {
    key: 'routes.accept',
    label: 'Reach networks other devices advertise',
    stored: true,
    inForce: true,
    ...rest,
  }
  if (live !== undefined) {
    field.live = live
  }
  return field
}

/** makeAutoMap defaults to the module switched off, matching a fresh install. */
export function makeAutoMap(overrides: Partial<AutoMapView> = {}): AutoMapView {
  return {
    enabled: false,
    ports: [22],
    limit: 32,
    mapped: 0,
    stored: 0,
    truncated: 0,
    ...overrides,
  }
}

/** makeExitNode is the exit-node module off, which is what a fresh install answers with.
 *  The warning is always present: the agent renders it whether or not anything is chosen,
 *  because it describes what changing the device costs rather than the current state. */
export function makeExitNode(overrides: Partial<ExitNodeView> = {}): ExitNodeView {
  return {
    tunnelId: 'tn_primary',
    enabled: false,
    rotating: false,
    liveOnline: false,
    reason: 'The exit node module is off, so this device traffic leaves from here.',
    warning:
      'Changing the exit node drops every connection going through the old one: downloads stop, SSH sessions end, and anything tied to the previous address has to sign in again.',
    capability: {
      available: false,
      degraded: false,
      reason: 'The exit node module is off, so this device traffic leaves from here.',
    },
    ...overrides,
  }
}

/** makeRoutes is the subnet-route module off, which is what a fresh install answers with.
 *  The limits are always present: they describe what a userspace router can carry rather
 *  than the current state, so they are stated whether or not anything is running. */
export function makeRoutes(overrides: Partial<RoutesView> = {}): RoutesView {
  return {
    tunnelId: 'tn_primary',
    enabled: false,
    accepting: false,
    serving: false,
    carried: 0,
    refused: 0,
    bytesIn: 0,
    bytesOut: 0,
    capability: {
      available: false,
      degraded: false,
      reason:
        'The subnet routes module is off, so this device neither reaches the networks its peers advertise nor offers any of its own.',
      limits: ['This device carries TCP only.'],
    },
    ...overrides,
  }
}

/** makeFabric is the ordinary addressing answer: nothing collides, so there is nothing to
 *  report and every network keeps its own addresses. */
export function makeFabric(overrides: Partial<FabricView> = {}): FabricView {
  return {
    mode: 'report',
    pool: ['198.18.0.0/15'],
    running: false,
    capability: {
      available: true,
      degraded: false,
      limits: ['Nothing is re-addressed.'],
    },
    ...overrides,
  }
}

/** makeEgress is the ordinary answer: internet traffic leaves this machine the way it
 *  always has, which is what an install nobody has changed does. */
export function makeEgress(overrides: Partial<EgressView> = {}): EgressView {
  return {
    mode: 'direct',
    carrying: false,
    ...overrides,
  }
}

/** makeRouting is an install with no exceptions, which is what every install starts as:
 *  internet traffic leaves the one way the egress setting says. */
export function makeRouting(overrides: Partial<RoutingView> = {}): RoutingView {
  return {
    rules: [] as RoutingRule[],
    describe: [],
    actions: ['via', 'direct', 'block'],
    tunnels: [{ id: 'tn_office', name: 'Office', running: true }],
    limits: ['A rule about a host name applies to traffic app-tail resolves for.'],
    capability: { available: true, degraded: false },
    ...overrides,
  }
}

/** makeLock is a tailnet without lock, which is what most tailnets answer with. Lock has
 *  no module switch: `enabled` is the tailnet's own setting, not app-tail's. */
export function makeLock(overrides: Partial<LockView> = {}): LockView {
  return {
    enabled: false,
    signed: false,
    canSign: false,
    visible: 0,
    capability: {
      available: true,
      degraded: false,
      reason:
        'Tailnet lock is off for your tailnet, so every device your network admits can be reached without a signature.',
    },
    ...overrides,
  }
}

/** makeDNS is the DNS module off, which is what a fresh install answers with. The limits
 *  are always present: they hold in every state, because app-tail never changes how this
 *  machine resolves names. */
export function makeDNS(overrides: Partial<DNSView> = {}): DNSView {
  return {
    enabled: false,
    using: false,
    magicDNS: false,
    exitNodeResolving: false,
    capability: {
      available: false,
      degraded: false,
      reason:
        "The DNS module is off, so app-tail resolves names with this machine's own resolver.",
      limits: [
        "Only app-tail's own connections use your tailnet's DNS. Other programs keep the resolver they already had.",
      ],
    },
    ...overrides,
  }
}

/** makeDNSSystem is the machine-wide resolver switched off, on a machine that could carry
 *  it: the state a fresh install answers with, so a test that wants the feature has to say
 *  so. */
export function makeDNSSystem(overrides: Partial<DNSSystemView> = {}): DNSSystemView {
  return {
    enabled: false,
    applied: false,
    profile: 'system',
    profileLabel: 'System default',
    retryOnNxdomain: false,
    ready: true,
    needsSetup: false,
    queries: { total: 0, toProfile: 0, toLocal: 0, answered: 0, failed: 0, blocked: 0 },
    capability: {
      available: true,
      degraded: false,
      reason:
        'The machine-wide resolver is off, so every program here resolves names the way it ' +
        'always did.',
      limits: [
        'While this is on, every program on this machine resolves names through app-tail. It ' +
          'is put back when you switch it off, when app-tail stops, and the next time app-tail ' +
          'starts if it was killed.',
      ],
    },
    ...overrides,
  }
}

/** makeDNSBlock is blocking switched off with the shipped list chosen but never
 *  downloaded, which is what a fresh install answers with. The limits hold in every state,
 *  so they are here rather than in the states that happen to show them. */
export function makeDNSBlock(overrides: Partial<DNSBlockView> = {}): DNSBlockView {
  return {
    enabled: false,
    own: false,
    system: false,
    answer: 'nxdomain',
    rules: 0,
    refreshHours: 24,
    blocked: 0,
    retryOnNxdomain: false,
    preset: 'medium',
    presets: [
      {
        id: 'minimum',
        name: 'Minimum',
        summary: 'Advertising, tracking and malicious hosts.',
        lists: ['hagezi-light'],
      },
      {
        id: 'medium',
        name: 'Medium',
        summary: 'The everyday level.',
        recommended: true,
        lists: ['hagezi-pro'],
      },
      {
        id: 'ultimate',
        name: 'Ultimate',
        summary: 'Everything the catalog can block without breaking a site.',
        lists: ['hagezi-ultimate'],
      },
    ],
    lists: [
      {
        id: 'hagezi-pro',
        provider: 'Hagezi',
        name: 'Hagezi Pro',
        url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt',
        format: 'abp',
        builtIn: true,
        enabled: true,
        rules: 0,
        skipped: 0,
      },
    ],
    capability: {
      available: true,
      degraded: false,
      reason: 'Blocking is off, so no name is refused by app-tail.',
      limits: [
        'Blocking happens where names are resolved, so a port forward -- which carries an ' +
          'address rather than a name -- is not filtered by it.',
        'Lists are downloaded and kept on this machine. A list that cannot be downloaded ' +
          'keeps blocking from the copy already here.',
        'A browser-filter list only contributes the rules a resolver can express; the rest ' +
          'are counted as skipped.',
      ],
    },
    ...overrides,
  }
}

/** makeIPS is traffic inspection switched off with nothing named, which is what a fresh
 *  install answers with. The limits hold in every state, so they are here rather than in
 *  the states that happen to show them. */
export function makeIPS(overrides: Partial<IPSView> = {}): IPSView {
  return {
    enabled: false,
    mode: 'detect',
    names: false,
    destinations: false,
    anomaly: false,
    handshake: false,
    fingerprints: false,
    payload: false,
    signatures: 0,
    rules: 0,
    skipped: 0,
    matched: 0,
    refused: 0,
    anomalies: 0,
    refreshHours: 24,
    preset: 'medium',
    presets: [
      {
        id: 'minimum',
        name: 'Minimum',
        summary: 'Networks with no legitimate traffic at all.',
        feeds: ['firehol-level1'],
      },
      {
        id: 'medium',
        name: 'Medium',
        summary: 'The everyday level.',
        recommended: true,
        feeds: ['firehol-level1', 'firehol-level2'],
      },
      {
        id: 'ultimate',
        name: 'Ultimate',
        summary: 'Every source on its widest tier.',
        feeds: ['firehol-level1', 'firehol-level2', 'ipsum-3'],
      },
    ],
    intercept: {
      mode: 'off',
      agreed: false,
      on: false,
      running: false,
      destinations: 0,
      shipped: false,
      certPath: '/state/tls/ca.crt',
      needsNewRoot: false,
      expiresSoon: false,
      expired: false,
      installed: false,
      opened: 0,
      failed: 0,
    },
    capability: {
      available: true,
      degraded: false,
      reason: 'Traffic inspection is off, so no connection is refused by app-tail.',
      limits: [
        'Inspection covers what app-tail itself carries -- the network interface in fabric ' +
          'mode, the proxy, and connections other devices on the tailnet route through this ' +
          'one. It is not a filter on everything this machine does.',
        "In tun mode this machine's own networking carries the tailnet's traffic rather " +
          'than app-tail, so nothing on that path is inspected. Fabric mode is the one that is.',
        'Traffic OpenVPN puts on its own interface never passes through app-tail and is not ' +
          'inspected. What app-tail carries over an OpenVPN tunnel is.',
        'A port forward carries an address chosen in the settings rather than one a program ' +
          'asked for, so it is not inspected.',
        'The network interface knows only the address a connection is bound for. The name a ' +
          'program asked for reaches inspection through the proxy only.',
      ],
    },
    ...overrides,
  }
}

/** The shipped catalog: the profile that changes nothing, and the two public resolvers
 *  app-tail ships with. It is what GET /api/dns/profiles answers on a fresh install. */
export function builtInDNSProfiles(): DNSProfile[] {
  return [
    { id: 'system', name: 'System default', builtIn: true },
    { id: 'tailnet', name: 'Tailnet DNS', builtIn: true },
    {
      id: 'quad9',
      name: 'Quad9 (malware blocking)',
      servers: ['https://9.9.9.9/dns-query', 'https://149.112.112.112/dns-query'],
      builtIn: true,
    },
    {
      id: 'quad9-unfiltered',
      name: 'Quad9 (unfiltered)',
      servers: ['https://9.9.9.10/dns-query', 'https://149.112.112.10/dns-query'],
      builtIn: true,
    },
    {
      id: 'cloudflare',
      name: 'Cloudflare',
      servers: ['https://1.1.1.1/dns-query', 'https://1.0.0.1/dns-query'],
      builtIn: true,
    },
    {
      id: 'google',
      name: 'Google',
      servers: ['https://8.8.8.8/dns-query', 'https://8.8.4.4/dns-query'],
      builtIn: true,
    },
  ]
}

/** makeDNSProfile is one of the user's own profiles, which is the only kind that can be
 *  edited or deleted. */
export function makeDNSProfile(overrides: Partial<DNSProfile> = {}): DNSProfile {
  return {
    id: 'nextdns',
    name: 'NextDNS',
    servers: ['https://dns.nextdns.io/abc123'],
    builtIn: false,
    ...overrides,
  }
}

/** makeExitNodeCandidate is one device the tailnet offers, online and not in use. */
export function makeExitNodeCandidate(
  overrides: Partial<ExitNodeCandidate> = {},
): ExitNodeCandidate {
  const id = overrides.id ?? 'nGATEWAY'
  const label = overrides.label ?? 'gateway'
  return {
    id,
    label,
    display: label,
    online: true,
    current: false,
    ...overrides,
  }
}

export function makeStatus(overrides: Partial<Status> = {}): Status {
  return {
    tunnelId: 'tn_primary',
    backendState: 'Running',
    running: true,
    hostname: 'app-tail-workstation',
    dnsName: 'app-tail-workstation.tail1234.ts.net',
    tailscaleIps: ['100.64.0.2'],
    loginName: 'someone@example.com',
    tags: ['tag:app-tail'],
    authMode: 'interactive',
    version: '1.2.3',
    ...overrides,
  }
}

export function makeApprovalNeed(overrides: Partial<ApprovalNeed> = {}): ApprovalNeed {
  return {
    kind: 'full-tunnel',
    reason: "carry all of this machine's internet traffic through app-tail",
    features: ['interface'],
    ...overrides,
  }
}

/** makeApprovals is the agent's answer when something is waiting; `{ needs: [], command: '' }`
 *  is its answer once nothing is. */
export function makeApprovals(overrides: Partial<Approvals> = {}): Approvals {
  return {
    needs: [makeApprovalNeed()],
    command: 'sudo app-tail tun grant --full-tunnel',
    ...overrides,
  }
}

/** makeSettings mirrors the agent's first-run defaults (internal/config/config.go),
 *  so a fixture never renders a value the real dashboard could not show. */
export function makeSettings(overrides: Partial<Settings> = {}): Settings {
  return {
    hostname: '',
    hostnameTemplate: 'app-tail-{hostname}',
    tags: ['tag:app-tail'],
    advertiseTagsOnLogin: false,
    hasAuthKey: false,
    hasOAuthClientSecret: false,
    oauthClientSecretFile: '',
    advancedNetworking: false,
    controlURL: '',
    ephemeral: false,
    uiListenAddr: '127.0.0.1:0',
    udpSessionTimeoutSec: 90,
    udpBufferBytes: 65535,
    'proxy.enabled': false,
    'proxy.listenAddr': '127.0.0.1:1080',
    'proxy.scope': 'tailnet',
    'proxy.resolveVia': 'netmap',
    'proxy.requireToken': false,
    'proxy.hasToken': false,
    'proxy.dialTimeoutSec': 30,
    'proxy.system': false,
    'automap.enabled': false,
    'automap.ports': ['22'],
    'automap.max': 32,
    'automap.portBase': 14000,
    'routes.enabled': false,
    'routes.accept': false,
    'routes.advertise': [],
    'routes.serve': false,
    'routes.netfilter':
      'Not applicable: app-tail routes in userspace and never configures netfilter, so ' +
      'there is nothing here to set.',
    'routes.advertiseExitNode': false,
    'exitNode.enabled': false,
    'exitNode.nodeId': '',
    'exitNode.auto': false,
    'exitNode.allowLanAccess': false,
    'exitNode.onFailure': 'hold',
    'exitNode.rotate.enabled': false,
    'exitNode.rotate.strategy': 'round_robin',
    'exitNode.rotate.intervalSec': 900,
    'exitNode.rotate.pauseOnActive': true,
    'exitNode.rotate.maxDeferrals': 3,
    'dns.enabled': false,
    'dns.useTailnet': false,
    // Empty is what the agent stores for the default zone, so the field reads as unset the
    // way it does on a first run.
    'dns.zone': '',
    'systemDns.enabled': false,
    'systemDns.profile': 'system',
    'systemDns.bootstrapProfile': 'quad9',
    'systemDns.localSuffixes': [],
    'systemDns.retryOnNxdomain': false,
    'systemDns.listenAddr': '127.0.0.153:53',
    'dnsBlock.enabled': false,
    'dnsBlock.own': false,
    'dnsBlock.system': false,
    'dnsBlock.answer': 'nxdomain',
    'dnsBlock.lists': ['hagezi-pro'],
    'dnsBlock.refreshHours': 24,
    'dnsBlock.allow': [],
    'dnsBlock.deny': [],
    'ips.enabled': false,
    'ips.mode': 'detect',
    'ips.names': false,
    'ips.destinations': false,
    'ips.anomaly': false,
    'ips.handshake': false,
    'ips.fingerprints': false,
    'ips.payload': false,
    'ips.signatures': [],
    'ips.lists': [],
    'ips.refreshHours': 24,
    'ips.allow': [],
    'ips.deny': [],
    'ips.intercept': 'off',
    'ips.interceptAgreed': false,
    'ips.interceptOnly': [],
    'ips.interceptExcept': [],
    'security.enabled': false,
    'security.shieldsUp': false,
    'security.postureChecking': false,
    'interface.enabled': false,
    'interface.mode': 'userspace',
    'traffic.latency': false,
    'traffic.smooth': true,
    'telemetry.enabled': false,
    'telemetry.eventLog.retentionDays': 30,
    'interface.name': '',
    'interface.virtualPool': ['198.18.0.0/15'],
    'tailnet.repairRoutes': true,
    'egress.mode': 'direct',
    'egress.tunnelId': '',
    'egress.multi.shape': 'spread',
    'egress.multi.tunnelIds': [],
    'egress.killSwitch': false,
    showTray: true,
    autoOpenDashboard: true,
    startAtLogin: false,
    stateDir: '/home/example/.config/app-tail',
    machineId: 'a1b2c3d4',
    effectiveHostname: 'app-tail-workstation',
    // Read from the switches above rather than set beside them, so a document built here
    // with the proxy on cannot also claim to be in standalone mode.
    'mode.primary': primaryMode({ ...overrides }),
    ...overrides,
  }
}

/** primaryMode mirrors config.PrimaryMode for the fixture: which mode a document built
 *  from these overrides is in. Reading it off the same switches the agent does is what
 *  keeps a fixture from describing a machine that cannot exist. */
function primaryMode(settings: Partial<Settings>): string {
  if (settings['interface.enabled'] === true) {
    if (settings['interface.mode'] === 'fabric') return 'fabric'
    if (settings['interface.mode'] === 'tun') return 'interface'
  }
  return settings['proxy.enabled'] === true ? 'proxy' : 'standalone'
}

/**
 * makeSettingsSchema is what GET /api/settings/schema answers: the generated registry
 * with each field's availability resolved against the given document, mirroring
 * config.SettingsSchemaFor. Resolving it here rather than serving the bare generated
 * table is what keeps the dashboard's own availability rules under test -- a form that
 * ignored the agent's answer would still pass against an always-available schema.
 */
export function makeSettingsSchema(settings: Settings): {
  fields: SettingFieldSchema[]
  groups: SettingGroupInfo[]
  modules: FeatureModuleInfo[]
} {
  const values = settings as unknown as Record<string, unknown>
  const moduleIsOn = (module: string): boolean => {
    const owner = featureModules.find((m) => m.id === module)
    if (owner === undefined) return false
    const control = settingsSchema.find((f) => f.key === owner.switchKey)
    return control !== undefined && values[control.viewKey] === true
  }
  const fields = settingsSchema.map((f) => {
    if (f.module === 'core') return { ...f, available: true, availableReason: '' }
    const owner = featureModules.find((m) => m.id === f.module)
    if (moduleIsOn(f.module)) return { ...f, available: true, availableReason: '' }
    return {
      ...f,
      available: false,
      availableReason: `needs the ${owner?.label ?? f.module} module turned on`,
    }
  })
  return { fields, groups: [...settingsGroups], modules: [...featureModules] }
}

/** makeTunnel is the connection every install has: the tailnet, up and carrying. Tests
 *  that care about a connection being down or unnamed supply their own. */
export function makeTunnel(overrides: Partial<TunnelView> = {}): TunnelView {
  const held: TunnelView = {
    id: 'tn_primary',
    type: 'tailscale',
    typeLabel: 'Tailscale',
    name: 'Tailnet',
    slug: 'tailnet',
    enabled: true,
    // Derived from the id this fixture is being given, so a test that adds a second
    // connection gets one that offers the actions a second connection really offers. Read
    // before the spread, so a test naming it explicitly still wins.
    removable: overrides.id !== undefined && overrides.id !== 'tn_primary',
    // Same reasoning, and the same rule the agent applies: the primary connection is brought
    // up with this machine's own tailnet settings rather than as one of the connections
    // beside it, so it is the one that cannot be built again on its own.
    retryable:
      (overrides.id !== undefined && overrides.id !== 'tn_primary') &&
      (overrides.enabled ?? true),
    settings: { name: 'Tailnet', slug: 'tailnet', type: 'tailscale' },
    state: 'connected',
    stateLabel: 'Connected',
    live: true,
    ...overrides,
  }
  // The stored half of the view is what the connection form is rendered from, so a test
  // that renames a connection must not have to restate the settings map to match.
  return {
    ...held,
    settings: {
      // Derived by the agent from the short name and the zone, and served on every
      // connection, so a fixture without it would let a page pass while showing nothing
      // for a name the real agent always answers for.
      'dns.suffix': `${held.slug}.internal`,
      ...held.settings,
      name: held.name,
      slug: held.slug,
      type: held.type,
    },
  }
}

/**
 * makeTunnelSchema is what GET /api/tunnels/schema answers.
 *
 * Unlike the settings schema this is authored rather than generated, because the
 * connection registry has no generated copy bundled with the page: a client renders
 * whatever the agent serves. The pages under test read the served fields rather than
 * naming any, so a field added in Go reaches them without this fixture growing.
 */
export function makeTunnelSchema(fields?: readonly SettingFieldSchema[]): TunnelSchemaView {
  const served = [...(fields ?? [tunnelField('name', 'Name'), tunnelField('slug', 'Short name')])]
  return {
    fields: served,
    groups: [
      {
        id: 'connection',
        label: 'Connection',
        description: 'What this connection is called, here and in DNS.',
      },
    ],
    // The modules the served fields name, the way the agent answers: a module no field is
    // gated on is a switch the form would have no reason to be told about.
    modules: featureModules.filter((m) => served.some((f) => f.module === m.id)),
    // What the add menu is built from. Only the kind this build can bring up, which is
    // what a real agent serves -- a fixture offering all three would let a page pass its
    // tests while offering something nothing can start.
    types: [{ value: 'tailscale', label: 'Tailscale' }],
  }
}

/** tunnelField is one field of a connection form. The overrides are what a test that
 *  cares about a particular section or a module-gated field reaches for; everything else
 *  is the ordinary shape of a connection's own text field. */
export function tunnelField(
  key: string,
  label: string,
  overrides: Partial<SettingFieldSchema> = {},
): SettingFieldSchema {
  return {
    key,
    viewKey: key,
    kind: 'string',
    secret: false,
    readOnly: false,
    derived: false,
    restart: 'none',
    write: 'patch',
    label,
    group: 'connection',
    tier: 'basic',
    module: 'core',
    help: `What this connection's ${label.toLowerCase()} is.`,
    ...overrides,
  }
}

/** tunnelRoutes answers every connection read: the form's values come from the list, the
 *  fields that describe them come from the schema, and the devices a form can target come
 *  from the connection that was selected. */
export function tunnelRoutes(tunnels: readonly TunnelView[] = [makeTunnel()]): Routes {
  const routes: Routes = {
    'GET /api/tunnels': { tunnels: [...tunnels] },
    'GET /api/tunnels/schema': makeTunnelSchema(),
  }
  for (const held of tunnels) {
    routes[`GET /api/tunnels/${held.id}/peers`] = { peers: [] as Peer[] }
  }
  return routes
}

/** settingsRoutes answers both settings reads from one document, because the schema's
 *  availability is resolved against exactly the settings the agent is serving. */
export function settingsRoutes(settings: Settings): Routes {
  return {
    'GET /api/settings': settings,
    'GET /api/settings/schema': makeSettingsSchema(settings),
  }
}

/** The settings write response, which carries the restart classification on top of
 *  the stored document. */
export function makeSettingsResponse(
  overrides: Partial<Settings> & {
    restartRequired?: boolean
    nodeRestart?: boolean
    uiRelisten?: boolean
    appRestart?: boolean
    adminRestart?: boolean
    adminRelaunch?: boolean
    deferred?: DeferredSetting[]
  } = {},
) {
  const {
    restartRequired,
    nodeRestart,
    uiRelisten,
    appRestart,
    adminRestart,
    adminRelaunch,
    deferred: held,
    ...settings
  } = overrides
  return {
    ...makeSettings(settings),
    restartRequired: restartRequired ?? false,
    nodeRestart: nodeRestart ?? false,
    uiRelisten: uiRelisten ?? false,
    appRestart: appRestart ?? false,
    adminRestart: adminRestart ?? false,
    adminRelaunch: adminRelaunch ?? false,
    ...(held ? { deferred: held } : {}),
  }
}

/** The filter vocabulary the agent serves, in its own order: every category and every
 *  severity, and the codes a page is most likely to be filtered down to. A fixture that
 *  offered a word the agent does not match on would let a page pass its tests while
 *  sending a filter the real agent refuses. */
const TELEMETRY_CATEGORIES = ['system', 'network', 'device', 'dns', 'security', 'settings']
const TELEMETRY_SEVERITIES = ['info', 'notice', 'warning', 'error']
const TELEMETRY_CODES = [
  'app.start',
  'connection.down',
  'connection.error',
  'connection.up',
  'forward.up',
  'settings.changed',
]

/** makeTelemetry defaults to recording switched off, which is what a fresh install
 *  answers -- so a test that wants the log has to say so. */
export function makeTelemetry(overrides: Partial<TelemetryView> = {}): TelemetryView {
  const enabled = overrides.enabled ?? false
  return {
    enabled,
    switchKey: 'telemetry.enabled',
    ...(enabled ? {} : { reason: 'Recording is switched off, so nothing is being kept.' }),
    stats: {
      events: 0,
      eventsRecorded: 0,
      eventCapacity: 5000,
      dropped: 0,
      retentionSec: 30 * 24 * 60 * 60,
    },
    codes: [...TELEMETRY_CODES],
    categories: [...TELEMETRY_CATEGORIES],
    severities: [...TELEMETRY_SEVERITIES],
    capability: {
      available: true,
      degraded: false,
      limits: [
        "The log is held in this app's memory, so it starts empty every time app-tail is started.",
      ],
    },
    ...overrides,
  }
}

/** makeTelemetryEvent is one ordinary entry: a connection coming up, which is the event a
 *  machine records most. */
export function makeTelemetryEvent(overrides: Partial<TelemetryEvent> = {}): TelemetryEvent {
  return {
    seq: 1,
    at: new Date(Date.UTC(2026, 7, 30, 9, 15, 0)).toISOString(),
    code: 'connection.up',
    category: 'network',
    severity: 'info',
    message: 'A connection was started.',
    ...overrides,
  }
}

/** makeTelemetryPage is one page of the log, newest first, the way the agent answers.
 *  `total` defaults to what is on the page, so a fixture is a complete answer unless a
 *  test is asking about a page that stopped at its limit. */
export function makeTelemetryPage(
  events: readonly TelemetryEvent[] = [],
  total?: number,
): TelemetryPage {
  return { events: [...events], total: total ?? events.length }
}

/** makeTraffic is a quiet machine: the window is sampled and holds enough to draw, and
 *  nothing has crossed. Tests that care about movement supply their own points. */
export function makeTraffic(overrides: Partial<TrafficView> = {}): TrafficView {
  const at = (n: number) => new Date(Date.UTC(2026, 6, 29, 10, 0, n)).toISOString()
  const quiet = (n: number): TrafficPoint => ({
    at: at(n),
    proxyUp: 0,
    proxyDown: 0,
    forwardUp: 0,
    forwardDown: 0,
    routeIn: 0,
    routeOut: 0,
    tunnelUp: 0,
    tunnelDown: 0,
    connections: 0,
  })
  return {
    intervalSec: 1,
    windowSec: 300,
    points: [quiet(0), quiet(1), quiet(2)],
    current: quiet(2),
    totals: { proxyUp: 0, proxyDown: 0, refused: 0, failed: 0 },
    peers: [],
    destinations: [],
    ...overrides,
  }
}

/** makeTrafficPeer is one device that has exchanged traffic, reached directly. */
/** One lane of the rolling window, split by what that lane names. The default holds two
 *  keys moving at a steady rate, which is the least a line can be drawn from. */
export function makeTrafficBreakdown(
  overrides: Partial<TrafficBreakdown> = {},
): TrafficBreakdown {
  return {
    lane: 'devices',
    intervalSec: 1,
    windowSec: 300,
    series: [
      makeTrafficSeries({ key: 'n1', label: 'nas', up: [1024, 2048], down: [4096, 4096] }),
      makeTrafficSeries({ key: 'n2', label: 'laptop', up: [64, 64], down: [128, 96] }),
    ],
    ...overrides,
  }
}

export function makeTrafficSeries(overrides: Partial<TrafficSeries> = {}): TrafficSeries {
  return { key: 'n1', label: 'nas', up: [1024, 2048], down: [4096, 4096], ...overrides }
}

export function makeTrafficPeer(overrides: Partial<TrafficPeer> = {}): TrafficPeer {
  return {
    id: 'n1',
    label: 'nas',
    online: true,
    active: true,
    rxBytes: 900_000,
    txBytes: 12_000,
    direct: true,
    exitNode: false,
    ...overrides,
  }
}

/** defaultRoutes answers every read the dashboard performs on mount, typed as the
 *  real interfaces so a drift in the generated settings schema fails the typecheck
 *  rather than surfacing as a puzzling render. Writes are deliberately absent: a
 *  test that mutates must say what the agent answers. */
export function defaultRoutes(): Routes {
  return {
    'GET /api/status': makeStatus(),
    'GET /api/peers': { peers: [] as Peer[] },
    'GET /api/forwards/suggest-port': { port: 41000 },
    'GET /api/forwards': { forwards: [] as Forward[] },
    ...tunnelRoutes(),
    'GET /api/presets': { presets: [] as Preset[] },
    'GET /api/proxy/system': makeSystemProxy(),
    'GET /api/proxy': makeProxy(),
    ...proxyRoutes(),
    'GET /api/automap': makeAutoMap(),
    'GET /api/exitnode': makeExitNode(),
    'GET /api/routes': makeRoutes(),
    'GET /api/fabric': makeFabric(),
    'GET /api/egress': makeEgress(),
    'GET /api/routing': makeRouting(),
    'GET /api/lock': makeLock(),
    'GET /api/dns': makeDNS({ system: makeDNSSystem() }),
    'GET /api/dns/profiles': { profiles: builtInDNSProfiles() },
    'GET /api/dns/block': makeDNSBlock(),
    'GET /api/ips': makeIPS(),
    'GET /api/tun': makeInterface(),
    'GET /api/prefs': makePrefs(),
    'GET /api/telemetry': makeTelemetry(),
    'GET /api/telemetry/events': makeTelemetryPage(),
    ...settingsRoutes(makeSettings()),
    'GET /api/traffic': makeTraffic(),
    // The breakdowns are read only while their dimension is on screen, so none of these is
    // a mount-time call -- they are declared so a test that switches dimension does not
    // have to restate the whole set to reach one of them.
    'GET /api/traffic/devices': makeTrafficBreakdown({ lane: 'devices' }),
    'GET /api/traffic/connections': makeTrafficBreakdown({ lane: 'connections' }),
    'GET /api/traffic/destinations': makeTrafficBreakdown({ lane: 'destinations' }),
    'GET /api/traffic/ports': makeTrafficBreakdown({ lane: 'ports' }),
    'GET /api/autostart': { enabled: false },
    'POST /api/restart-app': { restarting: true },
    'GET /healthz': { ok: true },
  }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

export interface ScopedView extends BoundFunctions<typeof queries> {
  container: HTMLElement
  unmount: () => void
  rerender: (node: ReactElement) => void
}

export interface AgentView extends ScopedView {
  agent: AgentStub
}

/**
 * renderAgent stubs the agent, mounts the component and lets its mount-time fetches
 * land. Queries are scoped to this render's own container rather than the whole
 * document, so a file's tests never see each other's markup.
 */
export async function renderAgent(
  node: ReactElement,
  routes: Routes = {},
  options: AgentOptions = {},
): Promise<AgentView> {
  const agent = stubAgent(routes, options)
  // A fresh store per render, never a shared one: the suite clears globals between files
  // but not module state, so a store outliving a test would answer the next one from the
  // responses this one stubbed.
  const store = new PollStore()
  const view = render(<StoreProvider store={store}>{node}</StoreProvider>)
  await settle()
  return {
    ...within(view.container),
    container: view.container,
    agent,
    unmount: view.unmount,
    // Re-wrapped in the same provider: rendering the bare node would swap the tree's root
    // element type, which unmounts the component under test and throws away the state a
    // rerender is asking about.
    rerender: (next: ReactElement) =>
      view.rerender(<StoreProvider store={store}>{next}</StoreProvider>),
  }
}

/** renderScoped mounts a component that talks to nothing, with the same
 *  container-scoped queries renderAgent gives. Leaving fetch alone is the point: a
 *  presentational component that starts making requests should fail loudly here. */
export function renderScoped(node: ReactElement): ScopedView {
  const view = render(node)
  return {
    ...within(view.container),
    container: view.container,
    unmount: view.unmount,
    rerender: view.rerender,
  }
}

/**
 * settle flushes pending microtasks inside act. Twice by default: the first pass
 * resolves a mount effect's fetch, the second lets the state it set run the effects
 * that depend on it.
 */
export async function settle(times = 2): Promise<void> {
  for (let i = 0; i < times; i += 1) {
    await act(async () => {})
  }
}

/**
 * A settings form holding nothing, for a card under test on its own.
 *
 * Every feature card carries its group's settings, so it takes a form. A card test that
 * is asking about the readout -- what state is named, which sentence is shown -- wants no
 * controls in the way, and this is the form with none. A test that is actually about the
 * settings should render the card through `renderAgent` with a real `useSettingsDraft`
 * instead, so the write path is under test rather than stubbed.
 */
export function emptySettingsForm(overrides: Partial<SettingsForm> = {}): SettingsForm {
  return {
    loaded: true,
    groups: [],
    available: [],
    error: undefined,
    saving: false,
    saveGroup: async () => {},
    dirtyGroups: new Set<string>(),
    bind: () => ({
      value: '',
      example: '',
      onChange: () => {},
      stored: false,
      error: undefined,
      disabled: true,
    }),
    bindImmediate: () => ({
      value: '',
      example: '',
      onChange: () => {},
      stored: false,
      error: undefined,
      disabled: true,
    }),
    applyPatch: () => Promise.resolve({ stored: true }),
    nodeRestartPending: false,
    uiRelistenPending: false,
    appRestartPending: false,
    adminRestartPending: false,
    adminRelaunchPending: false,
    deferred: [],
    clearNodeRestart: () => {},
    setError: () => {},
    restarting: false,
    restartNode: async () => {},
    ...overrides,
  }
}

/**
 * A settings form with these modules switched on.
 *
 * Several of a connection's settings are gated on a module the installation holds rather
 * than the connection, so a page rendering one of them is handed the form those switches
 * live on. A test about such a field has to say which modules are on, for the same reason
 * the page has to be told: with every switch off, the agent serves the field as
 * unavailable and nothing draws it.
 */
export function settingsFormWithModules(...on: readonly string[]): SettingsForm {
  const switches = featureModules
    .filter((m) => on.includes(m.id))
    .flatMap((m) => settingsSchema.filter((f) => f.key === m.switchKey))
    .map((f) => ({ ...f, available: true, availableReason: '' }))
  const bind = (field: SettingFieldSchema) => ({
    value: switches.some((f) => f.key === field.key),
    example: '',
    onChange: () => {},
    stored: false,
    error: undefined,
    disabled: false,
  })
  return emptySettingsForm({ available: switches, bind, bindImmediate: bind })
}

/** pressEscape sends the key from the document, so it reaches the window-level
 *  keydown listener every overlay installs. */
export function pressEscape(): void {
  fireEvent.keyDown(document.body, { key: 'Escape' })
}

/**
 * openInfo opens the info popover named for `label` and hands back the panel it revealed.
 *
 * The prose a card states permanently -- what the mode changes, what a route will not
 * carry -- lives behind this rather than stacked above the live data. It is genuinely
 * absent from the document until the button is pressed, so a test that asserts on that
 * prose has to press the button first. Asserting on it without opening would only prove
 * the sentence had leaked back into the page.
 */
export function openInfo(container: HTMLElement, label: string): HTMLElement {
  const trigger = within(container).getByRole('button', { name: `About ${label}` })
  fireEvent.click(trigger)
  const body = container.querySelector('.info-body')
  if (!(body instanceof HTMLElement)) throw new Error(`the ${label} popover revealed nothing`)
  return body
}

/**
 * openPicker opens the choice picker whose legend is `legend` and hands back the list it
 * dropped down.
 *
 * A picker shows only the choice in force until it is clicked, so its other rows are
 * genuinely absent from the document rather than merely hidden. A test asserting on them
 * has to open it first, the same way a person does.
 */
export function openPicker(container: HTMLElement, legend: string): HTMLElement {
  const label = [...container.querySelectorAll('.picker-legend')].find(
    (node) => node.textContent === legend,
  )
  const picker = label?.closest('.choice-picker')
  const trigger = picker?.querySelector('.picker-current')
  if (!(trigger instanceof HTMLElement)) throw new Error(`no picker is legended ${legend}`)
  // Clicked only while it is closed: the control is a toggle, so a second call meaning
  // "have it open" would shut the list a first call opened.
  if (trigger.getAttribute('aria-expanded') !== 'true') fireEvent.click(trigger)
  const list = picker?.querySelector('.choice-list')
  if (!(list instanceof HTMLElement)) throw new Error(`the ${legend} picker opened onto nothing`)
  return list
}

/** Every row the picker legended `legend` offers, once it has been opened. */
export function pickerRows(container: HTMLElement, legend: string): string[] {
  return [...openPicker(container, legend).querySelectorAll('.choice-row')].map(
    (row) => row.textContent ?? '',
  )
}

/** The row the open picker marks as the one in force. */
export function pickerChosen(container: HTMLElement, legend: string): string | undefined {
  const inputs = openPicker(container, legend).querySelectorAll<HTMLInputElement>('input')
  return [...inputs].find((input) => input.checked)?.value
}

/** The closed control: what the picker says is in force without being touched. */
export function pickerCurrent(container: HTMLElement, legend: string): HTMLElement {
  const label = [...container.querySelectorAll('.picker-legend')].find(
    (node) => node.textContent === legend,
  )
  const current = label?.closest('.choice-picker')?.querySelector('.picker-current')
  if (!(current instanceof HTMLElement)) throw new Error(`no picker is legended ${legend}`)
  return current
}

/** Choosing a row of a picker that has to be opened first, which is what a person does. */
export function pickRow(container: HTMLElement, legend: string, value: string) {
  const row = openPicker(container, legend).querySelector<HTMLInputElement>(`input[value="${value}"]`)
  if (row === null) throw new Error(`the ${legend} picker offers no row valued ${value}`)
  fireEvent.click(row)
}

/** A promise a test resolves by hand. Required for any assertion about a busy or
 *  disabled state: those flags are set and cleared around a single await, so once
 *  the request has resolved the flag is already back to false. */
export interface Deferred<T> {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason?: unknown) => void
}

export function deferred<T = void>(): Deferred<T> {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

/** stubConfirm answers window.confirm. jsdom's own implementation throws "not
 *  implemented" and returns undefined, which reads as a cancelled dialog -- so a
 *  delete guarded by confirm() silently never fires unless this is installed. */
export function stubConfirm(answer: boolean): Mock<(message?: string) => boolean> {
  const mock = vi.fn<(message?: string) => boolean>(() => answer)
  vi.stubGlobal('confirm', mock)
  return mock
}

/** stubClipboard installs a writable clipboard. jsdom has none, and vi.stubGlobal
 *  cannot help: navigator.clipboard has to be defined on the existing navigator
 *  rather than replacing the whole object. Restored when the test finishes, since
 *  unstubAllGlobals does not know about it. */
export function stubClipboard(): { writeText: Mock<(text: string) => Promise<void>> } {
  const writeText = vi.fn<(text: string) => Promise<void>>(() => Promise.resolve())
  const original = Object.getOwnPropertyDescriptor(navigator, 'clipboard')
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText },
    configurable: true,
    writable: true,
  })
  onTestFinished(() => {
    if (original) Object.defineProperty(navigator, 'clipboard', original)
    else delete (navigator as { clipboard?: unknown }).clipboard
  })
  return { writeText }
}
