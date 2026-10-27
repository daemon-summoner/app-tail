// SPDX-License-Identifier: MIT

import { api } from '../api'

/** Resource is one thing the dashboard reads from the agent: how to fetch it, and how
 *  often it is worth asking again. The interval lives here rather than at the call site so
 *  two screens reading the same thing cannot disagree about its cadence -- which is what
 *  makes one shared timer per key correct rather than a coincidence. */
export interface Resource<T> {
  fetch: () => Promise<T>
  intervalMs: number
}

/** resource is a typed constructor, so `resources` below infers each entry's payload type
 *  instead of collapsing to a single union. */
function resource<T>(fetch: () => Promise<T>, intervalMs: number): Resource<T> {
  return { fetch, intervalMs }
}

// Status drives the connection card; forwards drive the counters. Both are cheap
// loopback calls, so the intervals are tuned for a live feel rather than for load.
const STATUS_INTERVAL_MS = 2000
const FORWARDS_INTERVAL_MS = 3000
// Everything else moves on its own schedule -- an admin approves a route, a peer stops
// advertising one, the exit node rotates -- and none of it is urgent.
const FEATURE_INTERVAL_MS = 4000
// The traffic view carries a whole window per response, so the poll only decides how
// fresh the right-hand edge of the graph is, not how much history there is.
const TRAFFIC_INTERVAL_MS = 2000
// Slower than the rest: this reads a value that lives outside the app, and nothing about
// it moves unless a person changes a setting.
const SYSTEM_PROXY_INTERVAL_MS = 6000

/**
 * resources is every polled read the dashboard makes, keyed by a name a screen asks for.
 *
 * A key that appears here can be read from anywhere without arranging a fetch, and two
 * screens asking for the same key share one timer and one request. The registry is also
 * what makes `refreshAll` and `invalidate` possible: neither can exist while each screen
 * owns its own private poll.
 */
export const resources = {
  status: resource(api.status, STATUS_INTERVAL_MS),
  forwards: resource(api.forwards, FORWARDS_INTERVAL_MS),
  traffic: resource(api.traffic, TRAFFIC_INTERVAL_MS),
  // One key per breakdown rather than one parameterised key, because the store starts a
  // poll on the first subscriber and stops it on the last: rendering only the selected
  // lane's chart is then the whole of the gating, and the lanes nobody is looking at cost
  // no requests. Each carries a series per key, which is most of the payload on this page.
  'traffic.devices': resource(() => api.trafficBreakdown('devices'), TRAFFIC_INTERVAL_MS),
  'traffic.connections': resource(() => api.trafficBreakdown('connections'), TRAFFIC_INTERVAL_MS),
  'traffic.destinations': resource(() => api.trafficBreakdown('destinations'), TRAFFIC_INTERVAL_MS),
  'traffic.ports': resource(() => api.trafficBreakdown('ports'), TRAFFIC_INTERVAL_MS),
  // A connection's state moves without this page asking: a node signs in, a network goes
  // away, an interactive login completes in another window.
  tunnels: resource(api.tunnels, FEATURE_INTERVAL_MS),
  proxy: resource(api.proxy, FEATURE_INTERVAL_MS),
  // An instance's counters move with every connection through it, and whether it is
  // listening changes when a port it wanted is taken or given up elsewhere.
  proxies: resource(api.proxies, FEATURE_INTERVAL_MS),
  'proxy.system': resource(api.systemProxy, SYSTEM_PROXY_INTERVAL_MS),
  automap: resource(api.automap, FEATURE_INTERVAL_MS),
  // The interface mode is decided outside this page too -- the menu bar switches it, and
  // a node that could not create one falls back on its own -- so it is polled like the
  // rest rather than read once.
  tun: resource(api.tun, FEATURE_INTERVAL_MS),
  // The exit node changes on a schedule and when a device goes away, neither of which
  // this page is told about.
  exitNode: resource(api.exitNode, FEATURE_INTERVAL_MS),
  // Both directions of subnet routing move without this page asking: an admin approves a
  // route in the console, and a peer starts or stops advertising one.
  routes: resource(api.routes, FEATURE_INTERVAL_MS),
  // Which networks collide changes as connections come up and as the networks behind them
  // start or stop advertising a range, neither of which this page is told about.
  fabric: resource(api.fabric, FEATURE_INTERVAL_MS),
  // Whether the connection carrying internet traffic can still carry it moves on its own:
  // an exit node goes offline, a connection drops. The setting stays where it was, so
  // nothing but this says the traffic stopped going that way.
  egress: resource(api.egress, FEATURE_INTERVAL_MS),
  // A rule naming a connection that stopped running refuses its destinations rather than
  // sending them another way, and nothing but this says so -- the rules themselves have
  // not changed.
  routing: resource(api.routing, FEATURE_INTERVAL_MS),
  // Tailnet lock is enabled by an administrator for the whole tailnet, and a device it
  // holds back looks exactly like a working one until this says otherwise.
  lock: resource(api.lock, FEATURE_INTERVAL_MS),
  dns: resource(api.dns, FEATURE_INTERVAL_MS),
  // Lists download on a schedule of their own and a pause ends by itself, so what blocking
  // is doing moves without this page having asked for anything.
  dnsBlock: resource(api.dnsBlock, FEATURE_INTERVAL_MS),
  // Matches land as connections are made and a pause ends by itself, so what inspection has
  // found moves without this page having asked for anything.
  ips: resource(api.ips, FEATURE_INTERVAL_MS),
  // The node's own preferences change without this app asking, so this is a poll rather
  // than a value refreshed after a save.
  prefs: resource(api.prefs, FEATURE_INTERVAL_MS),
  // The log grows as the app does things, and the counters here are what say there is
  // something new to read -- so the events themselves need no timer of their own.
  telemetry: resource(api.telemetry, FEATURE_INTERVAL_MS),
} as const

export type ResourceKey = keyof typeof resources

/** ResourceTable is the whole registry: every key the store can be asked for, with the
 *  fetch and the cadence that answer it. Naming the shape is what lets the store take one
 *  rather than reach for this module's own, so its timing can be exercised against
 *  fetchers a test controls instead of against the network. */
export type ResourceTable = { readonly [K in ResourceKey]: Resource<ResourceData<K>> }

/** ResourceData is what a key's fetch resolves to, which is what `usePolled` hands back.
 *  Deriving it keeps the store untyped internally and typed at its edges. */
export type ResourceData<K extends ResourceKey> =
  (typeof resources)[K] extends Resource<infer T> ? T : never
