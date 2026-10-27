// SPDX-License-Identifier: MIT

// The dashboard's addresses.
//
// Every route lives in the hash, and not by preference: the bundle is built with a
// relative base so the agent can serve it from wherever it likes, which means a path
// route like /devices resolves ./assets/x.js against /devices/ and gets a 404 and a blank
// page. A hash keeps every address on one document. The query string lives inside the
// hash for the same reason it exists at all -- a filtered view has to be a link someone
// can send -- so a route carries its own query rather than sharing the document's.

/** SECTIONS is every top-level page, in the order the nav rail lists them. */
export const SECTIONS = [
  'dashboard',
  'connections',
  'internet',
  'dns',
  'inspection',
  'security',
  'activity',
  'settings',
] as const

export type SectionId = (typeof SECTIONS)[number]

/** SETTINGS_SECTIONS is every page under Settings. There is one, and `#/settings` alone
 *  means it; it keeps a name of its own because the menu bar's link to it names it. */
export const SETTINGS_SECTIONS = ['application'] as const

export type SettingsSectionId = (typeof SETTINGS_SECTIONS)[number]

/**
 * CONNECTIONS_SECTIONS is the second column under Connections, in the order it lists
 * them. `networks` is the landing page and is what `#/connections` alone means.
 *
 * The order is the reader's order of questions: which networks, how this machine is on
 * them, then what programs are let through to them -- the ports, the grants that read
 * as sentences, the proxies that carry those grants, and last the ordered rules that
 * decide them, because rule order is semantics and a reader who never needs to see it
 * should not have to.
 */
export const CONNECTIONS_SECTIONS = [
  'networks',
  'paths',
  'forwards',
  'grants',
  'proxies',
  'rules',
] as const

export type ConnectionsSectionId = (typeof CONNECTIONS_SECTIONS)[number]

/** DNS_SECTIONS is the second column under DNS. `resolver` is the landing page and is
 *  what `#/dns` alone means. */
export const DNS_SECTIONS = ['resolver', 'blocklist', 'names'] as const

export type DnsSectionId = (typeof DNS_SECTIONS)[number]

/**
 * Route is an address the dashboard understands.
 *
 * `missing` is a section of its own rather than a silent fall back to the dashboard: an
 * address that names nothing is usually a stale link, and quietly showing something else
 * is how a broken link survives.
 */
export interface Route {
  section: SectionId | 'missing'
  /** params are the path segments after the section, e.g. ['proxy'] under settings. */
  params: readonly string[]
  query: URLSearchParams
}

function isSection(value: string): value is SectionId {
  return (SECTIONS as readonly string[]).includes(value)
}

/** isSettingsSection is exported because the settings page has to tell a section it can
 *  render from one that only looks like one. */
export function isSettingsSection(value: string | undefined): value is SettingsSectionId {
  return value !== undefined && (SETTINGS_SECTIONS as readonly string[]).includes(value)
}

/** isConnectionsSection tells a page under Connections from a connection's own address:
 *  `#/connections/wireguard/tn_x` carries a kind first, and the kinds and the sections
 *  are disjoint sets, which the router's tests pin. */
export function isConnectionsSection(value: string | undefined): value is ConnectionsSectionId {
  return value !== undefined && (CONNECTIONS_SECTIONS as readonly string[]).includes(value)
}

/** isDnsSection is the same distinction for the DNS page. */
export function isDnsSection(value: string | undefined): value is DnsSectionId {
  return value !== undefined && (DNS_SECTIONS as readonly string[]).includes(value)
}

/** parseRoute reads a location hash. It accepts the hash with or without its '#', because
 *  `location.hash` carries one and a written link does not. */
export function parseRoute(hash: string): Route {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash
  const at = raw.indexOf('?')
  const path = at < 0 ? raw : raw.slice(0, at)
  const query = new URLSearchParams(at < 0 ? '' : raw.slice(at + 1))
  const segments = path.split('/').filter((segment) => segment !== '')

  const head = segments[0]
  if (head === undefined) return { section: 'dashboard', params: [], query }
  if (!isSection(head)) return { section: 'missing', params: segments, query }
  return { section: head, params: segments.slice(1), query }
}

/** href builds the address of a page, which is what every link on the shell is. */
export function href(section: SectionId, ...params: readonly string[]): string {
  const path = [section === 'dashboard' ? '' : section, ...params]
    .filter((segment) => segment !== '')
    .join('/')
  return `#/${path}`
}

/**
 * Addresses that named a page here and now name a different one, and where each goes.
 *
 * Settings that belong to one private network moved onto that network's own page, and a
 * bookmark or a link in a note is the way people arrive at a page they use. Keyed by path
 * rather than matched loosely, so a redirect can only land on an address named here.
 *
 * These tables are Maps because their keys come from the address bar: on a plain object a
 * segment such as `constructor` would find Object.prototype's own members.
 */
const MOVED_ROUTES = new Map<string, string>([
  // The connections list rather than one connection: which network's exit node or subnet
  // routes the reader meant is exactly what these addresses never said.
  ['settings/exitnode', href('connections')],
  ['settings/routes', href('connections')],
  // The proxy is no longer one thing with one set of settings, so its page is the list of
  // the instances that replaced it.
  ['settings/proxy', href('connections', 'proxies')],
  // The network interface is not a setting among settings: it is one of the ways this
  // machine reaches its networks, and it belongs beside the other ways.
  ['settings/interface', href('connections', 'paths')],
  // Who can reach this device and its dashboard is a section of its own on the rail.
  ['settings/security', href('security')],
  // Everything about how programs reach the networks lives under Connections now: the
  // ways this machine is on them, the ports opened for them, and what is let through.
  ['mode', href('connections', 'paths')],
  ['forwards', href('connections', 'forwards')],
  ['access', href('connections', 'grants')],
])

/**
 * Sections that moved whole, keeping every page under them: the first segment is
 * replaced and the rest of the address is kept, for the pages named here. A whole address
 * in MOVED_ROUTES wins over a prefix here, so a page that moved somewhere other than the
 * rest of its section can still say so.
 */
const MOVED_PREFIXES = new Map<string, { to: SectionId; pages: readonly string[] }>([
  // Grants, proxies and rules keep their names under Connections, so a link to one rule
  // still opens that rule.
  ['access', { to: 'connections', pages: ['grants', 'proxies', 'rules'] }],
])

/** movedTo is the address a stale one now means, or undefined when it still means itself.
 *  It takes a hash for the same reason parseRoute does, and normalizes it the same way.
 *  An address under a moved section that names no page there is left alone: it named
 *  nothing before the move, and a redirect would have it quietly name something now. */
export function movedTo(hash: string): string | undefined {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash
  const at = raw.indexOf('?')
  const segments = (at < 0 ? raw : raw.slice(0, at)).split('/').filter((s) => s !== '')
  const whole = MOVED_ROUTES.get(segments.join('/'))
  if (whole !== undefined) return whole
  const [head, page] = segments
  if (head === undefined || page === undefined) return undefined
  const prefix = MOVED_PREFIXES.get(head)
  if (prefix === undefined || !prefix.pages.includes(page)) return undefined
  return href(prefix.to, ...segments.slice(1))
}

/** The sections the menu bar may name, and the address each one means. Named rather than
 *  taken from the URL as given: a query that could reach any address at all would put the
 *  page in the hands of whoever wrote the link. A Map for the same reason as MOVED_ROUTES. */
const LEGACY_SECTIONS = new Map<string, string>([
  ['dns', href('dns')],
  ['proxies', href('connections', 'proxies')],
  ['connections', href('connections')],
])

/**
 * legacyHash translates what the menu bar asks for into an address.
 *
 * Opening a browser is the entire handoff those entries have, so the query string is the
 * whole message, and it is a query string because the tray predates these routes and is
 * pinned by its own tests. Nothing else in the app reads the document's query.
 */
export function legacyHash(search: string): string | undefined {
  const params = new URLSearchParams(search)
  if (params.get('settings') === '1') return href('settings', 'application')
  const named = params.get('section')
  if (named === null) return undefined
  return LEGACY_SECTIONS.get(named)
}
