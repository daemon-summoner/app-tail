// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import {
  CONNECTIONS_SECTIONS,
  DNS_SECTIONS,
  href,
  isConnectionsSection,
  isDnsSection,
  isSettingsSection,
  legacyHash,
  movedTo,
  parseRoute,
  SECTIONS,
} from './router'
import type { TunnelType } from '../api'

/** Every kind a connection's own address can start with. Listed by hand so that adding a
 *  kind to the API forces a look at whether it collides with a page under Connections. */
const TUNNEL_TYPES: readonly TunnelType[] = ['tailscale', 'wireguard', 'openvpn']

describe('reading an address', () => {
  it.each([
    ['', 'dashboard', []],
    ['#', 'dashboard', []],
    ['#/', 'dashboard', []],
    ['#/internet', 'internet', []],
    ['#/inspection', 'inspection', []],
    ['#/connections', 'connections', []],
    ['#/connections/forwards', 'connections', ['forwards']],
    // A connection's own page carries its kind and its id, and parseRoute keeps both
    // rather than stopping at the section.
    ['#/connections/wireguard/tn_office', 'connections', ['wireguard', 'tn_office']],
    ['#/dns', 'dns', []],
    ['#/dns/blocklist', 'dns', ['blocklist']],
    ['#/settings', 'settings', []],
    ['#/settings/proxy', 'settings', ['proxy']],
    // Trailing and doubled separators are what a hand-written link looks like, and none of
    // them change which page was asked for.
    ['#/settings/proxy/', 'settings', ['proxy']],
    ['#//settings//proxy', 'settings', ['proxy']],
    ['#/nowhere', 'missing', ['nowhere']],
  ])('reads %j as %s', (hash, section, params) => {
    const route = parseRoute(hash)

    expect(route.section).toBe(section)
    expect([...route.params]).toEqual(params)
  })

  // The query belongs to the route rather than to the document: a filtered view has to be
  // a link someone can send, and only what is inside the hash survives being sent.
  it('carries the query that came with the route', () => {
    const route = parseRoute('#/activity?range=1h&peer=n1')

    expect(route.query.get('range')).toBe('1h')
    expect(route.query.get('peer')).toBe('n1')
  })

  it('leaves the query empty when the address carries none', () => {
    expect([...parseRoute('#/activity').query.keys()]).toEqual([])
  })

  // Every link in the shell is built by href, so an address it produces that parseRoute
  // reads back as something else is a link that lands on "no such page".
  it('builds addresses its own reader understands', () => {
    for (const section of SECTIONS) {
      expect(parseRoute(href(section)).section).toBe(section)
    }
    expect(parseRoute(href('settings', 'application')).params[0]).toBe('application')
  })

  it('knows which settings sections it can render', () => {
    expect(isSettingsSection('application')).toBe(true)
    expect(isSettingsSection('security')).toBe(false)
    expect(isSettingsSection('nowhere')).toBe(false)
    expect(isSettingsSection(undefined)).toBe(false)
  })

  it('knows which pages live under Connections and under DNS', () => {
    expect(isConnectionsSection('paths')).toBe(true)
    expect(isConnectionsSection('security')).toBe(false)
    expect(isConnectionsSection(undefined)).toBe(false)
    expect(isDnsSection('blocklist')).toBe(true)
    expect(isDnsSection('paths')).toBe(false)
    expect(isDnsSection(undefined)).toBe(false)
  })

  // A connection's own page is `#/connections/<kind>/<id>`, so its first segment shares
  // the slot the section's pages use. The two vocabularies have to stay disjoint or a
  // kind's list page would be shadowed by a section of the same name.
  it('never names a page under Connections after a kind of connection', () => {
    for (const kind of TUNNEL_TYPES) {
      expect(isConnectionsSection(kind)).toBe(false)
    }
    expect(CONNECTIONS_SECTIONS).toContain('networks')
    expect(DNS_SECTIONS).toContain('resolver')
  })
})

// A moved address is looked up by its path alone, read the same way parseRoute reads it:
// a link written by hand, with a query or a doubled separator, still has to land on the
// page that replaced it, and nothing that merely resembles a moved address may.
describe('an address that moved', () => {
  it.each([
    ['#/settings/proxy', '#/connections/proxies'],
    ['settings/proxy', '#/connections/proxies'],
    ['#/settings/proxy/', '#/connections/proxies'],
    ['#//settings//proxy', '#/connections/proxies'],
    ['#/settings/proxy?from=note', '#/connections/proxies'],
    ['#/settings/interface', '#/connections/paths'],
    ['#/settings/exitnode', '#/connections'],
    ['#/settings/routes', '#/connections'],
    // Security is a section of the rail now, and the settings page it was is a stale link.
    ['#/settings/security', '#/security'],
    ['#/settings/security?from=note', '#/security'],
    ['#/mode', '#/connections/paths'],
    ['#/forwards', '#/connections/forwards'],
    // The whole section moved, and its pages kept their names: a bare address lands on
    // the first page, and a page keeps everything after its name.
    ['#/access', '#/connections/grants'],
    ['#/access/proxies', '#/connections/proxies'],
    ['#/access/rules/px_psql', '#/connections/rules/px_psql'],
    ['#/access/rules/px_psql?from=note', '#/connections/rules/px_psql'],
  ])('sends %j to %s', (hash, wanted) => {
    expect(movedTo(hash)).toBe(wanted)
  })

  // The addresses that moved wholesale are not prefixes of anything else: an address that
  // merely starts with one of them is its own address.
  it.each([
    [''],
    ['#/'],
    ['#/settings'],
    ['#/settings/application'],
    ['#/settings/security/extra'],
    ['#/security'],
    ['#/settings/proxy/extra'],
    ['#/connections/proxies'],
    ['#/connections/paths'],
    ['#/modes'],
    ['#/forwards/extra'],
    ['#/nowhere'],
    // Under the section that moved whole, only its pages moved with it. An address there
    // that named no page still names none, rather than landing on the connections list.
    ['#/access/nowhere'],
    ['#/access/networks'],
    // Segments that name members of Object.prototype are addresses like any other: none of
    // them moved, and none of them may throw or answer with something that is not a string.
    ['#/constructor'],
    ['#/constructor/x'],
    ['#/toString/grants'],
    ['#/__proto__'],
    ['#/hasOwnProperty/rules'],
  ])('leaves %j meaning itself', (hash) => {
    expect(movedTo(hash)).toBeUndefined()
  })

  // Every redirect lands on an address the router reads as a page, or the redirect only
  // moves the reader from one stale link to another.
  it('sends every moved address somewhere that exists', () => {
    for (const from of [
      '#/mode',
      '#/forwards',
      '#/access',
      '#/access/rules/px_x',
      '#/settings/proxy',
      '#/settings/security',
    ]) {
      const to = movedTo(from)
      expect(to).toBeDefined()
      expect(parseRoute(to ?? '').section).not.toBe('missing')
    }
  })
})

// The menu bar's entries can only launch a browser, so the query is the entire handoff.
// Getting it wrong drops the user on the dashboard with what they asked for nowhere in
// sight, and no error anywhere says so.
describe('the address the menu bar asks for', () => {
  it.each([
    ['?settings=1', '#/settings/application'],
    ['?settings=1&other=x', '#/settings/application'],
    ['?section=dns', '#/dns'],
    ['?section=dns&other=x', '#/dns'],
    // The menu switches a proxy on and off; adding one, or granting it something, is the
    // handoff this query carries, so it has to land on the page that holds the instances
    // rather than on the section they used to live in.
    ['?section=proxies', '#/connections/proxies'],
    // The menu switches a connection on and off; adding, importing or editing one is the
    // handoff this query carries.
    ['?section=connections', '#/connections'],
    ['', undefined],
    ['?settings=0', undefined],
    ['?settings', undefined],
    ['?other=1', undefined],
    // A query naming anything the menu does not offer lands nowhere, rather than handing
    // whoever wrote the link a way to point the dashboard at any address at all.
    ['?section=nowhere', undefined],
    ['?section=', undefined],
    ['?section=constructor', undefined],
    ['?section=__proto__', undefined],
  ])('reads %j as %s', (search, wanted) => {
    expect(legacyHash(search)).toBe(wanted)
  })
})
