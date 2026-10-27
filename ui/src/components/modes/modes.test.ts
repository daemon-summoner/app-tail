// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest'

import { isConnectionsSection, parseRoute } from '../../lib/router'
import { MODES } from './modes'

describe('the modes the dashboard offers', () => {
  // The tiles carry no state and no controls: every mode's answer is on the page it points
  // at. An address naming a page that does not exist is a link that lands on "no such
  // page", and nothing else in the app would notice.
  it('point at a page each', () => {
    const routes = MODES.map((m) => m.route)

    expect(new Set(routes).size).toBe(routes.length)
    for (const address of routes) {
      const route = parseRoute(address)
      expect(route.section).not.toBe('missing')
      // Every mode is a way onto the networks, so every one lives under Connections, and
      // the address has to name a page there rather than a connection or nothing.
      expect(route.section).toBe('connections')
      expect(isConnectionsSection(route.params[0])).toBe(true)
    }
  })
})
