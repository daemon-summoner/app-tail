// SPDX-License-Identifier: MIT

// What every surface needs to show a connection: the colour its state is drawn in, and
// the address of its own page. Both are decided here so a connection reads the same on a
// tile, in a list row and at the head of its own page. The word beside the dot is not --
// the agent serves that, so no two surfaces can name one state differently.

import type { TunnelState, TunnelType, TunnelView } from '../../api'
import { href } from '../../lib/router'

/** canImportConfig is whether a kind of connection is configured from a file the server
 *  issues. A tailnet is not: it is configured by signing in, and there is no file to
 *  paste, so offering one would be an empty box that never accepts anything. */
export function canImportConfig(type: TunnelType): boolean {
  return type === 'wireguard' || type === 'openvpn'
}

/** Tone is the four colours a card, a row or a tile can be. There is no fifth: the
 *  stylesheet's own check refuses a colour that is not already a token. */
export type Tone = 'running' | 'pending' | 'error' | 'off'

/**
 * toneOf is what colour a connection's state is drawn in.
 *
 * `degraded` is pending rather than error because traffic is still crossing, and painting
 * that red is what makes people stop believing red; `needs-login` is pending for the same
 * reason inverted -- it is waiting for a person, not broken.
 */
export function toneOf(state: TunnelState): Tone {
  switch (state) {
    case 'connected':
      return 'running'
    case 'failed':
      return 'error'
    case 'off':
      return 'off'
    default:
      return 'pending'
  }
}

/** connectionHref is where one connection's own page lives. The type is in the address
 *  because a link someone sends should say what it leads to, and because the page's own
 *  heading has nowhere else to read it from before the list has loaded. */
export function connectionHref(tunnel: TunnelView): string {
  return href('connections', tunnel.type, tunnel.id)
}
