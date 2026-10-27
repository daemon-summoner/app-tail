// SPDX-License-Identifier: MIT

// The three ways this machine reaches the tailnet, as the dashboard's tiles arrange them.
//
// Each mode's controls and its detail live on one page; this is only the index. Keeping
// the list here rather than inside the tiles is what lets the invariant that matters --
// every mode points at a page that exists -- be tested on its own.

import { href } from '../../lib/router'

/** Mode is one reach mode: what it is called, and where it is reported. */
interface Mode {
  id: string
  label: string
  /** route is the address of the page that holds this mode's state and its settings, so
   *  the tile can send someone to it rather than repeating either. */
  route: string
}

/**
 * MODES is the tiles' own order, leading with the mode that needs nothing from the
 * machine and ending with the one that changes it.
 */
export const MODES: readonly Mode[] = [
  { id: 'forwards', label: 'Port forwards', route: href('connections', 'forwards') },
  { id: 'proxy', label: 'Proxies', route: href('connections', 'proxies') },
  // The paths page rather than the interface's settings: what a reader wants from this
  // tile is to change how the machine is arranged, and that choice is made there.
  { id: 'interface', label: 'Network interface', route: href('connections', 'paths') },
]

/** ModeStatus is the dot and word beside a mode's name: what it is doing right now,
 *  decided by whichever view carries that mode's state. */
export interface ModeStatus {
  tone: 'running' | 'pending' | 'error' | 'off'
  label: string
}
