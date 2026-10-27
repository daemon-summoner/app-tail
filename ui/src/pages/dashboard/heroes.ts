// SPDX-License-Identifier: MIT

// The dashboard's hero cards: the features somebody opens the app to switch, each with
// its control on the card and a gear to the page that holds the rest.
//
// The list lives here rather than inside the cards so the invariant that matters --
// every gear points at a page that exists -- can be tested on its own, the way the reach
// modes are.

import { href } from '../../lib/router'

export interface Hero {
  id: string
  /** label heads the card and names its region. */
  label: string
  /** route is the page the gear opens: the feature's own page, with every setting the
   *  card leaves out. */
  route: string
}

export const HEROES: readonly Hero[] = [
  { id: 'internet', label: 'Internet', route: href('internet') },
  { id: 'resolver', label: 'System resolver', route: href('dns') },
  { id: 'blocklist', label: 'Blocking', route: href('dns', 'blocklist') },
  { id: 'inspection', label: 'Traffic inspection', route: href('inspection') },
  {
    id: 'paths',
    label: 'How this machine reaches the tailnet',
    route: href('connections', 'paths'),
  },
]

/** The hero with this id. The ids are fixed at build time, so a miss is a typo. */
export function heroNamed(id: string): Hero {
  const hero = HEROES.find((h) => h.id === id)
  if (hero === undefined) throw new Error(`no hero is called ${id}`)
  return hero
}
