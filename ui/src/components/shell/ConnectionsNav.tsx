// SPDX-License-Identifier: MIT

import { CONNECTIONS_SECTIONS, type ConnectionsSectionId } from '../../lib/router'
import { SubNav } from './SubNav'

/** The name each page under Connections goes by. They read as questions a reader has
 *  rather than as the machinery behind them: "What can reach what" before "Rules". */
export const CONNECTIONS_LABELS: Record<ConnectionsSectionId, string> = {
  networks: 'Networks',
  paths: 'How this machine reaches them',
  forwards: 'Port forwards',
  grants: 'What can reach what',
  proxies: 'Proxies',
  rules: 'Rules',
}

/** ConnectionsNav is the second column under Connections. `networks` is what the bare
 *  address means, so its link is the bare address. */
export function ConnectionsNav({ current }: { current: ConnectionsSectionId | undefined }) {
  return (
    <SubNav
      section="connections"
      heading="Connections"
      ids={CONNECTIONS_SECTIONS}
      labels={CONNECTIONS_LABELS}
      current={current}
      landing="networks"
    />
  )
}
