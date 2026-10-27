// SPDX-License-Identifier: MIT

import { DNS_SECTIONS, type DnsSectionId } from '../../lib/router'
import { SubNav } from './SubNav'

/** The name each page under DNS goes by. */
export const DNS_LABELS: Record<DnsSectionId, string> = {
  resolver: 'System resolver',
  blocklist: 'Blocking',
  names: 'Names',
}

/** DnsNav is the second column under DNS. `resolver` is what the bare address means, so
 *  its link is the bare address. */
export function DnsNav({ current }: { current: DnsSectionId | undefined }) {
  return (
    <SubNav
      section="dns"
      heading="DNS"
      ids={DNS_SECTIONS}
      labels={DNS_LABELS}
      current={current}
      landing="resolver"
    />
  )
}
