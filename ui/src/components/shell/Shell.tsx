// SPDX-License-Identifier: MIT

import type { ReactNode } from 'react'

import { type ConnectionsSectionId, type DnsSectionId, type Route } from '../../lib/router'
import { ConnectionsNav } from './ConnectionsNav'
import { DnsNav } from './DnsNav'
import { NavRail } from './NavRail'
import { TopBar } from './TopBar'

/** The sections whose pages are a column of controls, which reads as one; every other
 *  page carries graphs and tables and gets the full width. */
const NARROW_SECTIONS: ReadonlySet<Route['section']> = new Set(['security', 'settings'])

/**
 * Shell is the frame every page is drawn in: the rail of sections, the second column
 * where a section has pages of its own, and the bar that names where the reader is.
 *
 * It renders nothing about the tailnet. Everything it shows comes from the route and from
 * the page inside it, which is what keeps a nav rail that is always on screen from
 * subscribing to a poll for a page nobody is looking at.
 */
export function Shell({
  route,
  title,
  version,
  onRefresh,
  connectionsSection,
  dnsSection,
  notices,
  children,
}: {
  route: Route
  title: string
  version: string | undefined
  onRefresh: () => void
  /** connectionsSection draws the second column under Connections. Absent on one
   *  connection's own page, where the column still shows and marks nothing. */
  connectionsSection?: ConnectionsSectionId | undefined
  /** dnsSection draws the second column under DNS. */
  dnsSection?: DnsSectionId | undefined
  /** notices are what the whole app has to say -- a restart owed, an agent that stopped --
   *  rather than anything one page owns, so they sit above every page's content. */
  notices?: ReactNode | undefined
  children: ReactNode
}) {
  return (
    <div className="shell">
      <NavRail current={route.section} />
      {route.section === 'connections' ? <ConnectionsNav current={connectionsSection} /> : null}
      {route.section === 'dns' ? <DnsNav current={dnsSection} /> : null}
      <div className="shell-body">
        <TopBar title={title} version={version} onRefresh={onRefresh} />
        <main className={NARROW_SECTIONS.has(route.section) ? 'content narrow' : 'content'}>
          {notices}
          {children}
        </main>
      </div>
    </div>
  )
}
