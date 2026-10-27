// SPDX-License-Identifier: MIT

import type { ReactElement } from 'react'

import { href, SECTIONS, type SectionId } from '../../lib/router'
import {
  ActivityIcon,
  ConnectionsIcon,
  DashboardIcon,
  DnsIcon,
  InspectionIcon,
  InternetIcon,
  SecurityIcon,
  SettingsIcon,
} from './icons'

/** NavItem is one entry in the rail: what it is called, and the mark that stands for it.
 *  The label is rendered as well as read out -- an icon rail whose meaning is only in a
 *  tooltip is one nobody can use at a glance. */
interface NavItem {
  id: SectionId
  label: string
  Icon: (props: { className?: string | undefined }) => ReactElement
}

const ITEMS: Record<SectionId, NavItem> = {
  dashboard: { id: 'dashboard', label: 'Dashboard', Icon: DashboardIcon },
  connections: { id: 'connections', label: 'Connections', Icon: ConnectionsIcon },
  internet: { id: 'internet', label: 'Internet', Icon: InternetIcon },
  dns: { id: 'dns', label: 'DNS', Icon: DnsIcon },
  inspection: { id: 'inspection', label: 'Inspection', Icon: InspectionIcon },
  security: { id: 'security', label: 'Security', Icon: SecurityIcon },
  activity: { id: 'activity', label: 'Activity', Icon: ActivityIcon },
  settings: { id: 'settings', label: 'Settings', Icon: SettingsIcon },
}

/** NavRail is the app's one set of destinations. Every entry is a link to a hash, so
 *  back and forward work without the page arranging anything. */
export function NavRail({ current }: { current: SectionId | 'missing' }) {
  return (
    <nav className="rail" aria-label="Sections">
      {SECTIONS.map((id) => {
        const item = ITEMS[id]
        const here = id === current
        return (
          <a
            key={id}
            className={here ? 'rail-item here' : 'rail-item'}
            href={href(id)}
            // aria-current is what says "you are here" to a reader that cannot see the
            // highlight, and it is on the link rather than the label because the link is
            // what the reader lands on.
            {...(here ? { 'aria-current': 'page' as const } : {})}
          >
            <item.Icon />
            <span className="rail-label">{item.label}</span>
          </a>
        )
      })}
    </nav>
  )
}
