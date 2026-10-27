// SPDX-License-Identifier: MIT

// Every icon on the page, in one place.
//
// The shapes come from lucide, and this is the only file that imports it: a component
// that wants a mark takes it from here, so the set the page uses can be read in one
// screen and swapping the library is one file. Each is aria-hidden -- the control's own
// text is its name -- and painted in currentColor, so a state that changes a control's
// colour changes its icon with it. Every icon is inline SVG, which is what the page's
// image policy (this origin and data URLs only) allows.

import {
  Activity,
  ArrowDown,
  ArrowUp,
  Check,
  Copy,
  Globe,
  Info,
  LayoutGrid,
  LockKeyhole,
  RefreshCw,
  Search,
  Settings2,
  ShieldCheck,
  Waypoints,
  X,
  type LucideProps,
} from 'lucide-react'
import type { ComponentType } from 'react'

interface IconProps {
  className?: string | undefined
  /** size is the box in CSS pixels; the rail's icons are the one place it is larger. */
  size?: number | undefined
}

/** Icon wraps one lucide shape in the page's defaults: hidden from readers, a stroke
 *  weight that matches Inter at text size, and a class the sheets can size. */
function icon(Shape: ComponentType<LucideProps>, base: string) {
  return function Icon({ className, size }: IconProps) {
    return (
      <Shape
        className={className === undefined ? base : `${base} ${className}`}
        size={size ?? 16}
        strokeWidth={1.7}
        absoluteStrokeWidth
        aria-hidden="true"
        focusable="false"
      />
    )
  }
}

/** The rail: one mark per section. */
export const DashboardIcon = icon(LayoutGrid, 'nav-icon')
export const ConnectionsIcon = icon(Waypoints, 'nav-icon')
export const InternetIcon = icon(Globe, 'nav-icon')
export const DnsIcon = icon(Search, 'nav-icon')
export const InspectionIcon = icon(ShieldCheck, 'nav-icon')
export const SecurityIcon = icon(LockKeyhole, 'nav-icon')
export const ActivityIcon = icon(Activity, 'nav-icon')
export const SettingsIcon = icon(Settings2, 'nav-icon')

/** Marks on controls and in text. */
export const GearIcon = icon(Settings2, 'icon')
export const InfoIcon = icon(Info, 'icon')
export const CopyIcon = icon(Copy, 'icon')
export const CheckIcon = icon(Check, 'icon')
export const CloseIcon = icon(X, 'icon')
export const RefreshIcon = icon(RefreshCw, 'icon')
export const ArrowUpIcon = icon(ArrowUp, 'icon')
export const ArrowDownIcon = icon(ArrowDown, 'icon')
